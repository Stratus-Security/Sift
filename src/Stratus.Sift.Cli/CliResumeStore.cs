using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Net;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Stratus.Sift.FileSystem;

namespace Stratus.Sift.Cli;

internal sealed class CliResumeStore
{
    private const int DefaultRetentionDays = 30;
    private const long DefaultMaxJournalBytes = 128L * 1024 * 1024;
    private const long DefaultMaxDirectoryBytes = 512L * 1024 * 1024;

    private readonly string _directoryPath;
    private readonly ILogger<CliResumeStore> _logger;
    private readonly TimeSpan _retention;
    private readonly long _maxJournalBytes;
    private readonly long _maxDirectoryBytes;
    private readonly object _cleanupLock = new();
    private DateTime _nextCleanupAtUtc;

    public CliResumeStore(IConfiguration configuration, ILogger<CliResumeStore> logger)
    {
        _logger = logger;
        var checkpointPath = configuration["ContentScanner:CheckpointPath"]
            ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Stratus",
                "ContentScanner",
                "checkpoints.json");
        _directoryPath = configuration["ContentScanner:ResumeDirectory"]
            ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(checkpointPath))!, "resume");
        _retention = TimeSpan.FromDays(ReadPositiveInt(
            configuration["ContentScanner:ResumeRetentionDays"],
            DefaultRetentionDays,
            maximum: 3650));
        _maxJournalBytes = ReadPositiveMiB(
            configuration["ContentScanner:ResumeMaxJournalMiB"],
            DefaultMaxJournalBytes);
        _maxDirectoryBytes = Math.Max(
            _maxJournalBytes,
            ReadPositiveMiB(
                configuration["ContentScanner:ResumeMaxDiskMiB"],
                DefaultMaxDirectoryBytes));
    }

    public CliResumeSession OpenSession(string scope, bool resume)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        Directory.CreateDirectory(_directoryPath);
        var path = Path.Combine(_directoryPath, $"{CliResumeIdentity.Hash(scope)}.bin");
        Cleanup(path);
        return CliResumeSession.Open(path, resume, _maxJournalBytes, _logger);
    }

    private void Cleanup(string protectedPath)
    {
        lock (_cleanupLock)
        {
            var now = DateTime.UtcNow;
            var removeExpired = now >= _nextCleanupAtUtc;
            if (removeExpired)
            {
                _nextCleanupAtUtc = now.AddMinutes(10);
            }
            FileInfo[] journals;
            try
            {
                journals = new DirectoryInfo(_directoryPath).GetFiles("*.bin", SearchOption.TopDirectoryOnly);
            }
            catch (Exception exception)
            {
                _logger.LogDebug(exception, "Could not inspect the resume checkpoint directory.");
                return;
            }

            foreach (var journal in journals.Where(file =>
                         removeExpired
                         && !PathsEqual(file.FullName, protectedPath)
                         && now - file.LastWriteTimeUtc > _retention))
            {
                TryDelete(journal);
            }

            journals = journals.Where(file => file.Exists).ToArray();
            var totalBytes = journals.Sum(file => file.Length);
            foreach (var journal in journals
                         .Where(file => !PathsEqual(file.FullName, protectedPath))
                         .OrderBy(file => file.LastWriteTimeUtc))
            {
                if (totalBytes <= _maxDirectoryBytes)
                {
                    break;
                }

                var length = journal.Length;
                if (TryDelete(journal))
                {
                    totalBytes -= length;
                }
            }
        }
    }

    private bool TryDelete(FileInfo journal)
    {
        try
        {
            journal.Delete();
            _logger.LogDebug("Removed expired or excess resume checkpoint {Path}.", journal.FullName);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug(exception, "Could not remove resume checkpoint {Path}.", journal.FullName);
            return false;
        }
    }

    private static bool PathsEqual(string left, string right)
        => string.Equals(
            Path.GetFullPath(left),
            Path.GetFullPath(right),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private static int ReadPositiveInt(string? value, int fallback, int maximum)
        => int.TryParse(value, out var parsed) && parsed > 0
            ? Math.Min(parsed, maximum)
            : fallback;

    private static long ReadPositiveMiB(string? value, long fallbackBytes)
        => int.TryParse(value, out var parsed) && parsed > 0
            ? checked((long)Math.Min(parsed, 16 * 1024) * 1024 * 1024)
            : fallbackBytes;
}

internal sealed class CliResumeSession : IAsyncDisposable
{
    private static ReadOnlySpan<byte> CurrentMagic => "SIFTRES3"u8;
    private static ReadOnlySpan<byte> LegacyMagic => "SIFTRES2"u8;
    private const int SlotSize = sizeof(ulong) * 3;
    private const int HeaderSize = 8 + (SlotSize * 2);
    private const int RecordSize = 16;
    private const int StageRecordThreshold = 16_384;
    private const ulong SlotChecksumSalt = 0x5349465452455333;
    private static readonly TimeSpan CommitInterval = TimeSpan.FromSeconds(30);

    private readonly FileStream _stream;
    private readonly HashSet<CliResumeFingerprint> _completed;
    private readonly List<CliResumeFingerprint> _pending = new(StageRecordThreshold);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Stopwatch _sinceCommit = Stopwatch.StartNew();
    private readonly ILogger _logger;
    private readonly long _maxRecords;
    private long _committedRecords;
    private long _stagedRecords;
    private ulong _generation;
    private bool _capacityWarningWritten;
    private bool _disposed;

    private CliResumeSession(
        FileStream stream,
        HashSet<CliResumeFingerprint> completed,
        long committedRecords,
        ulong generation,
        long maxRecords,
        ILogger logger)
    {
        _stream = stream;
        _completed = completed;
        _committedRecords = committedRecords;
        _stagedRecords = committedRecords;
        _generation = generation;
        _maxRecords = maxRecords;
        _logger = logger;
    }

    public int CompletedCount => _completed.Count;

    internal static CliResumeSession Open(string path, bool resume, long maxJournalBytes, ILogger logger)
    {
        if (!resume && File.Exists(path))
        {
            File.Delete(path);
        }

        var completed = new HashSet<CliResumeFingerprint>();
        var stream = new FileStream(
            path,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        var maxRecords = Math.Max(1, (maxJournalBytes - HeaderSize) / RecordSize);
        ulong generation = 1;
        if (stream.Length == 0)
        {
            WriteSnapshot(stream, completed, generation);
        }
        else if (!TryLoad(stream, completed, maxRecords, out generation, out var requiresRewrite))
        {
            logger.LogWarning("Resume checkpoint {Path} was invalid and has been reset.", path);
            completed.Clear();
            generation = 1;
            WriteSnapshot(stream, completed, generation);
        }
        else if (requiresRewrite)
        {
            logger.LogWarning(
                "Resume checkpoint {Path} used an older format or exceeded the configured size and has been compacted.",
                path);
            generation = 1;
            WriteSnapshot(stream, completed, generation);
        }
        else
        {
            stream.SetLength(checked(HeaderSize + (completed.Count * RecordSize)));
            stream.Position = stream.Length;
        }

        try
        {
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            logger.LogDebug(exception, "Could not update resume checkpoint access time for {Path}.", path);
        }

        return new CliResumeSession(
            stream,
            completed,
            completed.Count,
            generation,
            maxRecords,
            logger);
    }

    public bool Contains(FileScanCandidate candidate)
        => _completed.Contains(CliResumeIdentity.ForFile(candidate));

    public bool ContainsRemote(string driveConnectionId, string itemId, string path, long? size)
        => _completed.Contains(CliResumeIdentity.ForRemoteItem(driveConnectionId, itemId, path, size));

    public ValueTask MarkCompletedAsync(
        FileScanCandidate candidate,
        Func<CancellationToken, Task> beforeCommit,
        CancellationToken cancellationToken)
        => MarkCompletedAsync(CliResumeIdentity.ForFile(candidate), beforeCommit, cancellationToken);

    public ValueTask MarkRemoteCompletedAsync(
        string driveConnectionId,
        string itemId,
        string path,
        long? size,
        Func<CancellationToken, Task> beforeCommit,
        CancellationToken cancellationToken)
        => MarkCompletedAsync(
            CliResumeIdentity.ForRemoteItem(driveConnectionId, itemId, path, size),
            beforeCommit,
            cancellationToken);

    public async ValueTask CommitAsync(
        Func<CancellationToken, Task> beforeCommit,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await CommitCoreAsync(beforeCommit, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask ClearAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _completed.Clear();
            _pending.Clear();
            _committedRecords = 0;
            _stagedRecords = 0;
            _generation = 1;
            cancellationToken.ThrowIfCancellationRequested();
            WriteSnapshot(_stream, _completed, _generation);
            _sinceCommit.Restart();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _stream.DisposeAsync();
        _gate.Dispose();
    }

    private async ValueTask MarkCompletedAsync(
        CliResumeFingerprint fingerprint,
        Func<CancellationToken, Task> beforeCommit,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!_completed.Add(fingerprint))
            {
                return;
            }

            if (_completed.Count > _maxRecords)
            {
                _completed.Remove(fingerprint);
                if (!_capacityWarningWritten)
                {
                    _capacityWarningWritten = true;
                    _logger.LogWarning(
                        "The resume journal reached its configured size limit. The scan will continue, but items beyond the limit may be repeated after an interruption.");
                }

                return;
            }

            _pending.Add(fingerprint);
            if (_pending.Count >= StageRecordThreshold)
            {
                await StagePendingAsync(cancellationToken);
            }

            if (_sinceCommit.Elapsed >= CommitInterval)
            {
                await CommitCoreAsync(beforeCommit, cancellationToken);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async ValueTask CommitCoreAsync(
        Func<CancellationToken, Task> beforeCommit,
        CancellationToken cancellationToken)
    {
        if (_pending.Count == 0 && _stagedRecords == _committedRecords)
        {
            return;
        }

        await beforeCommit(cancellationToken);
        await StagePendingAsync(cancellationToken);
        _generation++;
        var slot = CreateSlot(_generation, checked((ulong)_stagedRecords));
        _stream.Position = GetSlotOffset(_generation);
        await _stream.WriteAsync(slot, cancellationToken);
        _stream.Flush(flushToDisk: true);
        _committedRecords = _stagedRecords;
        _stream.Position = checked(HeaderSize + (_stagedRecords * RecordSize));
        _sinceCommit.Restart();
    }

    private async ValueTask StagePendingAsync(CancellationToken cancellationToken)
    {
        if (_pending.Count == 0)
        {
            return;
        }

        var length = checked(_pending.Count * RecordSize);
        var buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            var span = buffer.AsSpan(0, length);
            for (var index = 0; index < _pending.Count; index++)
            {
                var destination = span.Slice(index * RecordSize, RecordSize);
                BinaryPrimitives.WriteUInt64LittleEndian(destination, _pending[index].First);
                BinaryPrimitives.WriteUInt64LittleEndian(destination[sizeof(ulong)..], _pending[index].Second);
            }

            _stream.Position = checked(HeaderSize + (_stagedRecords * RecordSize));
            await _stream.WriteAsync(buffer.AsMemory(0, length), cancellationToken);
            _stagedRecords += _pending.Count;
            _pending.Clear();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, length));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool TryLoad(
        FileStream stream,
        HashSet<CliResumeFingerprint> completed,
        long maxRecords,
        out ulong generation,
        out bool requiresRewrite)
    {
        generation = 1;
        requiresRewrite = false;
        if (stream.Length < 8)
        {
            return false;
        }

        Span<byte> magic = stackalloc byte[8];
        stream.Position = 0;
        if (stream.Read(magic) != magic.Length)
        {
            return false;
        }

        long committedRecords;
        var recordsOffset = HeaderSize;
        if (magic.SequenceEqual(LegacyMagic))
        {
            if ((stream.Length - LegacyMagic.Length) % RecordSize != 0)
            {
                return false;
            }

            committedRecords = (stream.Length - LegacyMagic.Length) / RecordSize;
            recordsOffset = LegacyMagic.Length;
            requiresRewrite = true;
        }
        else if (magic.SequenceEqual(CurrentMagic))
        {
            if (stream.Length < HeaderSize)
            {
                return false;
            }

            Span<byte> slots = stackalloc byte[SlotSize * 2];
            if (stream.Read(slots) != slots.Length)
            {
                return false;
            }

            var first = ReadSlot(slots[..SlotSize]);
            var second = ReadSlot(slots[SlotSize..]);
            var selected = SelectNewestValidSlot(first, second);
            if (selected is null || selected.Value.Count > (ulong)((long.MaxValue - HeaderSize) / RecordSize))
            {
                return false;
            }

            generation = selected.Value.Generation;
            committedRecords = checked((long)selected.Value.Count);
            if (stream.Length < checked(HeaderSize + (committedRecords * RecordSize)))
            {
                return false;
            }
        }
        else
        {
            return false;
        }

        var recordsToLoad = Math.Min(committedRecords, maxRecords);
        requiresRewrite |= recordsToLoad != committedRecords;
        stream.Position = recordsOffset;
        Span<byte> record = stackalloc byte[RecordSize];
        for (long index = 0; index < recordsToLoad; index++)
        {
            if (stream.Read(record) != RecordSize)
            {
                return false;
            }

            completed.Add(new CliResumeFingerprint(
                BinaryPrimitives.ReadUInt64LittleEndian(record),
                BinaryPrimitives.ReadUInt64LittleEndian(record[sizeof(ulong)..])));
        }

        return true;
    }

    private static void WriteSnapshot(
        FileStream stream,
        IReadOnlyCollection<CliResumeFingerprint> completed,
        ulong generation)
    {
        stream.SetLength(0);
        Span<byte> header = stackalloc byte[HeaderSize];
        CurrentMagic.CopyTo(header);
        CreateSlot(generation, checked((ulong)completed.Count)).CopyTo(header[GetSlotOffset(generation)..]);
        stream.Write(header);

        const int batchRecords = 16_384;
        var buffer = ArrayPool<byte>.Shared.Rent(batchRecords * RecordSize);
        try
        {
            var bufferedRecords = 0;
            foreach (var fingerprint in completed)
            {
                var destination = buffer.AsSpan(bufferedRecords * RecordSize, RecordSize);
                BinaryPrimitives.WriteUInt64LittleEndian(destination, fingerprint.First);
                BinaryPrimitives.WriteUInt64LittleEndian(destination[sizeof(ulong)..], fingerprint.Second);
                bufferedRecords++;
                if (bufferedRecords == batchRecords)
                {
                    stream.Write(buffer, 0, bufferedRecords * RecordSize);
                    bufferedRecords = 0;
                }
            }

            if (bufferedRecords > 0)
            {
                stream.Write(buffer, 0, bufferedRecords * RecordSize);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }

        stream.Flush(flushToDisk: true);
        stream.Position = stream.Length;
    }

    private static byte[] CreateSlot(ulong generation, ulong count)
    {
        var slot = new byte[SlotSize];
        BinaryPrimitives.WriteUInt64LittleEndian(slot, generation);
        BinaryPrimitives.WriteUInt64LittleEndian(slot.AsSpan(sizeof(ulong)), count);
        BinaryPrimitives.WriteUInt64LittleEndian(
            slot.AsSpan(sizeof(ulong) * 2),
            ~(generation ^ count ^ SlotChecksumSalt));
        return slot;
    }

    private static ResumeSlot? ReadSlot(ReadOnlySpan<byte> slot)
    {
        var generation = BinaryPrimitives.ReadUInt64LittleEndian(slot);
        var count = BinaryPrimitives.ReadUInt64LittleEndian(slot[sizeof(ulong)..]);
        var checksum = BinaryPrimitives.ReadUInt64LittleEndian(slot[(sizeof(ulong) * 2)..]);
        return generation > 0 && checksum == ~(generation ^ count ^ SlotChecksumSalt)
            ? new ResumeSlot(generation, count)
            : null;
    }

    private static ResumeSlot? SelectNewestValidSlot(ResumeSlot? first, ResumeSlot? second)
        => first is null
            ? second
            : second is null || first.Value.Generation >= second.Value.Generation
                ? first
                : second;

    private static int GetSlotOffset(ulong generation)
        => 8 + (generation % 2 == 1 ? 0 : SlotSize);

    private readonly record struct ResumeSlot(ulong Generation, ulong Count);
}

internal readonly record struct CliResumeFingerprint(ulong First, ulong Second);

internal static class CliResumeIdentity
{
    internal static string Hash(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
            SHA256.HashData(bytes, digest);
            return Convert.ToHexString(digest[..16]).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal static CliResumeFingerprint ForFile(FileScanCandidate candidate)
        => CreateFingerprint(
            candidate.Path,
            candidate.Name,
            candidate.Size,
            candidate.Modified.ToUniversalTime().Ticks,
            candidate.IsDirectory ? "directory" : "file");

    internal static CliResumeFingerprint ForRemoteItem(
        string driveConnectionId,
        string itemId,
        string path,
        long? size)
        => CreateFingerprint(driveConnectionId, itemId, size ?? -1, 0, path);

    internal static string CreateRuleFingerprint(string? rulesPath)
    {
        if (string.IsNullOrWhiteSpace(rulesPath))
        {
            return typeof(Stratus.Sift.Core.Models.Classifier).Assembly.ManifestModule.ModuleVersionId.ToString("N");
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var root = Path.GetFullPath(rulesPath);
        foreach (var file in Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories)
                     .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            Append(hash, Path.GetRelativePath(root, file).Replace('\\', '/'));
            hash.AppendData(File.ReadAllBytes(file));
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    internal static string CreateFilesystemScope(
        FileSystemScanTarget target,
        string rootPath,
        string ruleFingerprint,
        bool includeBinary,
        CliLlmOptions? llmOptions,
        CliWindowsCredential? credential,
        bool strictKerberos,
        IPAddress? dnsServer)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "filesystem-v2");
        Append(hash, target.Mode.ToString());
        Append(hash, Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        Append(hash, ruleFingerprint);
        Append(hash, includeBinary.ToString());
        Append(hash, strictKerberos.ToString());
        Append(hash, dnsServer?.ToString() ?? "system-dns");
        Append(hash, llmOptions?.Enabled == true ? "llm" : "no-llm");
        Append(hash, llmOptions?.SensitiveOnly == true ? "sensitive-only" : "all-findings");
        Append(hash, llmOptions?.OllamaModel ?? string.Empty);
        Append(hash, credential?.QualifiedUserName ?? $"current:{Environment.UserDomainName}\\{Environment.UserName}");
        Append(hash, credential?.UsesNtHash == true
            ? Convert.ToHexString(credential.NtHash!)
            : credential?.Password ?? string.Empty);
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    internal static string CreateConnectorScope(
        string providerName,
        IReadOnlyDictionary<string, string> configuration,
        string runtimeIdentity,
        string ruleFingerprint,
        bool includeBinary,
        CliLlmOptions? llmOptions)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "connector-v2");
        Append(hash, providerName);
        Append(hash, runtimeIdentity);
        Append(hash, ruleFingerprint);
        Append(hash, includeBinary.ToString());
        Append(hash, llmOptions?.Enabled == true ? "llm" : "no-llm");
        Append(hash, llmOptions?.SensitiveOnly == true ? "sensitive-only" : "all-findings");
        Append(hash, llmOptions?.OllamaModel ?? string.Empty);
        foreach (var item in configuration.OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase))
        {
            Append(hash, item.Key.ToUpperInvariant());
            Append(hash, item.Value.Trim());
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static CliResumeFingerprint CreateFingerprint(
        string first,
        string second,
        long firstNumber,
        long secondNumber,
        string final)
    {
        var byteCount = checked(
            Encoding.UTF8.GetByteCount(first)
            + Encoding.UTF8.GetByteCount(second)
            + Encoding.UTF8.GetByteCount(final)
            + (sizeof(long) * 2)
            + 3);
        var buffer = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            var offset = 0;
            Write(first);
            Write(second);
            BinaryPrimitives.WriteInt64LittleEndian(buffer.AsSpan(offset), firstNumber);
            offset += sizeof(long);
            BinaryPrimitives.WriteInt64LittleEndian(buffer.AsSpan(offset), secondNumber);
            offset += sizeof(long);
            Write(final);

            Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
            SHA256.HashData(buffer.AsSpan(0, offset), digest);
            return new CliResumeFingerprint(
                BinaryPrimitives.ReadUInt64LittleEndian(digest),
                BinaryPrimitives.ReadUInt64LittleEndian(digest[sizeof(ulong)..]));

            void Write(string value)
            {
                offset += Encoding.UTF8.GetBytes(value, buffer.AsSpan(offset));
                buffer[offset++] = 0;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, byteCount));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void Append(IncrementalHash hash, string value)
    {
        var byteCount = Encoding.UTF8.GetByteCount(value);
        var buffer = ArrayPool<byte>.Shared.Rent(byteCount + 1);
        try
        {
            var written = Encoding.UTF8.GetBytes(value, buffer);
            buffer[written] = 0;
            hash.AppendData(buffer.AsSpan(0, written + 1));
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, written + 1));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
