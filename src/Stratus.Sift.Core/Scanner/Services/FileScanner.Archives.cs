using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SharpCompress.Archives;
using SharpCompress.Readers;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Models;

namespace Stratus.Sift.Scanner.Services;

public partial class FileScanner
{
    public static IReadOnlySet<string> ArchiveExtensions { get; } = new[]
    { ".zip", ".msapp", ".7z", ".rar", ".tar", ".gz", ".gzip", ".tgz", ".bz2", ".bzip2", ".tbz", ".tbz2", ".xz", ".txz", ".lz", ".zst", ".zstd", ".tzst" }
        .ToFrozenSet(StringComparer.OrdinalIgnoreCase);
    public static bool IsSupportedArchive(string? extension) => extension != null && ArchiveExtensions.Contains(extension);

    private async Task<ScanResult> ScanArchiveAsync(Stream stream, string archivePath, ScannerExecutionPlan plan,
        ScanOptions options, string exposure, string owner, List<AclEntry> aclEntries,
        System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats, ZipTraversalBudget budget,
        int depth, CancellationToken cancellationToken, string? extension = null)
    {
        extension ??= Path.GetExtension(archivePath);
        if (IsZipArchive(extension))
            return await ScanZipArchiveOnlyAsync(stream, archivePath, plan, options, exposure, owner, aclEntries, ruleStats, budget, depth, cancellationToken);
        var result = new ScanResult();
        List<ScanFinding>? issues = null;
        FileStream? container = null;
        IArchive? archive = null;
        IReader? reader = null;
        var timer = Stopwatch.StartNew();
        var names = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            var readerOptions = new ReaderOptions { LeaveStreamOpen = true, ExtensionHint = extension, RewindableBufferSize = 1024 * 1024 };
            if (extension.Equals(".7z", StringComparison.OrdinalIgnoreCase))
            {
                // 7z needs seekable input. Buffer within the same budget as nested ZIP containers.
                container = await BufferZipContainerAsync(stream, archivePath, options, budget, cancellationToken);
                if (container == null) { result.IsComplete = false; return result; }
                archive = ArchiveFactory.OpenArchive(container, readerOptions);
                reader = archive.ExtractAllEntries();
            }
            else reader = ReaderFactory.OpenReader(stream, readerOptions);
            while (reader.MoveToNextEntry())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (timer.Elapsed > TimeSpan.FromMinutes(2) || !budget.TryReserveArchive(1, 0))
                    throw new InvalidDataException("Archive exceeded its time or entry limit.");
                var entry = reader.Entry;
                if (entry.IsDirectory) continue;
                if (entry.IsEncrypted || entry.IsSplitAfter || !string.IsNullOrEmpty(entry.LinkTarget))
                    throw new InvalidDataException("Archive contains encrypted, linked or incomplete content.");
                var key = entry.Key;
                if (string.IsNullOrEmpty(key)) key = Path.GetFileName(archivePath[..Math.Max(0, archivePath.Length - extension.Length)]);
                if (!TryNormalizeZipEntryName(key, out var name) || !names.Add(name))
                    throw new InvalidDataException("Archive contains an unsafe or repeated entry name.");
                if (entry.Size < 0 || entry.Size > Math.Max(0, options.MaxZipEntryBytes))
                    throw new InvalidDataException("Archive entry exceeds its size limit.");
                var path = archivePath + "!/" + name;
                using var entryStream = reader.OpenEntryStream();
                await using var buffered = await BufferExpandedArchiveEntryAsync(entryStream, options, budget, cancellationToken);
                if (entry.CompressedSize > 0 && (double)buffered.Length / entry.CompressedSize > Math.Max(1, options.MaxZipCompressionRatio))
                    throw new InvalidDataException("Archive entry exceeds its compression ratio limit.");
                var nestedExtension = Path.GetExtension(name);
                var nested = IsSupportedArchive(nestedExtension);
                if (nested && depth >= Math.Clamp(options.MaxZipDepth, 1, 3)) { result.IsComplete = false; continue; }
                if (!nested && !plan.Optimizer.HasRulesForExtension(nestedExtension) && !HasDirectMetadataMatch(path, plan.Optimizer)) continue;
                var entryResult = nested
                    ? await ScanArchiveAsync(buffered, path, plan, options, exposure, owner, aclEntries, ruleStats, budget, depth + 1, cancellationToken)
                    : await ScanZipEntryAsync(buffered, path, buffered.Length, plan, options, exposure, owner, aclEntries, ruleStats, cancellationToken);
                AddScanResult(result, ref issues, entryResult);
            }
        }
        catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
        {
            // The caller groups warnings across files. Keep the detailed reader
            // exception in diagnostics and return a useful reason without a stack.
            _logger.LogDebug(ex, "Could not completely inspect archive {ArchivePath}.", archivePath);
            result.IsComplete = false;
            result.IncompleteReason = ex is SharpCompress.Common.InvalidFormatException
                ? "The file contents were not recognized as a supported archive. The extension is a hint; the file may be empty, truncated, mislabeled, or use an unsupported archive variant."
                : "Archive inspection failed: " + ex.Message.Replace('\r', ' ').Replace('\n', ' ');
        }
        finally { reader?.Dispose(); archive?.Dispose(); if (container != null) await container.DisposeAsync(); }
        result.Issues = AggregateIssues(issues, plan.PolicyNameLookup);
        return result;
    }

    private static async Task<FileStream> BufferExpandedArchiveEntryAsync(Stream source, ScanOptions options,
        ZipTraversalBudget budget, CancellationToken ct)
    {
        var path = Path.Combine(Path.GetTempPath(), "sift-archive-" + Guid.NewGuid().ToString("N") + ".tmp");
        var destination = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, System.IO.FileShare.None, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.DeleteOnClose);
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            int read;
            while ((read = await source.ReadAsync(buffer.AsMemory(), ct)) > 0)
            {
                if (read > Math.Max(0, options.MaxZipEntryBytes) - destination.Length
                    || !budget.TryReserveExpanded(read) || !budget.TryReserveBuffered(read))
                    throw new InvalidDataException("Archive exceeded its entry, expansion or buffering limit.");
                await destination.WriteAsync(buffer.AsMemory(0, read), ct);
            }
            destination.Position = 0;
            return destination;
        }
        catch { await destination.DisposeAsync(); throw; }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }
}
