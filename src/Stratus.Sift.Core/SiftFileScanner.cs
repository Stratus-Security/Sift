using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Stratus.Sift.Contracts;

namespace Stratus.Sift.Core;

public sealed record SiftScanError(string Path, string Message);

public sealed record SiftFileScanOptions(
    bool EnumerateOnly,
    bool IncludeBinary,
    bool Recurse,
    int Parallelism,
    long MaximumFileSizeBytes,
    IReadOnlySet<string> Extensions,
    IReadOnlySet<string> ExcludedDirectoryNames);

public sealed record SiftFileScanResult(
    string Target,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    long ObjectsDiscovered,
    long ObjectsScanned,
    IReadOnlyList<ContentObservation> Observations,
    IReadOnlyList<SiftScanError> Errors)
{
    public ContentScanSummary ToSummary() => new(
        RequestId: "cli",
        StartedAtUtc,
        CompletedAtUtc,
        ObjectsDiscovered,
        ObjectsScanned,
        Observations.Count,
        Errors.Count,
        Partial: Errors.Count > 0);
}

public sealed class SiftFileScanner(IReadOnlyList<SiftRule>? rules = null)
{
    private static readonly string[] AlwaysScanNames =
    [
        ".env", ".npmrc", ".pypirc", "credentials", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa",
    ];

    private readonly IReadOnlyList<SiftRule> _rules = rules ?? SiftRuleCatalog.Default;

    public async Task<SiftFileScanResult> ScanAsync(
        string target,
        SiftFileScanOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        var startedAtUtc = DateTimeOffset.UtcNow;
        var observations = new ConcurrentBag<ContentObservation>();
        var errors = new ConcurrentBag<SiftScanError>();
        var candidates = EnumerateCandidates(target, options, errors, cancellationToken);
        long discovered = 0;
        long scanned = 0;

        if (options.EnumerateOnly)
        {
            foreach (var _ in candidates)
            {
                cancellationToken.ThrowIfCancellationRequested();
                discovered++;
            }
        }
        else
        {
            await Parallel.ForEachAsync(
                candidates,
                new ParallelOptions
                {
                    CancellationToken = cancellationToken,
                    MaxDegreeOfParallelism = options.Parallelism,
                },
                async (path, token) =>
                {
                    Interlocked.Increment(ref discovered);
                    try
                    {
                        var fileObservations = await ScanFileAsync(path, options, token);
                        foreach (var observation in fileObservations)
                        {
                            observations.Add(observation);
                        }

                        Interlocked.Increment(ref scanned);
                    }
                    catch (OperationCanceledException) when (token.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception exception) when (IsExpectedIoFailure(exception))
                    {
                        errors.Add(new SiftScanError(path, SafeError(exception)));
                    }
                });
        }

        return new SiftFileScanResult(
            target,
            startedAtUtc,
            DateTimeOffset.UtcNow,
            discovered,
            scanned,
            observations
                .OrderBy(observation => observation.ResourcePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(observation => observation.LineNumber)
                .ThenBy(observation => observation.RuleId, StringComparer.Ordinal)
                .ToArray(),
            errors
                .OrderBy(error => error.Path, StringComparer.OrdinalIgnoreCase)
                .ThenBy(error => error.Message, StringComparer.Ordinal)
                .ToArray());
    }

    private static IEnumerable<string> EnumerateCandidates(
        string target,
        SiftFileScanOptions options,
        ConcurrentBag<SiftScanError> errors,
        CancellationToken cancellationToken)
    {
        var normalizedPath = Path.GetFullPath(target);
        if (File.Exists(normalizedPath))
        {
            if (ShouldScan(normalizedPath, options))
            {
                yield return normalizedPath;
            }

            yield break;
        }

        if (!Directory.Exists(normalizedPath))
        {
            throw new DirectoryNotFoundException($"The target does not exist or is not accessible: {target}");
        }

        var pending = new Stack<string>();
        pending.Push(normalizedPath);
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = pending.Pop();
            foreach (var entry in EnumerateDirectoryEntries(directory, errors))
            {
                cancellationToken.ThrowIfCancellationRequested();
                FileAttributes attributes;
                try
                {
                    attributes = File.GetAttributes(entry);
                }
                catch (Exception exception) when (IsExpectedIoFailure(exception))
                {
                    errors.Add(new SiftScanError(entry, SafeError(exception)));
                    continue;
                }

                if ((attributes & FileAttributes.Directory) == 0)
                {
                    if (ShouldScan(entry, options))
                    {
                        yield return entry;
                    }

                    continue;
                }

                if (!options.Recurse
                    || (attributes & FileAttributes.ReparsePoint) != 0
                    || options.ExcludedDirectoryNames.Contains(Path.GetFileName(entry)))
                {
                    continue;
                }

                pending.Push(entry);
            }
        }
    }

    private static IEnumerable<string> EnumerateDirectoryEntries(
        string directory,
        ConcurrentBag<SiftScanError> errors)
    {
        IEnumerator<string>? enumerator = null;
        try
        {
            enumerator = Directory.EnumerateFileSystemEntries(directory).GetEnumerator();
            while (true)
            {
                string current;
                try
                {
                    if (!enumerator.MoveNext())
                    {
                        yield break;
                    }

                    current = enumerator.Current;
                }
                catch (Exception exception) when (IsExpectedIoFailure(exception))
                {
                    errors.Add(new SiftScanError(directory, SafeError(exception)));
                    yield break;
                }

                yield return current;
            }
        }
        finally
        {
            enumerator?.Dispose();
        }
    }

    private async Task<IReadOnlyList<ContentObservation>> ScanFileAsync(
        string path,
        SiftFileScanOptions options,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(path);
        if (file.Length == 0 || file.Length > options.MaximumFileSizeBytes || file.Length > int.MaxValue)
        {
            return [];
        }

        var bytes = new byte[(int)file.Length];
        await using (var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = await stream.ReadAsync(bytes.AsMemory(offset), cancellationToken);
                if (read == 0)
                {
                    break;
                }

                offset += read;
            }

            if (offset != bytes.Length)
            {
                Array.Resize(ref bytes, offset);
            }
        }

        if (!options.IncludeBinary && SiftEvidence.LooksBinary(bytes))
        {
            return [];
        }

        var content = Decode(bytes);
        var observations = new List<ContentObservation>();
        var newlineOffsets = FindNewlineOffsets(content);
        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var evaluation = SiftMatchEngine.FindMatches(
                content,
                rule.Pattern,
                rule.SecretGroup,
                minimumEntropy: rule.MinimumEntropy,
                validator: rule.Validator is null
                    ? null
                    : candidate => rule.Validator(candidate.Value)
                        ? SiftValidationResult.Valid()
                        : SiftValidationResult.Invalid);

            foreach (var match in evaluation.Matches)
            {
                var lineNumber = FindLineNumber(newlineOffsets, match.Index);
                observations.Add(new ContentObservation(
                    ObservationId: CreateObservationId(rule.Id, path, lineNumber, match.Index),
                    RuleId: rule.Id,
                    RuleName: rule.Name,
                    ResourcePath: path,
                    LineNumber: lineNumber,
                    Severity: rule.Severity,
                    Confidence: rule.Confidence,
                    Value: match.Value,
                    Snippet: SiftEvidence.BuildLineSnippet(content, match.Index, match.Length),
                    DetectedAtUtc: DateTimeOffset.UtcNow));
            }
        }

        return observations;
    }

    private static bool ShouldScan(string path, SiftFileScanOptions options)
    {
        var name = Path.GetFileName(path);
        return AlwaysScanNames.Contains(name, StringComparer.OrdinalIgnoreCase)
            || options.Extensions.Contains(Path.GetExtension(path));
    }

    private static string Decode(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe)
        {
            return Encoding.Unicode.GetString(bytes);
        }

        if (bytes.Length >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff)
        {
            return Encoding.BigEndianUnicode.GetString(bytes);
        }

        return Encoding.UTF8.GetString(bytes);
    }

    private static int[] FindNewlineOffsets(string content)
    {
        var offsets = new List<int>();
        for (var index = 0; index < content.Length; index++)
        {
            if (content[index] == '\n')
            {
                offsets.Add(index);
            }
        }

        return offsets.ToArray();
    }

    private static int FindLineNumber(int[] newlineOffsets, int index)
    {
        var result = Array.BinarySearch(newlineOffsets, index);
        return (result >= 0 ? result : ~result) + 1;
    }

    private static string CreateObservationId(string ruleId, string path, int lineNumber, int matchIndex)
    {
        var input = Encoding.UTF8.GetBytes($"{ruleId}\n{path}\n{lineNumber}\n{matchIndex}");
        return Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()[..24];
    }

    private static bool IsExpectedIoFailure(Exception exception)
        => exception is IOException or UnauthorizedAccessException or System.Security.SecurityException;

    private static string SafeError(Exception exception)
        => exception switch
        {
            UnauthorizedAccessException => "Access denied.",
            DirectoryNotFoundException => "Directory not found.",
            FileNotFoundException => "File not found.",
            PathTooLongException => "Path is too long.",
            _ => "The item could not be read.",
        };
}
