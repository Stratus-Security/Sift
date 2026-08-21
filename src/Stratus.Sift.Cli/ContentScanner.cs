using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Stratus.Sift.Contracts;

namespace Stratus.Sift.Cli;

internal sealed record ScanError(string Path, string Message);

internal sealed record ScanRunResult(
    string Target,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    long ObjectsDiscovered,
    long ObjectsScanned,
    IReadOnlyList<ContentObservation> Observations,
    IReadOnlyList<ScanError> Errors)
{
    internal ContentScanSummary ToSummary() => new(
        RequestId: "cli",
        StartedAtUtc,
        CompletedAtUtc,
        ObjectsDiscovered,
        ObjectsScanned,
        Observations.Count,
        Errors.Count,
        Partial: Errors.Count > 0);
}

internal sealed class ContentScanner(IReadOnlyList<SiftRule>? rules = null)
{
    private static readonly string[] AlwaysScanNames =
    [
        ".env", ".npmrc", ".pypirc", "credentials", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa",
    ];

    private readonly IReadOnlyList<SiftRule> _rules = rules ?? SiftRuleCatalog.Default;

    internal async Task<ScanRunResult> ScanAsync(CliOptions options, CancellationToken cancellationToken)
    {
        PlatformGuard.EnsureSupported(options.Path);
        var startedAtUtc = DateTimeOffset.UtcNow;
        var observations = new ConcurrentBag<ContentObservation>();
        var errors = new ConcurrentBag<ScanError>();
        var candidates = EnumerateCandidates(options, errors, cancellationToken);
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
                        errors.Add(new ScanError(path, SafeError(exception)));
                    }
                });
        }

        var orderedObservations = observations
            .OrderBy(observation => observation.ResourcePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(observation => observation.LineNumber)
            .ThenBy(observation => observation.RuleId, StringComparer.Ordinal)
            .ToArray();

        var orderedErrors = errors
            .OrderBy(error => error.Path, StringComparer.OrdinalIgnoreCase)
            .ThenBy(error => error.Message, StringComparer.Ordinal)
            .ToArray();

        return new ScanRunResult(
            options.Path,
            startedAtUtc,
            DateTimeOffset.UtcNow,
            discovered,
            scanned,
            orderedObservations,
            orderedErrors);
    }

    private IEnumerable<string> EnumerateCandidates(
        CliOptions options,
        ConcurrentBag<ScanError> errors,
        CancellationToken cancellationToken)
    {
        var normalizedPath = Path.GetFullPath(options.Path);
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
            throw new DirectoryNotFoundException($"The target does not exist or is not accessible: {options.Path}");
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
                    errors.Add(new ScanError(entry, SafeError(exception)));
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
        ConcurrentBag<ScanError> errors)
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
                    errors.Add(new ScanError(directory, SafeError(exception)));
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
        CliOptions options,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(path);
        if (file.Length == 0 || file.Length > options.MaximumFileSizeBytes)
        {
            return [];
        }

        var bytes = new byte[file.Length];
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

        if (!options.IncludeBinary && LooksBinary(bytes))
        {
            return [];
        }

        var content = Decode(bytes);
        var observations = new List<ContentObservation>();
        var newlineOffsets = FindNewlineOffsets(content);
        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            MatchCollection matches;
            try
            {
                matches = rule.Pattern.Matches(content);
            }
            catch (RegexMatchTimeoutException)
            {
                continue;
            }

            foreach (Match match in matches)
            {
                var secretMatch = ResolveSecretMatch(rule, match);
                var value = secretMatch.Value.Trim();
                if (value.Length == 0 || (rule.Validator is not null && !rule.Validator(value)))
                {
                    continue;
                }

                var lineNumber = FindLineNumber(newlineOffsets, secretMatch.Index);
                var snippet = BuildSnippet(content, match.Index, match.Length);
                var detectedAtUtc = DateTimeOffset.UtcNow;
                observations.Add(new ContentObservation(
                    ObservationId: CreateObservationId(rule.Id, path, lineNumber, secretMatch.Index),
                    RuleId: rule.Id,
                    RuleName: rule.Name,
                    ResourcePath: path,
                    LineNumber: lineNumber,
                    Severity: rule.Severity,
                    Confidence: rule.Confidence,
                    Value: value,
                    Snippet: snippet,
                    DetectedAtUtc: detectedAtUtc));
            }
        }

        return observations;
    }

    private static bool ShouldScan(string path, CliOptions options)
    {
        var name = Path.GetFileName(path);
        if (AlwaysScanNames.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        return options.Extensions.Contains(Path.GetExtension(path));
    }

    private static Group ResolveSecretMatch(SiftRule rule, Match match)
    {
        if (rule.SecretGroup is null)
        {
            return match;
        }

        var group = match.Groups[rule.SecretGroup];
        return group.Success ? group : match;
    }

    private static bool LooksBinary(ReadOnlySpan<byte> bytes)
    {
        var sample = bytes[..Math.Min(bytes.Length, 4096)];
        var controlCharacters = 0;
        foreach (var value in sample)
        {
            if (value == 0)
            {
                return true;
            }

            if (value < 8 || value is > 13 and < 32)
            {
                controlCharacters++;
            }
        }

        return sample.Length > 0 && controlCharacters > sample.Length / 20;
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
        var newlinesBefore = result >= 0 ? result : ~result;
        return newlinesBefore + 1;
    }

    private static string BuildSnippet(
        string content,
        int matchIndex,
        int matchLength)
    {
        var lineStart = content.LastIndexOf('\n', Math.Max(0, matchIndex - 1));
        lineStart = lineStart < 0 ? 0 : lineStart + 1;
        var lineEnd = content.IndexOf('\n', matchIndex + matchLength);
        lineEnd = lineEnd < 0 ? content.Length : lineEnd;
        var line = content[lineStart..lineEnd].Replace("\r", string.Empty, StringComparison.Ordinal).Trim();
        return line.Length <= 240 ? line : string.Concat(line.AsSpan(0, 237), "...");
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
