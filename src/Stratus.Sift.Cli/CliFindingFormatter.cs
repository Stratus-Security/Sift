using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli;

internal static class CliFindingFormatter
{
    internal static string FormatMetadataPath(string resourcePath)
    {
        return FormatMetadataEvidence(resourcePath);
    }

    internal static string ParseMetadataPath(string resourcePath)
    {
        var path = CliConsoleFormat.StripAnsi(resourcePath);
        for (var index = path.IndexOf("[[", StringComparison.Ordinal);
             index >= 0;
             index = path.IndexOf("[[", index + 2, StringComparison.Ordinal))
        {
            if (!CliConsoleFormat.TryReadHighlight(path[index..], out var tail, out var start, out var length, requireSingleRange: false))
            {
                continue;
            }

            var plainPath = path[..index] + tail;
            if (!TryGetHighlightRangeFromPath(plainPath, out var expectedStart, out var expectedLength))
            {
                expectedStart = 0;
                expectedLength = plainPath.Length;
            }

            if (index + start == expectedStart && length == expectedLength)
            {
                return plainPath;
            }
        }

        return path;
    }

    internal static string FormatFindingEvidence(ScanFinding finding, string resourcePath)
    {
        if (IsMetadataFinding(finding))
        {
            return FormatMetadataEvidence(resourcePath);
        }

        var snippet = CliConsoleFormat.NormalizeEvidenceText(finding.Snippet);
        if (!string.IsNullOrWhiteSpace(snippet))
        {
            return HighlightContentEvidence(snippet, finding.RedactedValue, finding.SnippetMatchStart);
        }

        var extractedValue = ExtractDisplayMatchValue(finding, resourcePath);
        if (!string.IsNullOrWhiteSpace(extractedValue))
        {
            return CliConsoleFormat.ApplyHighlight(extractedValue, 0, extractedValue.Length);
        }

        return "(no evidence)";
    }

    internal static string? ExtractDisplayMatchValue(ScanFinding finding, string resourcePath)
    {
        if (IsMetadataFinding(finding))
        {
            var normalizedPath = CliConsoleFormat.NormalizeEvidenceText(resourcePath);
            if (string.IsNullOrWhiteSpace(normalizedPath))
            {
                return null;
            }

            var segment = Path.GetFileName(normalizedPath.Replace('\\', '/').TrimEnd('/'));
            return string.IsNullOrWhiteSpace(segment) ? normalizedPath : segment;
        }

        var snippet = CliConsoleFormat.NormalizeEvidenceText(finding.Snippet);
        if (!string.IsNullOrWhiteSpace(snippet) &&
            TryLocateSnippetMatch(snippet, finding.RedactedValue, finding.SnippetMatchStart, out var start, out var length))
        {
            return snippet.Substring(start, length);
        }

        var normalizedRedactedValue = CliConsoleFormat.NormalizeEvidenceText(finding.RedactedValue);
        if (!string.IsNullOrWhiteSpace(normalizedRedactedValue) &&
            !normalizedRedactedValue.Contains('*', StringComparison.Ordinal))
        {
            return normalizedRedactedValue;
        }

        return null;
    }

    internal static bool IsMetadataFinding(ScanFinding finding)
    {
        return string.Equals(finding.RedactedValue, "[METADATA MATCH]", StringComparison.Ordinal)
            || (string.IsNullOrWhiteSpace(finding.RedactedValue) && string.IsNullOrWhiteSpace(finding.Snippet));
    }

    private static string FormatMetadataEvidence(string resourcePath)
    {
        var displayPath = CliConsoleFormat.NormalizeEvidenceText(resourcePath);
        if (string.IsNullOrWhiteSpace(displayPath))
        {
            return "(metadata match)";
        }

        if (TryGetHighlightRangeFromPath(displayPath, out var start, out var length))
        {
            return CliConsoleFormat.ApplyHighlight(displayPath, start, length);
        }

        return CliConsoleFormat.ApplyHighlight(displayPath, 0, displayPath.Length);
    }

    private static string HighlightContentEvidence(string snippet, string redactedValue, int? knownStart)
    {
        if (TryLocateSnippetMatch(snippet, redactedValue, knownStart, out var start, out var length))
        {
            return CliConsoleFormat.ApplyHighlight(snippet, start, length);
        }

        return snippet;
    }

    private static bool TryLocateSnippetMatch(string snippet, string redactedValue, int? knownStart, out int start, out int length)
    {
        start = 0;
        length = 0;

        var normalizedRedactedValue = CliConsoleFormat.NormalizeEvidenceText(redactedValue);
        if (string.IsNullOrWhiteSpace(normalizedRedactedValue))
        {
            return false;
        }

        if (knownStart is int offset && offset >= 0 && offset <= snippet.Length - normalizedRedactedValue.Length &&
            snippet.AsSpan(offset, normalizedRedactedValue.Length).SequenceEqual(normalizedRedactedValue.AsSpan()))
        {
            start = offset;
            length = normalizedRedactedValue.Length;
            return true;
        }

        var exactIndex = snippet.IndexOf(normalizedRedactedValue, StringComparison.Ordinal);
        if (exactIndex < 0)
        {
            exactIndex = snippet.IndexOf(normalizedRedactedValue, StringComparison.OrdinalIgnoreCase);
        }

        if (exactIndex >= 0)
        {
            start = exactIndex;
            length = normalizedRedactedValue.Length;
            return true;
        }

        // Legacy masks retain the first two characters and replace the rest with '*'.
        // An asterisk elsewhere in a raw value does not indicate a mask.
        if (normalizedRedactedValue.Length <= 2 || normalizedRedactedValue.IndexOf('*') != 2 ||
            normalizedRedactedValue.AsSpan(2).IndexOfAnyExcept('*') >= 0)
        {
            return false;
        }

        var prefix = normalizedRedactedValue[..2];
        var candidateStart = -1;
        var candidateLength = 0;
        for (var index = snippet.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
             index >= 0;
             index = snippet.IndexOf(prefix, index + prefix.Length, StringComparison.OrdinalIgnoreCase))
        {
            if (index > 0 && !IsTokenBoundary(snippet[index - 1]))
            {
                continue;
            }

            var end = index + prefix.Length;
            while (end < snippet.Length && !IsTokenBoundary(snippet[end]))
            {
                end++;
            }

            if (end == index + prefix.Length)
            {
                continue;
            }

            if (candidateStart >= 0)
            {
                return false;
            }

            candidateStart = index;
            candidateLength = end - index;
        }

        if (candidateStart < 0)
        {
            return false;
        }

        start = candidateStart;
        length = candidateLength;
        return true;
    }

    private static bool TryGetHighlightRangeFromPath(string resourcePath, out int start, out int length)
    {
        start = 0;
        length = 0;

        var displayPath = CliConsoleFormat.NormalizeEvidenceText(resourcePath);
        if (string.IsNullOrWhiteSpace(displayPath))
        {
            return false;
        }

        if (Uri.TryCreate(displayPath, UriKind.Absolute, out var uri))
        {
            var absolutePath = uri.LocalPath.Replace('\\', '/');
            var segment = GetLastMeaningfulSegment(absolutePath);
            if (!string.IsNullOrWhiteSpace(segment))
            {
                var index = displayPath.LastIndexOf(segment, StringComparison.OrdinalIgnoreCase);
                if (index >= 0)
                {
                    start = index;
                    length = segment.Length;
                    return true;
                }
            }
        }

        var normalizedPath = displayPath.Replace('\\', '/');
        var fileName = Path.GetFileName(normalizedPath);
        if (!string.IsNullOrWhiteSpace(fileName))
        {
            var fileNameIndex = displayPath.LastIndexOf(fileName, StringComparison.OrdinalIgnoreCase);
            if (fileNameIndex >= 0)
            {
                start = fileNameIndex;
                length = fileName.Length;
                return true;
            }
        }

        var lastSegment = GetLastMeaningfulSegment(normalizedPath);
        if (!string.IsNullOrWhiteSpace(lastSegment))
        {
            var segmentIndex = displayPath.LastIndexOf(lastSegment, StringComparison.OrdinalIgnoreCase);
            if (segmentIndex >= 0)
            {
                start = segmentIndex;
                length = lastSegment.Length;
                return true;
            }
        }

        return false;
    }

    private static bool IsTokenBoundary(char value)
    {
        return char.IsWhiteSpace(value) ||
               value is '"' or '\'' or '`' or ',' or ';' or '(' or ')' or '[' or ']' or '{' or '}' or '<' or '>' or '=';
    }

    private static string GetLastMeaningfulSegment(string path)
    {
        return path
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .LastOrDefault() ?? string.Empty;
    }
}
