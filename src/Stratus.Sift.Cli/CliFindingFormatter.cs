using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli;

internal static class CliFindingFormatter
{
    internal static string FormatMetadataPath(string resourcePath)
    {
        return FormatMetadataEvidence(resourcePath);
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
            return HighlightContentEvidence(snippet, finding.RedactedValue);
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
            TryExtractRawSnippetMatch(snippet, finding.RedactedValue, out var rawMatch))
        {
            return rawMatch;
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

    private static string HighlightContentEvidence(string snippet, string redactedValue)
    {
        if (TryLocateSnippetMatch(snippet, redactedValue, out var start, out var length))
        {
            return CliConsoleFormat.ApplyHighlight(snippet, start, length);
        }

        var fallbackLength = GetFallbackHighlightLength(redactedValue, snippet);
        var fallbackStart = Math.Max(0, Math.Min(50, snippet.Length - fallbackLength));
        return CliConsoleFormat.ApplyHighlight(snippet, fallbackStart, fallbackLength);
    }

    private static bool TryLocateSnippetMatch(string snippet, string redactedValue, out int start, out int length)
    {
        start = 0;
        length = 0;

        var normalizedRedactedValue = CliConsoleFormat.NormalizeEvidenceText(redactedValue);
        if (string.IsNullOrWhiteSpace(normalizedRedactedValue))
        {
            return false;
        }

        var prefixEnd = normalizedRedactedValue.IndexOf('*');
        if (prefixEnd > 0)
        {
            var prefix = normalizedRedactedValue[..prefixEnd];
            var index = snippet.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                start = index;
                length = Math.Min(normalizedRedactedValue.Length, snippet.Length - index);
                return length > 0;
            }
        }

        var exactIndex = snippet.IndexOf(normalizedRedactedValue, StringComparison.OrdinalIgnoreCase);
        if (exactIndex >= 0)
        {
            start = exactIndex;
            length = normalizedRedactedValue.Length;
            return true;
        }

        return false;
    }

    private static bool TryExtractRawSnippetMatch(string snippet, string redactedValue, out string rawMatch)
    {
        rawMatch = string.Empty;
        var normalizedRedactedValue = CliConsoleFormat.NormalizeEvidenceText(redactedValue);
        if (string.IsNullOrWhiteSpace(normalizedRedactedValue))
        {
            return false;
        }

        if (!normalizedRedactedValue.Contains('*', StringComparison.Ordinal))
        {
            rawMatch = normalizedRedactedValue;
            return true;
        }

        var prefix = normalizedRedactedValue[..normalizedRedactedValue.IndexOf('*')];
        if (string.IsNullOrWhiteSpace(prefix))
        {
            return false;
        }

        var index = snippet.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return false;
        }

        rawMatch = ExpandToken(snippet, index, prefix.Length);
        return !string.IsNullOrWhiteSpace(rawMatch);
    }

    private static int GetFallbackHighlightLength(string redactedValue, string snippet)
    {
        var normalizedRedactedValue = CliConsoleFormat.NormalizeEvidenceText(redactedValue);
        if (!string.IsNullOrWhiteSpace(normalizedRedactedValue))
        {
            return Math.Min(normalizedRedactedValue.Length, snippet.Length);
        }

        return Math.Min(24, snippet.Length);
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

    private static string ExpandToken(string value, int start, int length)
    {
        var tokenStart = start;
        while (tokenStart > 0 && !IsTokenBoundary(value[tokenStart - 1]))
        {
            tokenStart--;
        }

        var tokenEnd = start + length;
        while (tokenEnd < value.Length && !IsTokenBoundary(value[tokenEnd]))
        {
            tokenEnd++;
        }

        return value[tokenStart..tokenEnd].Trim();
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
