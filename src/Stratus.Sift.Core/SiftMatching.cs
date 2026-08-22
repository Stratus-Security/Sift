using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Stratus.Sift.Core;

public readonly record struct SiftMatchCandidate(string Value, string Context, int Index, int Length);

public readonly record struct SiftValidationResult(bool IsValid, double Confidence = 1.0)
{
    public static SiftValidationResult Valid(double confidence = 1.0) => new(true, confidence);

    public static SiftValidationResult Invalid => new(false, 0.0);
}

public sealed record SiftRuleMatch(int Index, int Length, string Value, double Confidence);

public sealed record SiftRuleEvaluation(IReadOnlyList<SiftRuleMatch> Matches, bool TimedOut);

public static class SiftMatchEngine
{
    public static SiftRuleEvaluation FindMatches(
        ReadOnlySpan<char> content,
        Regex pattern,
        int overlapLength = 0,
        double minimumEntropy = 0,
        Func<SiftMatchCandidate, SiftValidationResult>? validator = null)
    {
        var matches = new List<SiftRuleMatch>();
        try
        {
            foreach (var match in pattern.EnumerateMatches(content))
            {
                if (match.Index + match.Length <= overlapLength)
                {
                    continue;
                }

                var value = content.Slice(match.Index, match.Length).ToString();
                AddIfValid(content, match.Index, match.Length, value, minimumEntropy, validator, matches);
            }

            return new SiftRuleEvaluation(matches, TimedOut: false);
        }
        catch (RegexMatchTimeoutException)
        {
            return new SiftRuleEvaluation(matches, TimedOut: true);
        }
    }

    public static SiftRuleEvaluation FindMatches(
        string content,
        Regex pattern,
        string? valueGroup,
        int overlapLength = 0,
        double minimumEntropy = 0,
        Func<SiftMatchCandidate, SiftValidationResult>? validator = null)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (string.IsNullOrWhiteSpace(valueGroup))
        {
            return FindMatches(content.AsSpan(), pattern, overlapLength, minimumEntropy, validator);
        }

        var matches = new List<SiftRuleMatch>();
        try
        {
            foreach (Match match in pattern.Matches(content))
            {
                if (match.Index + match.Length <= overlapLength)
                {
                    continue;
                }

                var group = match.Groups[valueGroup];
                var candidate = group.Success ? group : match;
                AddIfValid(content.AsSpan(), candidate.Index, candidate.Length, candidate.Value, minimumEntropy, validator, matches);
            }

            return new SiftRuleEvaluation(matches, TimedOut: false);
        }
        catch (RegexMatchTimeoutException)
        {
            return new SiftRuleEvaluation(matches, TimedOut: true);
        }
    }

    private static void AddIfValid(
        ReadOnlySpan<char> content,
        int index,
        int length,
        string value,
        double minimumEntropy,
        Func<SiftMatchCandidate, SiftValidationResult>? validator,
        ICollection<SiftRuleMatch> matches)
    {
        value = value.Trim();
        if (value.Length == 0 || (minimumEntropy > 0 && SiftEvidence.CalculateShannonEntropy(value) < minimumEntropy))
        {
            return;
        }

        var validation = validator?.Invoke(new SiftMatchCandidate(
            value,
            SiftEvidence.BuildSurroundingContext(content, index, length, 100),
            index,
            length)) ?? SiftValidationResult.Valid();
        if (validation.IsValid)
        {
            matches.Add(new SiftRuleMatch(index, length, value, validation.Confidence));
        }
    }
}

public static class SiftEvidence
{
    public static double CalculateShannonEntropy(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty)
        {
            return 0;
        }

        var counts = new Dictionary<char, int>();
        foreach (var character in value)
        {
            counts[character] = counts.GetValueOrDefault(character) + 1;
        }

        var entropy = 0.0;
        foreach (var count in counts.Values)
        {
            var probability = (double)count / value.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    public static string BuildLineSnippet(ReadOnlySpan<char> content, int matchIndex, int matchLength, int maximumLength = 240)
    {
        var text = content.ToString();
        var lineStart = text.LastIndexOf('\n', Math.Max(0, matchIndex - 1));
        lineStart = lineStart < 0 ? 0 : lineStart + 1;
        var lineEnd = text.IndexOf('\n', matchIndex + matchLength);
        lineEnd = lineEnd < 0 ? text.Length : lineEnd;
        var line = text[lineStart..lineEnd].Replace("\r", string.Empty, StringComparison.Ordinal).Trim();
        return line.Length <= maximumLength ? line : string.Concat(line.AsSpan(0, maximumLength - 3), "...");
    }

    public static string BuildSurroundingContext(ReadOnlySpan<char> content, int matchIndex, int matchLength, int surroundingCharacters)
    {
        var start = Math.Max(0, matchIndex - surroundingCharacters);
        var end = Math.Min(content.Length, matchIndex + matchLength + surroundingCharacters);
        return content.Slice(start, end - start).ToString();
    }

    public static string MaskValue(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value.Length <= 2
            ? new string('*', value.Length)
            : string.Concat(value.AsSpan(0, 2), new string('*', value.Length - 2));
    }

    public static string ComputeSha256Base64(string value)
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static bool LooksBinary(ReadOnlySpan<byte> bytes)
    {
        var sample = bytes[..Math.Min(bytes.Length, 4096)];
        if (sample.Length >= 2
            && ((sample[0] == 0xff && sample[1] == 0xfe)
                || (sample[0] == 0xfe && sample[1] == 0xff)))
        {
            return false;
        }

        if (sample.Length >= 3 && sample[0] == 0xef && sample[1] == 0xbb && sample[2] == 0xbf)
        {
            return false;
        }

        var nullBytes = 0;
        var controlBytes = 0;
        var oddNulls = 0;
        var evenNulls = 0;
        for (var index = 0; index < sample.Length; index++)
        {
            var value = sample[index];
            if (value == 0)
            {
                nullBytes++;
                if (index % 2 == 0)
                {
                    evenNulls++;
                }
                else
                {
                    oddNulls++;
                }

                continue;
            }

            if (value < 0x09 || value is > 0x0d and < 0x20)
            {
                controlBytes++;
            }
        }

        var looksLikeUtf16 = sample.Length % 2 == 0
            && ((oddNulls > evenNulls && oddNulls > sample.Length * 0.3)
                || (evenNulls > oddNulls && evenNulls > sample.Length * 0.3));
        return !looksLikeUtf16
            && (nullBytes > 0 || (sample.Length > 0 && (double)controlBytes / sample.Length > 0.1));
    }
}
