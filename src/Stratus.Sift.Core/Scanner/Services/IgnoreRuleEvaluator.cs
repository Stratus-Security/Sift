using System.IO.Enumeration;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Scanner.Services;

public static class IgnoreRuleEvaluator
{
    public static IReadOnlyList<IgnoreRule> GetMatchedRules(string path, IEnumerable<IgnoreRule>? rules)
    {
        if (string.IsNullOrWhiteSpace(path)
            || rules == null
            || rules is IReadOnlyCollection<IgnoreRule> { Count: 0 })
        {
            return [];
        }

        var normalizedPath = NormalizePath(path);
        var name = GetLeafName(normalizedPath);
        List<IgnoreRule>? matches = null;

        foreach (var rule in rules)
        {
            if (!rule.IsEnabled || string.IsNullOrWhiteSpace(rule.Pattern))
            {
                continue;
            }

            if (MatchesRule(rule, normalizedPath, name))
            {
                (matches ??= new List<IgnoreRule>()).Add(rule);
            }
        }

        return matches ?? [];
    }

    public static bool ShouldIgnore(string path, IEnumerable<IgnoreRule>? rules)
    {
        if (string.IsNullOrWhiteSpace(path)
            || rules == null
            || rules is IReadOnlyCollection<IgnoreRule> { Count: 0 })
        {
            return false;
        }

        var normalizedPath = NormalizePath(path);
        var name = GetLeafName(normalizedPath);
        foreach (var rule in rules)
        {
            if (rule.IsEnabled
                && !string.IsNullOrWhiteSpace(rule.Pattern)
                && MatchesRule(rule, normalizedPath, name))
            {
                return true;
            }
        }

        return false;
    }

    public static bool ShouldPruneDirectory(string directoryPath, IEnumerable<IgnoreRule>? rules)
    {
        if (string.IsNullOrWhiteSpace(directoryPath) || rules == null)
        {
            return false;
        }

        var normalizedPath = NormalizePath(directoryPath);
        foreach (var rule in rules)
        {
            if (!rule.IsEnabled || string.IsNullOrWhiteSpace(rule.Pattern))
            {
                continue;
            }

            switch (rule.MatchTarget)
            {
                case RuleTarget.DirectoryName:
                    if (MatchesDirectoryName(normalizedPath, rule.Pattern))
                    {
                        return true;
                    }
                    break;
                case RuleTarget.DirectoryPath:
                case RuleTarget.Content:
                    if (MatchesDirectoryPath(normalizedPath, rule.Pattern))
                    {
                        return true;
                    }
                    break;
                case RuleTarget.ShareName:
                    if (MatchesShareName(normalizedPath, rule.Pattern))
                    {
                        return true;
                    }
                    break;
            }
        }

        return false;
    }

    public static bool ShouldIgnoreDespiteMetadata(
        IReadOnlyCollection<IgnoreRule> matchedIgnoreRules,
        IReadOnlyCollection<ClassifierOptimizer.MetadataMatch> metadataMatches)
    {
        return matchedIgnoreRules.Count > 0;
    }

    private static bool MatchesRule(IgnoreRule rule, string normalizedPath, string name)
    {
        return rule.MatchTarget switch
        {
            RuleTarget.FileName => FileSystemName.MatchesSimpleExpression(rule.Pattern, name),
            RuleTarget.FileExtension => FileSystemName.MatchesSimpleExpression(
                rule.Pattern.StartsWith('*') ? rule.Pattern : "*" + rule.Pattern,
                name),
            RuleTarget.DirectoryName => MatchesDirectoryName(normalizedPath, rule.Pattern),
            RuleTarget.DirectoryPath or RuleTarget.Content => MatchesDirectoryPath(normalizedPath, rule.Pattern),
            RuleTarget.ShareName => MatchesShareName(normalizedPath, rule.Pattern),
            _ => false
        };
    }

    private static bool MatchesDirectoryName(string normalizedPath, string pattern)
    {
        var normalizedPattern = NormalizePath(pattern).Trim('\\');
        if (string.IsNullOrWhiteSpace(normalizedPattern))
        {
            return false;
        }

        if (!HasWildcard(normalizedPattern))
        {
            return normalizedPath.Contains("\\" + normalizedPattern + "\\", StringComparison.OrdinalIgnoreCase)
                || normalizedPath.EndsWith("\\" + normalizedPattern, StringComparison.OrdinalIgnoreCase);
        }

        foreach (var segment in EnumerateSegments(normalizedPath))
        {
            if (FileSystemName.MatchesSimpleExpression(normalizedPattern, segment))
            {
                return true;
            }
        }

        return false;
    }

    private static bool MatchesDirectoryPath(string normalizedPath, string pattern)
    {
        var normalizedPattern = NormalizePath(pattern);
        if (string.IsNullOrWhiteSpace(normalizedPattern))
        {
            return false;
        }

        return HasWildcard(normalizedPattern)
            ? FileSystemName.MatchesSimpleExpression(normalizedPattern, normalizedPath)
            : normalizedPath.StartsWith(normalizedPattern, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesShareName(string normalizedPath, string pattern)
    {
        var shareName = GetShareName(normalizedPath);
        if (string.IsNullOrEmpty(shareName))
        {
            return false;
        }

        var normalizedPattern = NormalizePath(pattern).Trim('\\');
        if (string.IsNullOrWhiteSpace(normalizedPattern))
        {
            return false;
        }

        return HasWildcard(normalizedPattern)
            ? FileSystemName.MatchesSimpleExpression(normalizedPattern, shareName)
            : string.Equals(normalizedPattern, shareName, StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> EnumerateSegments(string normalizedPath)
    {
        var trimmedPath = normalizedPath.Trim('\\');
        if (trimmedPath.Length == 0)
        {
            yield break;
        }

        var startIndex = 0;
        while (startIndex < trimmedPath.Length)
        {
            var separatorIndex = trimmedPath.IndexOf('\\', startIndex);
            if (separatorIndex < 0)
            {
                yield return trimmedPath[startIndex..];
                yield break;
            }

            if (separatorIndex > startIndex)
            {
                yield return trimmedPath[startIndex..separatorIndex];
            }

            startIndex = separatorIndex + 1;
        }
    }

    private static string? GetShareName(string normalizedPath)
    {
        if (!normalizedPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return null;
        }

        var trimmedPath = normalizedPath[2..];
        var serverSeparatorIndex = trimmedPath.IndexOf('\\');
        if (serverSeparatorIndex < 0 || serverSeparatorIndex == trimmedPath.Length - 1)
        {
            return null;
        }

        var shareAndRest = trimmedPath[(serverSeparatorIndex + 1)..];
        var shareSeparatorIndex = shareAndRest.IndexOf('\\');
        return shareSeparatorIndex >= 0 ? shareAndRest[..shareSeparatorIndex] : shareAndRest;
    }

    private static string GetLeafName(string normalizedPath)
    {
        var trimmedPath = normalizedPath.TrimEnd('\\');
        if (trimmedPath.Length == 0)
        {
            return normalizedPath;
        }

        var separatorIndex = trimmedPath.LastIndexOf('\\');
        return separatorIndex >= 0 ? trimmedPath[(separatorIndex + 1)..] : trimmedPath;
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('/', '\\');
    }

    private static bool HasWildcard(string pattern)
    {
        return pattern.IndexOfAny(['*', '?', '[']) >= 0;
    }
}
