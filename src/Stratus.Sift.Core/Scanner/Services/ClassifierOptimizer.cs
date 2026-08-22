using System.Text.RegularExpressions;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Scanner.Services;

public class ClassifierOptimizer
{
    public readonly record struct MetadataMatch(Classifier Classifier, RuleTarget Target, string ResourcePath, bool IsLiteral);
    private readonly record struct KeywordOverlap(int Offset, string Keyword);

    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(1);

    private readonly bool _allowEmptyExtensions;
    private readonly ILogger _logger;

    public ClassifierOptimizer(bool allowEmptyExtensions = false, ILogger? logger = null)
    {
        _allowEmptyExtensions = allowEmptyExtensions;
        _logger = logger ?? NullLogger.Instance;
    }

    // --- Metadata Match Buckets (Fast) ---
    private readonly Dictionary<string, List<Classifier>> _filenameClassifiers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<Classifier>> _filenameClassifiersCaseSensitive = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<Classifier>> _extensionClassifiers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<Classifier>> _extensionClassifiersCaseSensitive = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<Classifier>> _directoryNameClassifiers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<Classifier>> _directoryNameClassifiersCaseSensitive = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<Classifier>> _shareNameClassifiers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<Classifier>> _shareNameClassifiersCaseSensitive = new(StringComparer.Ordinal);
    private readonly List<(Regex Regex, Classifier Classifier)> _regexFilenameClassifiers = new();
    private readonly List<(Regex Regex, Classifier Classifier)> _regexDirectoryNameClassifiers = new();
    private readonly List<(string Prefix, Classifier Classifier)> _pathClassifiers = new();
    private readonly List<(string Prefix, Classifier Classifier)> _pathClassifiersCaseSensitive = new();
    private readonly List<(Regex Regex, Classifier Classifier)> _regexPathClassifiers = new();

    // --- Content Match Buckets (Slow) ---
    private readonly List<Classifier> _contentClassifiers = new();
    private readonly HashSet<string> _monitoredExtensions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, HashSet<string>> _classifierExtensions = new();

    // Existing Hotword logic
    private Dictionary<string, List<Classifier>> _keywordMap = new();
    private Dictionary<string, List<Classifier>> _keywordMapCaseSensitive = new();
    private Dictionary<string, List<KeywordOverlap>> _keywordOverlaps = new();
    private Dictionary<string, List<KeywordOverlap>> _keywordOverlapsCaseSensitive = new();
    private Regex? _hotwordScanner;
    private Regex? _hotwordScannerCaseSensitive;
    private List<Classifier> _alwaysRunClassifiers = new();
    private Dictionary<string, Regex> _compiledRegexes = new();
    private Dictionary<Guid, ClassifierOptimizer> _subOptimizers = new(); // Key by ID for Classifiers

    private readonly ConcurrentDictionary<string, Regex> _regexCache = new();

    public bool HasContentClassifiers => _contentClassifiers.Count > 0;

    public void LoadClassifiers(IEnumerable<Classifier> classifiers)
    {
        // Reset buckets
        _filenameClassifiers.Clear();
        _filenameClassifiersCaseSensitive.Clear();
        _extensionClassifiers.Clear();
        _extensionClassifiersCaseSensitive.Clear();
        _directoryNameClassifiers.Clear();
        _directoryNameClassifiersCaseSensitive.Clear();
        _shareNameClassifiers.Clear();
        _shareNameClassifiersCaseSensitive.Clear();
        _regexFilenameClassifiers.Clear();
        _regexDirectoryNameClassifiers.Clear();
        _pathClassifiers.Clear();
        _pathClassifiersCaseSensitive.Clear();
        _regexPathClassifiers.Clear();

        _contentClassifiers.Clear();
        _monitoredExtensions.Clear();
        _classifierExtensions.Clear();
        _keywordMap = new Dictionary<string, List<Classifier>>(StringComparer.OrdinalIgnoreCase);
        _keywordMapCaseSensitive = new Dictionary<string, List<Classifier>>(StringComparer.Ordinal);
        _keywordOverlaps = new Dictionary<string, List<KeywordOverlap>>(StringComparer.OrdinalIgnoreCase);
        _keywordOverlapsCaseSensitive = new Dictionary<string, List<KeywordOverlap>>(StringComparer.Ordinal);
        _alwaysRunClassifiers = new List<Classifier>();
        _compiledRegexes = new Dictionary<string, Regex>();
        _subOptimizers.Clear();
        _regexCache.Clear();

        var allKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allCaseSensitiveKeywords = new HashSet<string>(StringComparer.Ordinal);

        foreach (var classifier in classifiers)
        {
            if (classifier.SubClassifiers != null && classifier.SubClassifiers.Any())
            {
                var subOpt = new ClassifierOptimizer(allowEmptyExtensions: true, _logger);
                subOpt.LoadClassifiers(classifier.SubClassifiers);
                _subOptimizers[classifier.Id] = subOpt;
            }

            // Aggregate extensions for quick lookup
            var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (classifier.Matches != null)
            {
                foreach (var match in classifier.Matches)
                {
                    foreach (var ext in ContentExtensionProfiles.Resolve(match.ExtensionProfile)) extensions.Add(ext);
                    if (match.IncludedExtensions != null)
                        foreach (var ext in match.IncludedExtensions) extensions.Add(ext);
                }
            }
            _classifierExtensions[classifier.Id] = extensions;

            // Process Matches
            if (classifier.Matches != null)
            {
                // Metadata matches
                foreach (var match in classifier.Matches.Where(m => m.Target != RuleTarget.Content))
                {
                    OptimizeDetection(classifier, match);
                }

                // Content matches (aggregate)
                var contentMatches = classifier.Matches.Where(m => m.Target == RuleTarget.Content).ToList();
                if (contentMatches.Any())
                {
                    _contentClassifiers.Add(classifier);
                    AddCombinedContentLogic(classifier, contentMatches, allKeywords, allCaseSensitiveKeywords);
                }
            }
        }

        // Build Hotword Scanner for content classifiers
        if (allKeywords.Count > 0)
        {
            string pattern = "(?:" + string.Join("|", allKeywords) + ")";
            try
            {
                _hotwordScanner = GetOrAddRegex(
                    pattern,
                    RegexOptions.NonBacktracking | RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant);
            }
            catch (NotSupportedException)
            {
                _hotwordScanner = GetOrAddRegex(
                    pattern,
                    RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant,
                    MatchTimeout);
            }

            _keywordOverlaps = BuildKeywordOverlaps(_keywordMap, StringComparison.OrdinalIgnoreCase);
        }
        else
        {
            _hotwordScanner = null;
        }

        if (allCaseSensitiveKeywords.Count > 0)
        {
            string pattern = "(?:" + string.Join("|", allCaseSensitiveKeywords) + ")";
            try
            {
                _hotwordScannerCaseSensitive = GetOrAddRegex(
                    pattern,
                    RegexOptions.NonBacktracking | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant);
            }
            catch (NotSupportedException)
            {
                _hotwordScannerCaseSensitive = GetOrAddRegex(
                    pattern,
                    RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant,
                    MatchTimeout);
            }

            _keywordOverlapsCaseSensitive = BuildKeywordOverlaps(_keywordMapCaseSensitive, StringComparison.Ordinal);
        }
        else
        {
            _hotwordScannerCaseSensitive = null;
        }
    }

    private void OptimizeDetection(Classifier classifier, ClassifierMatch match)
    {
        switch (match.Target)
        {
            case RuleTarget.FileName:
                foreach (var pattern in match.Patterns)
                {
                    if (!match.IsLiteral && ClassifierConventions.LooksLikeRegexPattern(pattern))
                    {
                        var regex = GetOrAddSafeRegex(pattern, match.CaseSensitive);
                        _regexFilenameClassifiers.Add((regex, classifier));
                    }
                    else
                    {
                        var bucket = match.CaseSensitive ? _filenameClassifiersCaseSensitive : _filenameClassifiers;
                        if (!bucket.ContainsKey(pattern)) bucket[pattern] = new List<Classifier>();
                        bucket[pattern].Add(classifier);
                    }
                }
                break;
            case RuleTarget.FileExtension:
                foreach (var pattern in match.Patterns)
                {
                    var ext = pattern.TrimStart('*');
                    var bucket = match.CaseSensitive ? _extensionClassifiersCaseSensitive : _extensionClassifiers;
                    if (!bucket.ContainsKey(ext)) bucket[ext] = new List<Classifier>();
                    bucket[ext].Add(classifier);
                }
                break;
            case RuleTarget.DirectoryName:
                foreach (var pattern in match.Patterns)
                {
                    if (!match.IsLiteral && ClassifierConventions.LooksLikeRegexPattern(pattern))
                    {
                        var regex = GetOrAddSafeRegex(pattern, match.CaseSensitive);
                        _regexDirectoryNameClassifiers.Add((regex, classifier));
                    }
                    else
                    {
                        var bucket = match.CaseSensitive ? _directoryNameClassifiersCaseSensitive : _directoryNameClassifiers;
                        if (!bucket.ContainsKey(pattern)) bucket[pattern] = new List<Classifier>();
                        bucket[pattern].Add(classifier);
                    }
                }
                break;
            case RuleTarget.ShareName:
                foreach (var pattern in match.Patterns)
                {
                    var bucket = match.CaseSensitive ? _shareNameClassifiersCaseSensitive : _shareNameClassifiers;
                    if (!bucket.ContainsKey(pattern)) bucket[pattern] = new List<Classifier>();
                    bucket[pattern].Add(classifier);
                }
                break;
            case RuleTarget.DirectoryPath:
                foreach (var pattern in match.Patterns)
                {
                    if (!match.IsLiteral && ClassifierConventions.LooksLikeRegexPattern(pattern))
                    {
                        var regex = GetOrAddSafeRegex(pattern, match.CaseSensitive);
                        _regexPathClassifiers.Add((regex, classifier));
                    }
                    else
                    {
                        if (match.CaseSensitive)
                        {
                            _pathClassifiersCaseSensitive.Add((pattern, classifier));
                        }
                        else
                        {
                            _pathClassifiers.Add((pattern, classifier));
                        }
                    }
                }
                break;
        }
    }

    private void AddCombinedContentLogic(
        Classifier classifier,
        List<ClassifierMatch> matches,
        HashSet<string> allKeywords,
        HashSet<string> allCaseSensitiveKeywords)
    {
        var allPatterns = new List<string>();
        var keywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var caseSensitiveKeywords = new HashSet<string>(StringComparer.Ordinal);

        foreach (var match in matches)
        {
            // Track monitored extensions
            foreach (var ext in ContentExtensionProfiles.Resolve(match.ExtensionProfile))
            {
                _monitoredExtensions.Add(ext.TrimStart('*'));
            }

            if (match.IncludedExtensions != null)
            {
                foreach (var ext in match.IncludedExtensions)
                {
                    _monitoredExtensions.Add(ext.TrimStart('*'));
                }
            }

            // Patterns
            foreach (var p in match.Patterns)
            {
                var pattern = match.IsLiteral ? Regex.Escape(p) : p;
                allPatterns.Add(WrapCaseSensitivity(pattern, match.CaseSensitive));
            }

            // Keywords
            if (match.Keywords != null)
            {
                foreach (var k in match.Keywords)
                {
                    if (match.CaseSensitive)
                    {
                        caseSensitiveKeywords.Add(k);
                    }
                    else
                    {
                        keywords.Add(k);
                    }
                }
            }
        }

        if (allPatterns.Count == 0) return;

        string combinedPattern;
        if (allPatterns.Count == 1)
        {
            combinedPattern = allPatterns[0];
        }
        else
        {
            combinedPattern = "(?:" + string.Join("|", allPatterns) + ")";
        }

        try
        {
            var regex = GetOrAddRegex(
                combinedPattern,
                RegexOptions.NonBacktracking | RegexOptions.CultureInvariant,
                MatchTimeout);

            _compiledRegexes[classifier.Name] = regex;
        }
        catch (NotSupportedException)
        {
            try
            {
                var regex = GetOrAddRegex(
                    combinedPattern,
                    RegexOptions.Compiled | RegexOptions.CultureInvariant,
                    MatchTimeout);

                _compiledRegexes[classifier.Name] = regex;
            }
            catch (ArgumentException)
            {
                return;
            }
        }

        if (keywords.Count == 0 && caseSensitiveKeywords.Count == 0)
        {
            _alwaysRunClassifiers.Add(classifier);
            return;
        }

        foreach (var kw in keywords)
        {
            if (!_keywordMap.ContainsKey(kw))
                _keywordMap[kw] = new List<Classifier>();

            _keywordMap[kw].Add(classifier);
            allKeywords.Add(Regex.Escape(kw));
        }

        foreach (var kw in caseSensitiveKeywords)
        {
            if (!_keywordMapCaseSensitive.ContainsKey(kw))
            {
                _keywordMapCaseSensitive[kw] = new List<Classifier>();
            }

            _keywordMapCaseSensitive[kw].Add(classifier);
            allCaseSensitiveKeywords.Add(Regex.Escape(kw));
        }
    }

    private Regex GetOrAddSafeRegex(string pattern, bool caseSensitive)
    {
        var commonOptions = RegexOptions.CultureInvariant
            | (caseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase);

        try
        {
            return GetOrAddRegex(pattern, commonOptions | RegexOptions.NonBacktracking, MatchTimeout);
        }
        catch (NotSupportedException)
        {
            return GetOrAddRegex(pattern, commonOptions | RegexOptions.Compiled, MatchTimeout);
        }
    }

    private static string WrapCaseSensitivity(string pattern, bool caseSensitive)
    {
        return caseSensitive
            ? $"(?-i:{pattern})"
            : $"(?i:{pattern})";
    }

    private Regex GetOrAddRegex(string pattern, RegexOptions options, TimeSpan? timeout = null)
    {
        var cacheKey = timeout.HasValue
            ? $"{(int)options}|{timeout.Value.Ticks}|{pattern}"
            : $"{(int)options}|none|{pattern}";

        return _regexCache.GetOrAdd(
            cacheKey,
            _ => timeout.HasValue
                ? new Regex(pattern, options, timeout.Value)
                : new Regex(pattern, options));
    }

    private static Dictionary<string, List<KeywordOverlap>> BuildKeywordOverlaps(
        IReadOnlyDictionary<string, List<Classifier>> keywordMap,
        StringComparison comparison)
    {
        var comparer = comparison == StringComparison.Ordinal
            ? StringComparer.Ordinal
            : StringComparer.OrdinalIgnoreCase;
        var overlaps = new Dictionary<string, List<KeywordOverlap>>(comparer);

        foreach (var matchedKeyword in keywordMap.Keys)
        {
            List<KeywordOverlap>? candidates = null;

            foreach (var candidateKeyword in keywordMap.Keys)
            {
                for (var offset = 0; offset < matchedKeyword.Length; offset++)
                {
                    if (offset == 0 && string.Equals(matchedKeyword, candidateKeyword, comparison))
                    {
                        continue;
                    }

                    var sharedLength = Math.Min(matchedKeyword.Length - offset, candidateKeyword.Length);
                    if (!matchedKeyword.AsSpan(offset, sharedLength)
                        .Equals(candidateKeyword.AsSpan(0, sharedLength), comparison))
                    {
                        continue;
                    }

                    candidates ??= [];
                    candidates.Add(new KeywordOverlap(offset, candidateKeyword));
                }
            }

            if (candidates is { Count: > 0 })
            {
                overlaps[matchedKeyword] = candidates;
            }
        }

        return overlaps;
    }

    private string? GetShareName(string path)
    {
        int firstSlash = path.IndexOf('\\', 2);
        if (firstSlash == -1) return null;

        int secondSlash = path.IndexOf('\\', firstSlash + 1);
        if (secondSlash == -1)
        {
            return path.Substring(firstSlash + 1);
        }

        return path.Substring(firstSlash + 1, secondSlash - firstSlash - 1);
    }

    private static string GetShareRoot(string path)
    {
        int firstSlash = path.IndexOf('\\', 2);
        if (firstSlash == -1)
        {
            return path;
        }

        int secondSlash = path.IndexOf('\\', firstSlash + 1);
        return secondSlash == -1 ? path : path.Substring(0, secondSlash);
    }

    private static string CanonicalizeMatchedPath(string fullPath, int matchIndex, int matchLength)
    {
        var candidate = fullPath.Substring(0, Math.Min(fullPath.Length, matchIndex + matchLength)).TrimEnd('\\', '/');
        return string.IsNullOrWhiteSpace(candidate) ? fullPath : candidate;
    }

    private static IEnumerable<(string Name, string FullPath)> GetDirectoryNames(string path)
    {
        var normalizedPath = path.Replace('/', '\\');
        var directoryPath = Path.GetDirectoryName(normalizedPath);
        if (string.IsNullOrWhiteSpace(directoryPath))
        {
            yield break;
        }

        var root = Path.GetPathRoot(normalizedPath) ?? string.Empty;
        var currentPath = string.IsNullOrWhiteSpace(root) ? string.Empty : root.TrimEnd('\\');

        foreach (var segment in directoryPath.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment.EndsWith(":", StringComparison.Ordinal))
            {
                currentPath = segment;
                continue;
            }

            currentPath = string.IsNullOrEmpty(currentPath)
                ? segment
                : currentPath + "\\" + segment;

            yield return (segment, currentPath);
        }
    }

    public IEnumerable<Classifier> CheckMetadataClassifiers(string path)
    {
        return GetMetadataMatches(path)
            .Select(match => match.Classifier)
            .DistinctBy(classifier => classifier.Id);
    }

    public IEnumerable<MetadataMatch> GetMetadataMatches(string path)
    {
        var name = Path.GetFileName(path);
        var ext = Path.GetExtension(path);

        if (_filenameClassifiers.TryGetValue(name, out var rules))
        {
            foreach (var r in rules) yield return new MetadataMatch(r, RuleTarget.FileName, path, true);
        }

        if (_filenameClassifiersCaseSensitive.TryGetValue(name, out var caseSensitiveRules))
        {
            foreach (var r in caseSensitiveRules) yield return new MetadataMatch(r, RuleTarget.FileName, path, true);
        }

        if (_extensionClassifiers.TryGetValue(ext.TrimStart('*'), out var extRules))
        {
            foreach (var r in extRules) yield return new MetadataMatch(r, RuleTarget.FileExtension, path, true);
        }

        if (_extensionClassifiersCaseSensitive.TryGetValue(ext.TrimStart('*'), out var caseSensitiveExtensionRules))
        {
            foreach (var r in caseSensitiveExtensionRules) yield return new MetadataMatch(r, RuleTarget.FileExtension, path, true);
        }

        foreach (var (directoryName, directoryPath) in GetDirectoryNames(path))
        {
            if (_directoryNameClassifiers.TryGetValue(directoryName, out var directoryRules))
            {
                foreach (var r in directoryRules) yield return new MetadataMatch(r, RuleTarget.DirectoryName, directoryPath, true);
            }

            if (_directoryNameClassifiersCaseSensitive.TryGetValue(directoryName, out var caseSensitiveDirectoryRules))
            {
                foreach (var r in caseSensitiveDirectoryRules) yield return new MetadataMatch(r, RuleTarget.DirectoryName, directoryPath, true);
            }

            foreach (var (regex, rule) in _regexDirectoryNameClassifiers)
            {
                if (TryIsMatch(regex, directoryName, rule))
                {
                    yield return new MetadataMatch(rule, RuleTarget.DirectoryName, directoryPath, false);
                }
            }
        }

        if (path.StartsWith(@"\\"))
        {
            var share = GetShareName(path);
            if (!string.IsNullOrEmpty(share) && _shareNameClassifiers.TryGetValue(share, out var shareRules))
            {
                var shareRoot = GetShareRoot(path);
                foreach (var r in shareRules) yield return new MetadataMatch(r, RuleTarget.ShareName, shareRoot, true);
            }

            if (!string.IsNullOrEmpty(share) && _shareNameClassifiersCaseSensitive.TryGetValue(share, out var caseSensitiveShareRules))
            {
                var shareRoot = GetShareRoot(path);
                foreach (var r in caseSensitiveShareRules) yield return new MetadataMatch(r, RuleTarget.ShareName, shareRoot, true);
            }
        }

        foreach (var (regex, rule) in _regexFilenameClassifiers)
        {
            if (TryIsMatch(regex, name, rule))
            {
                yield return new MetadataMatch(rule, RuleTarget.FileName, path, false);
            }
        }

        foreach (var (prefix, rule) in _pathClassifiers)
        {
            var matchIndex = path.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (matchIndex >= 0)
            {
                yield return new MetadataMatch(rule, RuleTarget.DirectoryPath, CanonicalizeMatchedPath(path, matchIndex, prefix.Length), true);
            }
        }

        foreach (var (prefix, rule) in _pathClassifiersCaseSensitive)
        {
            var matchIndex = path.IndexOf(prefix, StringComparison.Ordinal);
            if (matchIndex >= 0)
            {
                yield return new MetadataMatch(rule, RuleTarget.DirectoryPath, CanonicalizeMatchedPath(path, matchIndex, prefix.Length), true);
            }
        }

        foreach (var (regex, rule) in _regexPathClassifiers)
        {
            var match = TryMatch(regex, path, rule);
            if (match is { Success: true })
            {
                yield return new MetadataMatch(rule, RuleTarget.DirectoryPath, CanonicalizeMatchedPath(path, match.Index, match.Length), false);
            }
        }
    }

    private bool TryIsMatch(Regex regex, string input, Classifier classifier)
    {
        try
        {
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            LogRegexTimeout(classifier);
            return false;
        }
    }

    private Match? TryMatch(Regex regex, string input, Classifier classifier)
    {
        try
        {
            return regex.Match(input);
        }
        catch (RegexMatchTimeoutException)
        {
            LogRegexTimeout(classifier);
            return null;
        }
    }

    private void LogRegexTimeout(Classifier classifier)
    {
        _logger.LogWarning(
            "Skipping timed-out metadata regex for classifier {ClassifierName}.",
            classifier.Name);
    }

    public IEnumerable<Classifier> GetClassifiersForContent(string content, string extension)
    {
        return GetClassifiersForContent(content.AsSpan(), extension);
    }

    public IEnumerable<Classifier> GetClassifiersForContent(ReadOnlySpan<char> content, string extension)
    {
        var rulesToRun = new HashSet<Classifier>();
        PopulateClassifiersForContent(content, rulesToRun, extension);
        return rulesToRun;
    }

    public void PopulateClassifiersForContent(ReadOnlySpan<char> content, HashSet<Classifier> target, string extension)
    {
        var normalizedExt = extension.StartsWith(".") ? extension.Substring(1) : extension;
        var dotExt = "." + normalizedExt;

        PopulateClassifiersForContentInternal(content, target, normalizedExt, dotExt);
    }

    public void PopulateClassifiersForContentInternal(ReadOnlySpan<char> content, HashSet<Classifier> target, string normalizedExt, string dotExt)
    {
        foreach (var rule in _alwaysRunClassifiers)
        {
            if (IsExtensionMatch(rule, normalizedExt, dotExt))
            {
                target.Add(rule);
            }
        }

        PopulateKeywordClassifiers(
            content,
            target,
            normalizedExt,
            dotExt,
            _hotwordScanner,
            _keywordMap,
            _keywordOverlaps,
            StringComparison.OrdinalIgnoreCase);
        PopulateKeywordClassifiers(
            content,
            target,
            normalizedExt,
            dotExt,
            _hotwordScannerCaseSensitive,
            _keywordMapCaseSensitive,
            _keywordOverlapsCaseSensitive,
            StringComparison.Ordinal);
    }

    private void PopulateKeywordClassifiers(
        ReadOnlySpan<char> content,
        HashSet<Classifier> target,
        string normalizedExt,
        string dotExt,
        Regex? scanner,
        Dictionary<string, List<Classifier>> keywordMap,
        Dictionary<string, List<KeywordOverlap>> overlapMap,
        StringComparison comparison)
    {
        if (scanner is null)
        {
            return;
        }

        var lookup = keywordMap.GetAlternateLookup<ReadOnlySpan<char>>();
        var overlapLookup = overlapMap.GetAlternateLookup<ReadOnlySpan<char>>();

        foreach (var match in scanner.EnumerateMatches(content))
        {
            var keywordSpan = content.Slice(match.Index, match.Length);
            if (lookup.TryGetValue(keywordSpan, out var linkedRules))
            {
                AddExtensionMatchedRules(linkedRules, target, normalizedExt, dotExt);
            }

            if (!overlapLookup.TryGetValue(keywordSpan, out var overlaps))
            {
                continue;
            }

            foreach (var overlap in overlaps)
            {
                var candidate = content.Slice(match.Index + overlap.Offset);
                if (candidate.StartsWith(overlap.Keyword, comparison)
                    && keywordMap.TryGetValue(overlap.Keyword, out var overlapRules))
                {
                    AddExtensionMatchedRules(overlapRules, target, normalizedExt, dotExt);
                }
            }
        }
    }

    private void AddExtensionMatchedRules(
        IEnumerable<Classifier> rules,
        HashSet<Classifier> target,
        string normalizedExt,
        string dotExt)
    {
        foreach (var rule in rules)
        {
            if (IsExtensionMatch(rule, normalizedExt, dotExt))
            {
                target.Add(rule);
            }
        }
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private bool IsExtensionMatch(Classifier classifier, string normalizedExt, string dotExt)
    {
        if (_allowEmptyExtensions)
        {
            if (!_classifierExtensions.TryGetValue(classifier.Id, out var exts) || exts.Count == 0) return true;
        }

        if (_classifierExtensions.TryGetValue(classifier.Id, out var extensions))
        {
            if (extensions.Count == 0) return _allowEmptyExtensions;
            if (extensions.Contains(normalizedExt) || extensions.Contains(dotExt)) return true;
        }
        else if (_allowEmptyExtensions)
        {
            return true;
        }

        return false;
    }

    public bool HasRulesForExtension(string extension)
    {
        if (string.IsNullOrEmpty(extension)) return _monitoredExtensions.Contains(string.Empty);
        var ext = extension.TrimStart('*');
        if (ext.StartsWith("."))
        {
            if (_monitoredExtensions.Contains(ext)) return true;
            ext = ext.Substring(1);
        }
        return _monitoredExtensions.Contains(ext) || _monitoredExtensions.Contains("." + ext);
    }

    public Regex? GetCompiledRegex(string ruleName)
    {
        return _compiledRegexes.TryGetValue(ruleName, out var regex) ? regex : null;
    }

    public Regex? GetRegex(Classifier classifier)
    {
        return GetCompiledRegex(classifier.Name);
    }

    public ClassifierOptimizer? GetSubOptimizer(Classifier classifier)
    {
        return _subOptimizers.TryGetValue(classifier.Id, out var subOpt) ? subOpt : null;
    }
}
