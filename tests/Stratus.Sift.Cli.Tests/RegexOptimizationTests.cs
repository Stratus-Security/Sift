using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging.Abstractions;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;
using Stratus.Sift.Scanner.Validators;

namespace Stratus.Sift.Cli.Tests;

public sealed class RegexOptimizationTests : IDisposable
{
    private readonly string _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

    public RegexOptimizationTests()
    {
        Directory.CreateDirectory(_tempDirectory);
    }

    [Fact]
    public void CombinedPatterns_PreserveNumericBackreferencesAndMatchBounds()
    {
        var classifier = CreateContentClassifier("Backreference", [@"(ab)\1", "other"]);
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([classifier]);

        var regex = Assert.IsType<Regex>(optimizer.GetRegex(classifier));
        var match = regex.Match("prefix abab suffix");

        Assert.True(match.Success);
        Assert.Equal(7, match.Index);
        Assert.Equal(4, match.Length);
        Assert.Equal("abab", match.Value);
        Assert.Equal(TimeSpan.FromSeconds(1), regex.MatchTimeout);
    }

    [Fact]
    public void HotwordPrefilter_ReturnsSameStartOverlappingKeywords()
    {
        var shortKeyword = CreateContentClassifier("Short keyword", ["short"], ["user"]);
        var longKeyword = CreateContentClassifier("Long keyword", ["long"], ["users:"]);
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([shortKeyword, longKeyword]);

        var classifiers = optimizer.GetClassifiersForContent("users: value", ".txt").ToHashSet();

        Assert.Contains(shortKeyword, classifiers);
        Assert.Contains(longKeyword, classifiers);
    }

    [Fact]
    public void HotwordPrefilter_ReturnsKeywordsEmbeddedInsideAnotherMatch()
    {
        var outerKeyword = CreateContentClassifier("Outer keyword", ["outer"], ["password"]);
        var innerKeyword = CreateContentClassifier("Inner keyword", ["inner"], ["word"]);
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([outerKeyword, innerKeyword]);

        var classifiers = optimizer.GetClassifiersForContent("password", ".txt").ToHashSet();

        Assert.Contains(outerKeyword, classifiers);
        Assert.Contains(innerKeyword, classifiers);
    }

    [Theory]
    [InlineData(".go")]
    [InlineData(".tf")]
    [InlineData(".hcl")]
    [InlineData(".md")]
    [InlineData(".gradle")]
    [InlineData(".pypirc")]
    [InlineData(".jsx")]
    [InlineData(".csv")]
    [InlineData(".docx")]
    [InlineData(".bicepparam")]
    [InlineData(".har")]
    [InlineData(".http")]
    [InlineData(".jsonl")]
    [InlineData(".mdc")]
    [InlineData(".ndjson")]
    [InlineData(".prompt")]
    [InlineData(".prompty")]
    [InlineData(".rest")]
    [InlineData(".tfplan")]
    [InlineData(".tfstate")]
    [InlineData("")]
    public void SourceAndConfigProfile_CoversModernAndExtensionlessTextFiles(string extension)
    {
        var classifier = CreateContentClassifier("Profile", ["secret"], ["secret"]);
        classifier.Matches[0].ExtensionProfile = Stratus.Sift.Core.Validation.ContentExtensionProfiles.SourceAndConfig;
        classifier.Matches[0].IncludedExtensions.Clear();
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([classifier]);

        Assert.True(optimizer.HasRulesForExtension(extension));
        Assert.Contains(classifier, optimizer.GetClassifiersForContent("secret", extension));
    }

    [Fact]
    public void CaseInsensitiveRegexes_AreInvariantUnderTurkishCulture()
    {
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;

        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
            CultureInfo.CurrentUICulture = new CultureInfo("tr-TR");
            var classifier = CreateContentClassifier("Invariant", ["FILE"]);
            var optimizer = new ClassifierOptimizer();
            optimizer.LoadClassifiers([classifier]);

            var regex = Assert.IsType<Regex>(optimizer.GetRegex(classifier));

            Assert.True(regex.Options.HasFlag(RegexOptions.CultureInvariant));
            Assert.Matches(regex, "file");
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
    }

    [Fact]
    public void MetadataTimeout_IsBoundedAndDoesNotSuppressOtherRules()
    {
        var timedOut = CreateMetadataClassifier("Timed out", @"(?=(a+)+$)");
        var safe = CreateMetadataClassifier("Safe", @"^a+!$");
        var optimizer = new ClassifierOptimizer(logger: NullLogger.Instance);
        optimizer.LoadClassifiers([timedOut, safe]);
        var path = Path.Combine("C:\\", new string('a', 40_000) + "!");

        var stopwatch = Stopwatch.StartNew();
        var matches = optimizer.CheckMetadataClassifiers(path).ToList();
        stopwatch.Stop();

        Assert.Contains(safe, matches);
        Assert.DoesNotContain(timedOut, matches);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void ContentTimeout_IsContainedToTheOffendingClassifier()
    {
        var timedOut = CreateContentClassifier("Timed out", [@"(?=(a+)+$)a"], ["trigger"]);
        var safe = CreateContentClassifier("Safe", ["SAFE_VALUE"], ["safe"]);
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([timedOut, safe]);
        var policyMap = new Dictionary<Guid, List<Policy>>
        {
            [timedOut.Id] = [CreatePolicy(timedOut)],
            [safe.Id] = [CreatePolicy(safe)]
        };
        var filePath = Path.Combine(_tempDirectory, "timeout.txt");
        File.WriteAllText(filePath, "trigger " + new string('a', 40_000) + "! safe SAFE_VALUE");
        var scanner = new FileScanner(
            NullLogger<FileScanner>.Instance,
            new ContentExtractor(),
            new ValidatorFactory([]));

        var regex = Assert.IsType<Regex>(optimizer.GetRegex(timedOut));
        Assert.Throws<RegexMatchTimeoutException>(() => regex.IsMatch(File.ReadAllText(filePath)));

        var issues = scanner.ScanFile(filePath, optimizer, policyMap).ToList();

        Assert.DoesNotContain(issues, issue => issue.ClassifierName == timedOut.Name);
        Assert.Contains(issues, issue => issue.ClassifierName == safe.Name);
    }

    [Fact]
    public void RegexCaches_AreOwnedByEachOptimizerInstance()
    {
        var first = new ClassifierOptimizer();
        var second = new ClassifierOptimizer();
        first.LoadClassifiers([CreateContentClassifier("First", ["first"])]);
        second.LoadClassifiers([CreateContentClassifier("Second", ["second"])]);
        var cacheField = typeof(ClassifierOptimizer).GetField("_regexCache", BindingFlags.Instance | BindingFlags.NonPublic);

        var firstCache = Assert.IsType<ConcurrentDictionary<string, Regex>>(cacheField?.GetValue(first));
        var secondCache = Assert.IsType<ConcurrentDictionary<string, Regex>>(cacheField?.GetValue(second));

        Assert.NotSame(firstCache, secondCache);
        Assert.DoesNotContain(firstCache.Keys, key => key.Contains("second", StringComparison.Ordinal));
        Assert.DoesNotContain(secondCache.Keys, key => key.Contains("first", StringComparison.Ordinal));

        first.LoadClassifiers([CreateContentClassifier("Replacement", ["replacement"])]);

        Assert.DoesNotContain(firstCache.Keys, key => key.Contains("first", StringComparison.Ordinal));
        Assert.Contains(firstCache.Keys, key => key.Contains("replacement", StringComparison.Ordinal));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory))
        {
            Directory.Delete(_tempDirectory, recursive: true);
        }
    }

    private static Classifier CreateContentClassifier(
        string name,
        List<string> patterns,
        List<string>? keywords = null)
    {
        return new Classifier
        {
            Id = Guid.NewGuid(),
            Name = name,
            Matches =
            [
                new ClassifierMatch
                {
                    Target = RuleTarget.Content,
                    Patterns = patterns,
                    Keywords = keywords ?? [],
                    IncludedExtensions = [".txt"]
                }
            ]
        };
    }

    private static Classifier CreateMetadataClassifier(string name, string pattern)
    {
        return new Classifier
        {
            Id = Guid.NewGuid(),
            Name = name,
            Matches =
            [
                new ClassifierMatch
                {
                    Target = RuleTarget.FileName,
                    Patterns = [pattern]
                }
            ]
        };
    }

    private static Policy CreatePolicy(Classifier classifier)
    {
        var policy = new Policy
        {
            Id = Guid.NewGuid(),
            Name = classifier.Name,
            Active = true,
            Severity = Severity.High
        };
        var link = new PolicyClassifier
        {
            Policy = policy,
            PolicyId = policy.Id,
            Classifier = classifier,
            ClassifierId = classifier.Id
        };
        policy.PolicyClassifiers.Add(link);
        classifier.PolicyClassifiers.Add(link);
        return policy;
    }
}
