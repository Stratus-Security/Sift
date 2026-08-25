using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Stratus.Sift.Cli;
using Stratus.Sift.Core.Defaults;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli.Tests;

public sealed class UnifiedRuleTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("n"));

    public UnifiedRuleTests()
    {
        Directory.CreateDirectory(_directory);
    }

    [Fact]
    public async Task UnifiedRule_LoadsDetectionAndReportingSettingsTogether()
    {
        await File.WriteAllTextAsync(
            Path.Combine(_directory, "custom.json"),
            """
            {
              "Name": "Example token",
              "Description": "Finds an example token.",
              "Label": "Secrets",
              "Severity": "High",
              "MinMatchCount": 2,
              "ExcludePaths": [ "**/fixtures/**" ],
              "Matches": [
                {
                  "Target": "Content",
                  "Patterns": [ "EXAMPLE_[A-Z0-9]{12}" ],
                  "ExtensionProfile": "SourceAndConfig"
                }
              ]
            }
            """);

        var catalog = await CliRuleCatalogLoader.LoadAsync(_directory, NullLogger.Instance);

        var classifier = Assert.Single(catalog.Classifiers);
        var policy = Assert.Single(catalog.Policies);
        Assert.Equal("Example token", classifier.Name);
        Assert.Equal(Severity.High, policy.Severity);
        Assert.Equal(2, policy.Configuration.MinMatchCount);
        Assert.Equal(["**/fixtures/**"], policy.Configuration.ExcludePaths);
        Assert.Same(classifier, Assert.Single(policy.PolicyClassifiers).Classifier);
    }

    [Fact]
    public async Task UnifiedParentRule_GatesChildWithoutCreatingAParentFinding()
    {
        await File.WriteAllTextAsync(
            Path.Combine(_directory, "nested.json"),
            """
            {
              "Name": "Configuration file",
              "ReportFinding": false,
              "Matches": [ { "Target": "FileName", "Patterns": [ "config" ] } ],
              "SubRules": [
                {
                  "Name": "Credential in configuration",
                  "Severity": "Critical",
                  "Matches": [
                    {
                      "Target": "Content",
                      "Patterns": [ "password=[^\\s]+" ],
                      "ExtensionProfile": "SourceAndConfig"
                    }
                  ]
                }
              ]
            }
            """);

        var catalog = await CliRuleCatalogLoader.LoadAsync(_directory, NullLogger.Instance);

        var parent = Assert.Single(catalog.Classifiers);
        var child = Assert.Single(parent.SubClassifiers);
        var policy = Assert.Single(catalog.Policies);
        Assert.Empty(parent.PolicyClassifiers);
        Assert.Same(child, Assert.Single(policy.PolicyClassifiers).Classifier);
    }

    [Fact]
    public async Task LegacySplitRules_RemainSupported()
    {
        await File.WriteAllTextAsync(
            Path.Combine(_directory, "classifier.json"),
            """
            {
              "Name": "Legacy token",
              "Label": "Secrets",
              "Matches": [
                {
                  "Target": "Content",
                  "Patterns": [ "LEGACY_[A-Z0-9]{12}" ],
                  "ExtensionProfile": "SourceAndConfig"
                }
              ]
            }
            """);
        await File.WriteAllTextAsync(
            Path.Combine(_directory, "policy.json"),
            """
            {
              "Name": "Legacy token",
              "Severity": "Critical",
              "Active": true
            }
            """);

        var catalog = await CliRuleCatalogLoader.LoadAsync(_directory, NullLogger.Instance);

        Assert.True(catalog.UsesLegacyPolicies);
        var classifier = Assert.Single(catalog.Classifiers);
        var policy = Assert.Single(catalog.Policies);
        Assert.Equal(Severity.Critical, policy.Severity);
        Assert.Same(classifier, Assert.Single(policy.PolicyClassifiers).Classifier);
    }

    [Fact]
    public async Task LegacyClassifierWithoutPolicy_GetsSaneCliDefaults()
    {
        await File.WriteAllTextAsync(
            Path.Combine(_directory, "classifier.json"),
            """
            {
              "Name": "Simple legacy rule",
              "Label": "Custom",
              "Matches": [ { "Target": "FileName", "Patterns": [ "secrets.txt" ] } ]
            }
            """);

        var catalog = await CliRuleCatalogLoader.LoadAsync(_directory, NullLogger.Instance);

        var classifier = Assert.Single(catalog.Classifiers);
        var policy = Assert.Single(catalog.Policies);
        Assert.Equal(Severity.Medium, policy.Severity);
        Assert.Same(classifier, Assert.Single(policy.PolicyClassifiers).Classifier);
    }

    [Fact]
    public async Task BundledRules_HaveCompleteReportingCoverage()
    {
        var catalog = await CliRuleCatalogLoader.LoadAsync(null, NullLogger.Instance);
        var classifiers = DataPolicyConventions.EnumerateClassifiers(catalog.Classifiers).ToList();
        var leaves = classifiers.Where(classifier => classifier.SubClassifiers.Count == 0).ToList();
        var parents = classifiers.Except(leaves).ToList();

        Assert.Equal(112, classifiers.Count);
        Assert.Equal(109, catalog.Policies.Count);
        Assert.Equal(109, leaves.Count);
        Assert.All(leaves, classifier => Assert.Single(classifier.PolicyClassifiers));
        Assert.All(parents, classifier => Assert.Empty(classifier.PolicyClassifiers));
        Assert.False(catalog.UsesLegacyPolicies);
    }

    [Fact]
    public async Task BundledEnabledRules_AreValidLinkedAndHaveAvailableValidators()
    {
        var catalog = await CliRuleCatalogLoader.LoadAsync(null, NullLogger.Instance);
        var classifiers = DataPolicyConventions.EnumerateClassifiers(catalog.Classifiers).ToList();
        using var host = Program.CreateHost();
        var validators = host.Services.GetServices<IValidator>()
            .Select(validator => validator.Name)
            .ToHashSet(StringComparer.Ordinal);
        var policyMap = CliScannerBootstrap.BuildPolicyMap(catalog.Policies);

        Assert.All(
            catalog.Classifiers,
            classifier => Assert.Empty(ClassifierConventions.ValidateClassifier(classifier)));
        Assert.All(
            classifiers.Where(classifier => classifier.IsEnabled && classifier.SubClassifiers.Count == 0),
            classifier => Assert.True(policyMap.ContainsKey(classifier.Id), $"No active finding mapping for '{classifier.Name}'."));
        Assert.All(
            classifiers.Where(classifier => classifier.IsEnabled && !string.IsNullOrWhiteSpace(classifier.Validator)),
            classifier => Assert.Contains(classifier.Validator!, validators));
    }

    [Theory]
    [InlineData("4539148803436467")]
    [InlineData("4539 1488 0343 6467")]
    [InlineData("4539-1488-0343-6467")]
    public async Task BundledCreditCardRule_DetectsValidNumbersWithoutContextKeywords(string cardNumber)
    {
        var catalog = await CliRuleCatalogLoader.LoadAsync(null, NullLogger.Instance);
        using var host = Program.CreateHost();
        var scanner = host.Services.GetRequiredService<FileScanner>();
        var path = Path.Combine(_directory, "records.csv");
        await File.WriteAllTextAsync(path, cardNumber);

        var findings = scanner.ScanFile(path, catalog.Classifiers, catalog.Policies).ToList();

        Assert.Single(findings, finding => finding.ClassifierName == "Credit Card Number");
    }

    [Fact]
    public async Task BundledCreditCardRule_RejectsInvalidChecksum()
    {
        var catalog = await CliRuleCatalogLoader.LoadAsync(null, NullLogger.Instance);
        using var host = Program.CreateHost();
        var scanner = host.Services.GetRequiredService<FileScanner>();
        var path = Path.Combine(_directory, "records.csv");
        await File.WriteAllTextAsync(path, "4539148803436460");

        var findings = scanner.ScanFile(path, catalog.Classifiers, catalog.Policies).ToList();

        Assert.DoesNotContain(findings, finding => finding.ClassifierName == "Credit Card Number");
    }

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
    }
}
