using System.Text.Json;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Core.Defaults;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli;

internal sealed record CliRuleCatalog(
    List<Classifier> Classifiers,
    List<Policy> Policies,
    List<IgnoreRule> IgnoreRules)
{
    public bool UsesLegacyPolicies { get; set; }
}

internal static class CliRuleCatalogLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
    };

    public static async Task<CliRuleCatalog> LoadAsync(
        string? rulesPath,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rulesPath))
        {
            return await LoadBundledDefaultsAsync(logger, cancellationToken);
        }

        if (!Directory.Exists(rulesPath))
        {
            throw new DirectoryNotFoundException($"Configuration directory not found: {rulesPath}");
        }

        var catalog = new CliRuleCatalog([], [], []);
        foreach (var file in Directory.EnumerateFiles(rulesPath, "*.json", SearchOption.AllDirectories))
        {
            try
            {
                var json = await File.ReadAllTextAsync(file, cancellationToken);
                LoadDocument(json, file, catalog);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "Could not parse scanner rules from {File}", file);
            }
        }

        FinalizeCatalog(catalog, addPoliciesForUnlinkedLegacyRules: true);
        if (catalog.UsesLegacyPolicies)
        {
            logger.LogWarning(
                "This rules directory uses the legacy classifier and policy format. " +
                "It remains supported for compatibility; new rules should use the unified SiftingRule format.");
        }

        return catalog.Classifiers.Count == 0
            ? await LoadBundledDefaultsAsync(logger, cancellationToken)
            : catalog;
    }

    private static async Task<CliRuleCatalog> LoadBundledDefaultsAsync(
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var catalog = new CliRuleCatalog([], [], []);
        var assembly = typeof(Classifier).Assembly;
        var resources = assembly.GetManifestResourceNames()
            .Where(name => name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                && name.Contains(".Defaults.Data.", StringComparison.Ordinal)
                && !name.Contains("Ignored", StringComparison.OrdinalIgnoreCase))
            .OrderBy(name => name, StringComparer.Ordinal);

        foreach (var resource in resources)
        {
            try
            {
                await using var stream = assembly.GetManifestResourceStream(resource)
                    ?? throw new InvalidOperationException($"Embedded resource '{resource}' was not found.");
                using var reader = new StreamReader(stream);
                var json = await reader.ReadToEndAsync(cancellationToken);
                LoadDocument(json, resource, catalog);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "Could not load bundled scanner rules from {Resource}", resource);
            }
        }

        FinalizeCatalog(catalog, addPoliciesForUnlinkedLegacyRules: false);
        if (catalog.Classifiers.Count == 0)
        {
            throw new InvalidOperationException("The scanner has no usable classifier definitions.");
        }

        return catalog;
    }

    private static void LoadDocument(string json, string source, CliRuleCatalog catalog)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
        });

        var elements = document.RootElement.ValueKind == JsonValueKind.Array
            ? document.RootElement.EnumerateArray().ToArray()
            : [document.RootElement];

        foreach (var element in elements)
        {
            if (HasProperty(element, "matchTarget"))
            {
                var ignoreRule = element.Deserialize(CliJsonContext.Default.IgnoreRule);
                if (ignoreRule is not null)
                {
                    catalog.IgnoreRules.Add(ignoreRule);
                }

                continue;
            }

            if (IsUnifiedRule(element))
            {
                var rule = element.Deserialize(CliJsonContext.Default.SiftingRule);
                if (rule is null)
                {
                    continue;
                }

                var materialized = SiftingRuleMaterializer.Materialize(rule);
                catalog.Classifiers.Add(materialized.Classifier);
                catalog.Policies.AddRange(materialized.Policies);
                continue;
            }

            if (HasProperty(element, "patterns") || HasProperty(element, "label"))
            {
                var classifier = element.Deserialize(CliJsonContext.Default.Classifier);
                if (classifier is not null && !string.IsNullOrWhiteSpace(classifier.Name))
                {
                    catalog.Classifiers.Add(classifier);
                }

                continue;
            }

            var policy = element.Deserialize(CliJsonContext.Default.Policy);
            if (policy is null)
            {
                continue;
            }

            PolicyDefaultResourceConventions.ApplyPolicyDefaultsFromResourceName(policy, source);
            if (policy.Domain == PolicyDomain.Data)
            {
                var errors = DataPolicyConventions.ValidatePolicy(policy);
                if (errors.Count > 0)
                {
                    throw new InvalidOperationException(
                        $"Invalid data policy '{source}': {string.Join(" ", errors)}");
                }
            }

            catalog.Policies.Add(policy);
            catalog.UsesLegacyPolicies = true;
        }
    }

    private static bool IsUnifiedRule(JsonElement element)
    {
        if (!HasProperty(element, "matches") && !HasProperty(element, "subRules"))
        {
            return false;
        }

        var hasUnifiedSetting = HasProperty(element, "enabled")
            || HasProperty(element, "reportFinding")
            || HasProperty(element, "findingName")
            || HasProperty(element, "severity")
            || HasProperty(element, "subRules")
            || HasProperty(element, "minMatchCount")
            || HasProperty(element, "includePaths")
            || HasProperty(element, "excludePaths")
            || HasProperty(element, "stopOnMatch");

        if (hasUnifiedSetting)
        {
            return true;
        }

        // The current standalone format needs only Name and Matches. Label and
        // IsEnabled belong to the deprecated split classifier format.
        return !HasProperty(element, "label") && !HasProperty(element, "isEnabled");
    }

    private static bool HasProperty(JsonElement element, string name)
    {
        return element.EnumerateObject().Any(
            property => string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    private static void FinalizeCatalog(CliRuleCatalog catalog, bool addPoliciesForUnlinkedLegacyRules)
    {
        DataPolicyConventions.LinkPoliciesToClassifiers(catalog.Classifiers, catalog.Policies);

        if (!addPoliciesForUnlinkedLegacyRules)
        {
            return;
        }

        foreach (var classifier in DataPolicyConventions.EnumerateClassifiers(catalog.Classifiers))
        {
            if (classifier.SubClassifiers.Count > 0 || classifier.PolicyClassifiers.Count > 0)
            {
                continue;
            }

            var generated = SiftingRuleMaterializer.Materialize(new SiftingRule
            {
                Enabled = classifier.IsEnabled,
                Name = classifier.Name,
                Description = classifier.Description,
                Severity = Severity.Medium
            }).Policies.Single();

            generated.PolicyClassifiers.Clear();
            generated.ClassifierNames = [classifier.Name];
            catalog.Policies.Add(generated);
        }

        DataPolicyConventions.LinkPoliciesToClassifiers(catalog.Classifiers, catalog.Policies);
    }
}
