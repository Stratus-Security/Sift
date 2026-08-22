using System.Text.Json;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Core.Defaults;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli;

internal sealed record CliRuleCatalog(
    List<Classifier> Classifiers,
    List<Policy> Policies,
    List<IgnoreRule> IgnoreRules);

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

        DataPolicyConventions.LinkPoliciesToClassifiers(catalog.Classifiers, catalog.Policies);
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

        DataPolicyConventions.LinkPoliciesToClassifiers(catalog.Classifiers, catalog.Policies);
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
            if (element.TryGetProperty("patterns", out _)
                || element.TryGetProperty("Patterns", out _)
                || element.TryGetProperty("label", out _)
                || element.TryGetProperty("Label", out _))
            {
                var classifier = element.Deserialize(CliJsonContext.Default.Classifier);
                if (classifier is not null && !string.IsNullOrWhiteSpace(classifier.Name))
                {
                    catalog.Classifiers.Add(classifier);
                }

                continue;
            }

            if (element.TryGetProperty("matchTarget", out _)
                || element.TryGetProperty("MatchTarget", out _))
            {
                var ignoreRule = element.Deserialize(CliJsonContext.Default.IgnoreRule);
                if (ignoreRule is not null)
                {
                    catalog.IgnoreRules.Add(ignoreRule);
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
        }
    }
}
