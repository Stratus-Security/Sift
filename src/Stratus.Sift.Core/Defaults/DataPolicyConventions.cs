using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Core.Defaults;

public static class DataPolicyConventions
{
    public static List<string> ValidatePolicy(Policy policy, bool requireClassifierLink = true)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(policy.Name))
        {
            errors.Add("Policy name is required.");
        }

        if (policy.Domain != PolicyDomain.Data)
        {
            return errors;
        }

        errors.AddRange(ValidateConfiguration(policy.Configuration));

        if ((policy.ClassifierNames ?? []).Any(static item => string.IsNullOrWhiteSpace(item)))
        {
            errors.Add("ClassifierNames cannot contain blank entries.");
        }

        if (!requireClassifierLink)
        {
            return errors;
        }

        var hasAttachedClassifiers = (policy.PolicyClassifiers ?? [])
            .Any(pc =>
            pc.ClassifierId != Guid.Empty
            || !string.IsNullOrWhiteSpace(pc.Classifier?.Name));

        if (!hasAttachedClassifiers && GetRequiredClassifierNames(policy).Count == 0)
        {
            errors.Add("Data policies must reference at least one detector/classifier.");
        }

        return errors;
    }

    public static List<string> ValidateConfiguration(PolicyConfiguration? configuration)
    {
        configuration ??= new PolicyConfiguration();
        configuration.EnsureMaterializedCollections();

        var errors = new List<string>();
        if (configuration.MinMatchCount < 1)
        {
            errors.Add("MinMatchCount must be greater than or equal to 1.");
        }

        return errors;
    }

    public static IReadOnlyList<string> GetRequiredClassifierNames(Policy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var configuredNames = (policy.ClassifierNames ?? [])
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .Select(static item => item.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (configuredNames.Count > 0)
        {
            return configuredNames;
        }

        return string.IsNullOrWhiteSpace(policy.Name)
            ? []
            : [policy.Name.Trim()];
    }

    public static IReadOnlyList<string> GetMissingClassifierNames(
        Policy policy,
        IReadOnlyDictionary<string, Classifier> classifierLookup)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(classifierLookup);

        return GetRequiredClassifierNames(policy)
            .Where(name => !classifierLookup.ContainsKey(name))
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    public static int LinkPoliciesToClassifiers(IEnumerable<Classifier> classifiers, IEnumerable<Policy> policies)
    {
        ArgumentNullException.ThrowIfNull(classifiers);
        ArgumentNullException.ThrowIfNull(policies);

        var classifierLookup = EnumerateClassifiers(classifiers)
            .GroupBy(classifier => classifier.Name, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);

        var linkCount = 0;
        foreach (var policy in policies.Where(static item => item.Domain == PolicyDomain.Data))
        {
            foreach (var classifierName in GetRequiredClassifierNames(policy))
            {
                if (!classifierLookup.TryGetValue(classifierName, out var classifier))
                {
                    continue;
                }

                if ((policy.PolicyClassifiers ?? []).Any(pc => pc.ClassifierId == classifier.Id))
                {
                    continue;
                }

                var link = new PolicyClassifier
                {
                    Policy = policy,
                    PolicyId = policy.Id,
                    Classifier = classifier,
                    ClassifierId = classifier.Id
                };

                policy.PolicyClassifiers ??= [];
                classifier.PolicyClassifiers ??= [];
                policy.PolicyClassifiers.Add(link);
                classifier.PolicyClassifiers.Add(link);
                linkCount++;
            }
        }

        return linkCount;
    }

    public static IEnumerable<Classifier> EnumerateClassifiers(IEnumerable<Classifier> classifiers)
    {
        ArgumentNullException.ThrowIfNull(classifiers);

        foreach (var classifier in classifiers)
        {
            yield return classifier;

            var childClassifiers = classifier.SubClassifiers ?? [];
            if (childClassifiers.Count == 0)
            {
                continue;
            }

            foreach (var child in EnumerateClassifiers(childClassifiers))
            {
                yield return child;
            }
        }
    }
}
