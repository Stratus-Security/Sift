using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Core.Defaults;

/// <summary>Translates the standalone rule format into the scanner's detection and finding models.</summary>
public static class SiftingRuleMaterializer
{
    public static (Classifier Classifier, IReadOnlyList<Policy> Policies) Materialize(SiftingRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        var policies = new List<Policy>();
        var classifier = MaterializeClassifier(rule, policies);
        return (classifier, policies);
    }

    private static Classifier MaterializeClassifier(SiftingRule rule, List<Policy> policies)
    {
        if (string.IsNullOrWhiteSpace(rule.Name))
        {
            throw new InvalidOperationException("Sifting rule name is required.");
        }

        if (rule.MinMatchCount < 1)
        {
            throw new InvalidOperationException($"Sifting rule '{rule.Name}' must use MinMatchCount of at least 1.");
        }

        var classifier = new Classifier
        {
            IsEnabled = rule.Enabled,
            Name = rule.Name.Trim(),
            Description = rule.Description,
            Label = string.IsNullOrWhiteSpace(rule.Label) ? "Custom" : rule.Label.Trim(),
            Matches = rule.Matches ?? [],
            Validator = rule.Validator,
            EntropyThreshold = rule.EntropyThreshold,
            EnableLlmValidation = rule.EnableLlmValidation
        };

        foreach (var subRule in rule.SubRules ?? [])
        {
            classifier.SubClassifiers.Add(MaterializeClassifier(subRule, policies));
        }

        if (!rule.ReportFinding)
        {
            return classifier;
        }

        var policy = new Policy
        {
            Name = string.IsNullOrWhiteSpace(rule.FindingName) ? classifier.Name : rule.FindingName.Trim(),
            Description = rule.Description,
            Active = rule.Enabled,
            Domain = PolicyDomain.Data,
            Severity = rule.Severity ?? Severity.Medium,
            StopOnMatch = rule.StopOnMatch,
            ClassifierNames = [classifier.Name],
            Configuration = new PolicyConfiguration
            {
                Description = rule.Description ?? string.Empty,
                IncludePaths = rule.IncludePaths ?? [],
                ExcludePaths = rule.ExcludePaths ?? [],
                MinMatchCount = rule.MinMatchCount
            }
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
        policies.Add(policy);
        return classifier;
    }
}
