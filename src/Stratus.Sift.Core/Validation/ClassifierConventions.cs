using System.Text.RegularExpressions;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Core.Validation;

public static class ClassifierConventions
{
    public static IReadOnlyDictionary<string, string[]> ValidateClassifier(Classifier classifier)
    {
        ArgumentNullException.ThrowIfNull(classifier);

        var errors = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        ValidateClassifier(classifier, errors, null);

        return errors.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.Distinct(StringComparer.Ordinal).ToArray(),
            StringComparer.OrdinalIgnoreCase);
    }

    public static bool LooksLikeRegexPattern(string pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        return pattern.Any(static c =>
            c == '*'
            || c == '?'
            || c == '['
            || c == '\\'
            || c == '^'
            || c == '$'
            || c == '+'
            || c == '{'
            || c == '|'
            || c == '('
            || c == ')');
    }

    private static void ValidateClassifier(
        Classifier classifier,
        IDictionary<string, List<string>> errors,
        string? prefix)
    {
        var namePrefix = prefix is null ? string.Empty : prefix + ".";

        if (string.IsNullOrWhiteSpace(classifier.Name))
        {
            AddError(errors, namePrefix + "name", "Classifier name is required.");
        }

        if (classifier.EntropyThreshold < 0)
        {
            AddError(errors, namePrefix + "entropyThreshold", "Entropy threshold must be greater than or equal to 0.");
        }

        if (!string.IsNullOrWhiteSpace(classifier.Validator)
            && !ClassifierValidatorCatalog.IsKnown(classifier.Validator))
        {
            AddError(
                errors,
                namePrefix + "validator",
                $"Validator '{classifier.Validator}' is not supported. Allowed values: {string.Join(", ", ClassifierValidatorCatalog.All)}.");
        }

        if (classifier.Matches is null || classifier.Matches.Count == 0)
        {
            AddError(errors, namePrefix + "matches", "At least one match rule is required.");
        }
        else
        {
            for (var i = 0; i < classifier.Matches.Count; i++)
            {
                ValidateMatch(classifier.Matches[i], errors, BuildPath(prefix, $"matches[{i}]"));
            }
        }

        if (classifier.SubClassifiers is null || classifier.SubClassifiers.Count == 0)
        {
            return;
        }

        for (var i = 0; i < classifier.SubClassifiers.Count; i++)
        {
            ValidateClassifier(classifier.SubClassifiers[i], errors, BuildPath(prefix, $"subClassifiers[{i}]"));
        }
    }

    private static void ValidateMatch(
        ClassifierMatch match,
        IDictionary<string, List<string>> errors,
        string prefix)
    {
        var patterns = match.Patterns ?? [];
        if (patterns.Count == 0 || patterns.All(string.IsNullOrWhiteSpace))
        {
            AddError(errors, prefix + ".patterns", "At least one non-blank pattern is required.");
            return;
        }

        for (var i = 0; i < patterns.Count; i++)
        {
            var pattern = patterns[i];
            if (string.IsNullOrWhiteSpace(pattern))
            {
                AddError(errors, prefix + ".patterns", "Pattern entries cannot be blank.");
                continue;
            }

            if (!RequiresRegexCompilation(match, pattern))
            {
                continue;
            }

            try
            {
                var options = RegexOptions.CultureInvariant
                    | (match.CaseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase);
                _ = new Regex(pattern, options, TimeSpan.FromSeconds(1));
            }
            catch (ArgumentException ex)
            {
                AddError(errors, prefix + ".patterns", $"Pattern '{pattern}' is not a valid regular expression: {ex.Message}");
            }
        }

        if (match.Keywords is { Count: > 0 } && match.Keywords.Any(string.IsNullOrWhiteSpace))
        {
            AddError(errors, prefix + ".keywords", "Keyword entries cannot be blank.");
        }

        if (!ContentExtensionProfiles.IsKnown(match.ExtensionProfile))
        {
            AddError(
                errors,
                prefix + ".extensionProfile",
                $"Extension profile '{match.ExtensionProfile}' is not supported. Allowed values: {string.Join(", ", ContentExtensionProfiles.Names)}.");
        }

        if (!string.IsNullOrWhiteSpace(match.ExtensionProfile) && match.Target != RuleTarget.Content)
        {
            AddError(errors, prefix + ".extensionProfile", "Extension profiles can only be used with content rules.");
        }

        if (match.IncludedExtensions is { Count: > 0 } && match.IncludedExtensions.Any(string.IsNullOrWhiteSpace))
        {
            AddError(errors, prefix + ".includedExtensions", "Included extension entries cannot be blank.");
        }
    }

    private static bool RequiresRegexCompilation(ClassifierMatch match, string pattern)
    {
        if (match.IsLiteral)
        {
            return false;
        }

        return match.Target switch
        {
            RuleTarget.Content => true,
            RuleTarget.FileName or RuleTarget.DirectoryName or RuleTarget.DirectoryPath => LooksLikeRegexPattern(pattern),
            _ => false
        };
    }

    private static void AddError(IDictionary<string, List<string>> errors, string key, string message)
    {
        if (!errors.TryGetValue(key, out var bucket))
        {
            bucket = [];
            errors[key] = bucket;
        }

        bucket.Add(message);
    }

    private static string BuildPath(string? prefix, string segment)
        => prefix is null ? segment : prefix + "." + segment;
}
