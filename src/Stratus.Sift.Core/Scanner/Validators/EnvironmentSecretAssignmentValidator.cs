using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public sealed class EnvironmentSecretAssignmentValidator : BaseValidator
{
    private static readonly string[] PlaceholderMarkers =
    [
        "changeme", "dummy", "example", "fake", "insert", "notset", "placeholder", "redacted",
        "replace", "sample", "todo", "unset", "xxxx", "yourapikey", "yourpassword", "yoursecret", "yourtoken"
    ];

    private static readonly string[] ReferencePrefixes =
    [
        "$", "%", "{{", "<", "@microsoft.keyvault", "arn:aws:secretsmanager:", "env:", "file:",
        "op://", "projects/", "secret:", "sm://", "vault:"
    ];

    public override string Name => ClassifierValidatorCatalog.EnvironmentSecretAssignment;

    public override ValidationResult Validate(ValidationContext context)
    {
        var delimiter = context.Candidate.IndexOfAny(['=', ':']);
        if (delimiter < 0 || delimiter == context.Candidate.Length - 1)
        {
            return Invalid("Secret assignment is malformed");
        }

        var value = context.Candidate[(delimiter + 1)..].Trim().Trim('"', '\'', '`');
        if (value.Length is < 12 or > 4096)
        {
            return Invalid("Assigned value length is not credible");
        }

        if (ReferencePrefixes.Any(prefix => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
        {
            return Invalid("Assigned value is an indirect secret reference");
        }

        var normalized = new string(value
            .Where(char.IsAsciiLetterOrDigit)
            .Select(char.ToLowerInvariant)
            .ToArray());

        if (normalized is "none" or "null" or "undefined"
            || PlaceholderMarkers.Any(normalized.Contains)
            || value.Distinct().Take(5).Count() < 5)
        {
            return Invalid("Assigned value looks like a placeholder");
        }

        return CheckCommonContextClues(context)
            ?? new ValidationResult { IsValid = true, Confidence = 0.9 };
    }

    private static ValidationResult Invalid(string reason) => new() { IsValid = false, Reason = reason };
}
