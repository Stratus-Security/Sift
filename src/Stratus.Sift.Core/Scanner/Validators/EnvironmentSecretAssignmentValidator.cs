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
        "@microsoft.keyvault", "arn:aws:secretsmanager:", "env:", "file:",
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

        var assignmentName = context.Candidate[..delimiter].Trim().Trim('"', '\'', '`');
        var value = context.Candidate[(delimiter + 1)..]
            .Trim()
            .TrimEnd(';', ',')
            .Trim('"', '\'', '`');

        if (IsPublicKeyTokenName(assignmentName))
        {
            return Invalid("Assigned value is a public assembly identity token");
        }

        if (value.Length is < 1 or > 4096)
        {
            return Invalid("Assigned value length is not credible");
        }

        if (value.Equals(assignmentName, StringComparison.OrdinalIgnoreCase))
        {
            return LowConfidence("Assigned value is the same as its assignment name");
        }

        if (LooksLikeIndirectReference(value))
        {
            return Invalid("Assigned value is an indirect secret reference");
        }

        if (value.Length < 12)
        {
            return LowConfidence("Assigned value is unusually short but may be a weak secret");
        }

        var normalized = new string(value
            .Where(char.IsAsciiLetterOrDigit)
            .Select(char.ToLowerInvariant)
            .ToArray());

        if (normalized is "none" or "null" or "undefined"
            || PlaceholderMarkers.Any(normalized.Contains)
            || value.Distinct().Take(5).Count() < 5)
        {
            return LowConfidence("Assigned value resembles a placeholder or weak secret");
        }

        return CheckCommonContextClues(context)
            ?? new ValidationResult { IsValid = true, Confidence = 0.9 };
    }

    private static bool IsPublicKeyTokenName(string name)
    {
        return name.Equals("publicKeyToken", StringComparison.OrdinalIgnoreCase)
            || name.Equals("public_key_token", StringComparison.OrdinalIgnoreCase)
            || name.Equals("public-key-token", StringComparison.OrdinalIgnoreCase)
            || name.Equals("public.key.token", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeIndirectReference(string value)
    {
        if (ReferencePrefixes.Any(prefix => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (value.StartsWith("${", StringComparison.Ordinal) && value.EndsWith('}'))
        {
            return true;
        }

        if (value.StartsWith("$(", StringComparison.Ordinal) && value.EndsWith(')'))
        {
            return true;
        }

        if (value.StartsWith("$env:", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (value.Length > 1 && value[0] == '$'
            && value[1..].All(static character => char.IsAsciiLetterOrDigit(character) || character == '_'))
        {
            return true;
        }

        if (value.Length > 2 && value[0] == '%' && value[^1] == '%'
            && value[1..^1].All(static character => char.IsAsciiLetterOrDigit(character) || character == '_'))
        {
            return true;
        }

        return value.StartsWith("{{", StringComparison.Ordinal) && value.EndsWith("}}", StringComparison.Ordinal)
            || value.StartsWith('<') && value.EndsWith('>');
    }

    private static ValidationResult Invalid(string reason) => new() { IsValid = false, Reason = reason };

    private static ValidationResult LowConfidence(string reason) => new()
    {
        IsValid = true,
        Confidence = 0.2,
        Reason = reason
    };
}
