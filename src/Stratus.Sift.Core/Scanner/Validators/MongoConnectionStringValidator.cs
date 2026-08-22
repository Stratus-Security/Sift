using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class MongoConnectionStringValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.MongoConnectionString;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = ExtractDelimitedContextToken(context);
        if (!candidate.StartsWith("mongodb://", StringComparison.OrdinalIgnoreCase)
            && !candidate.StartsWith("mongodb+srv://", StringComparison.OrdinalIgnoreCase))
        {
            return new ValidationResult { IsValid = false, Reason = "Candidate is not a MongoDB URI" };
        }

        if (!TryGetAuthority(candidate, out var authority))
        {
            return new ValidationResult { IsValid = false, Reason = "MongoDB URI is missing authority data" };
        }

        var atIndex = authority.IndexOf('@');
        var colonIndex = authority.IndexOf(':');
        if (colonIndex <= 0 || atIndex <= colonIndex + 1)
        {
            return new ValidationResult { IsValid = false, Reason = "MongoDB URI is missing user or password information" };
        }

        var hostPart = authority[(atIndex + 1)..];
        if (string.IsNullOrWhiteSpace(hostPart))
        {
            return new ValidationResult { IsValid = false, Reason = "MongoDB URI is missing a host" };
        }

        var contextResult = CheckCommonContextClues(context);
        if (contextResult != null)
        {
            return contextResult;
        }

        return new ValidationResult { IsValid = true, Confidence = 1.0 };
    }

    private static bool TryGetAuthority(string candidate, out string authority)
    {
        var schemeSeparator = candidate.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator < 0)
        {
            authority = string.Empty;
            return false;
        }

        var authorityStart = schemeSeparator + 3;
        var authorityEnd = candidate.IndexOfAny(['/', '?'], authorityStart);
        authority = authorityEnd >= 0 ? candidate[authorityStart..authorityEnd] : candidate[authorityStart..];
        return authority.Length > 0;
    }
}
