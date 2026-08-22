using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class NpmAccessTokenValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.NpmAccessToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        const string prefix = "npm_";

        if (string.IsNullOrWhiteSpace(candidate) || !candidate.StartsWith(prefix, StringComparison.Ordinal))
        {
            return new ValidationResult { IsValid = false, Reason = "NPM token prefix is invalid" };
        }

        var suffix = candidate[prefix.Length..];
        if (suffix.Length != 36 || !IsAsciiAlphaNumeric(suffix))
        {
            return new ValidationResult { IsValid = false, Reason = "NPM token body is malformed" };
        }

        if (LooksLikePlaceholderToken(suffix, 12))
        {
            return new ValidationResult { IsValid = false, Reason = "NPM token looks like a placeholder" };
        }

        return ValidWithContextReview(context);
    }
}
