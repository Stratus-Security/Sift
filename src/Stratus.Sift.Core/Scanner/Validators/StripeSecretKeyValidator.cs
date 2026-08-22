using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class StripeSecretKeyValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.StripeSecretKey;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Missing Stripe key" };
        }

        if (!TryParseKey(candidate, out var suffix))
        {
            return new ValidationResult { IsValid = false, Reason = "Stripe key prefix is invalid" };
        }

        if (suffix.Length is < 24 or > 99 || !IsAsciiAlphaNumeric(suffix))
        {
            return new ValidationResult { IsValid = false, Reason = "Stripe key body is malformed" };
        }

        if (LooksLikePlaceholderToken(suffix, 12))
        {
            return new ValidationResult { IsValid = false, Reason = "Stripe key looks like a placeholder" };
        }

        return ValidWithContextReview(context);
    }

    private static bool TryParseKey(string candidate, out string suffix)
    {
        suffix = string.Empty;
        if (candidate.StartsWith("sk_live_", StringComparison.Ordinal)
            || candidate.StartsWith("sk_test_", StringComparison.Ordinal)
            || candidate.StartsWith("rk_live_", StringComparison.Ordinal)
            || candidate.StartsWith("rk_test_", StringComparison.Ordinal))
        {
            suffix = candidate[(candidate.IndexOf('_', candidate.IndexOf('_') + 1) + 1)..];
            return true;
        }

        return false;
    }
}
