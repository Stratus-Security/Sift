using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class TwilioValidator : BaseValidator
{
    private static readonly HashSet<string> TwilioIndicators = new(CommonTestIndicators, StringComparer.OrdinalIgnoreCase)
    {
        "twilio",
        "accountsid",
        "apikeysid",
        "authtoken"
    };

    public override string Name => ClassifierValidatorCatalog.Twilio;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim();
        if (string.IsNullOrWhiteSpace(candidate) || candidate.Length != 34)
        {
            return new ValidationResult { IsValid = false, Reason = "Twilio identifier must be 34 characters" };
        }

        var prefix = candidate[..2];
        if (!prefix.Equals("AC", StringComparison.OrdinalIgnoreCase)
            && !prefix.Equals("SK", StringComparison.OrdinalIgnoreCase))
        {
            return new ValidationResult { IsValid = false, Reason = "Unsupported Twilio identifier prefix" };
        }

        var suffix = candidate[2..];
        if (!suffix.All(Uri.IsHexDigit))
        {
            return new ValidationResult { IsValid = false, Reason = "Twilio identifier suffix must be hexadecimal" };
        }

        if (LooksLikeRepeatedPlaceholder(suffix))
        {
            return new ValidationResult { IsValid = false, Reason = "Twilio identifier looks like a placeholder" };
        }

        var contextResult = CheckCommonContextClues(context, TwilioIndicators);
        if (contextResult != null)
        {
            return contextResult;
        }

        return new ValidationResult { IsValid = true, Confidence = 1.0 };
    }
}
