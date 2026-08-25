using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class SendGridApiKeyValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.SendGridApiKey;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Missing SendGrid API key" };
        }

        var segments = candidate.Split('.', StringSplitOptions.None);
        if (segments.Length != 3 || !string.Equals(segments[0], "SG", StringComparison.Ordinal))
        {
            return new ValidationResult { IsValid = false, Reason = "SendGrid API key shape is invalid" };
        }

        if (segments[1].Length is < 20 or > 25 || segments[2].Length is < 40 or > 50)
        {
            return new ValidationResult { IsValid = false, Reason = "SendGrid API key segments are malformed" };
        }

        if (!IsAlphaNumericDashOrUnderscore(segments[1]) || !IsAlphaNumericDashOrUnderscore(segments[2]))
        {
            return new ValidationResult { IsValid = false, Reason = "SendGrid API key contains invalid characters" };
        }

        return CheckPlaceholderClues(segments[1], 10)
            ?? CheckPlaceholderClues(segments[2], 12)
            ?? ValidWithContextReview(context);
    }
}
