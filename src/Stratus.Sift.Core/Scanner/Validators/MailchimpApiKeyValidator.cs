using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class MailchimpApiKeyValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.MailchimpApiKey;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Missing Mailchimp API key" };
        }

        var separatorIndex = candidate.LastIndexOf("-us", StringComparison.OrdinalIgnoreCase);
        if (separatorIndex <= 0)
        {
            return new ValidationResult { IsValid = false, Reason = "Mailchimp API key shape is invalid" };
        }

        var hexPart = candidate[..separatorIndex];
        var dataCenterPart = candidate[(separatorIndex + 3)..];

        if (hexPart.Length != 32 || !IsAsciiHex(hexPart))
        {
            return new ValidationResult { IsValid = false, Reason = "Mailchimp API key hash segment is malformed" };
        }

        if (dataCenterPart.Length == 0
            || dataCenterPart[0] == '0'
            || !dataCenterPart.All(char.IsAsciiDigit))
        {
            return new ValidationResult { IsValid = false, Reason = "Mailchimp API key data center suffix is invalid" };
        }

        return CheckPlaceholderClues(hexPart, 12) ?? ValidWithContextReview(context);
    }
}
