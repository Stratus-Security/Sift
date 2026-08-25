using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class TwilioValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.Twilio;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim();
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return Invalid("Twilio credential assignment is empty");
        }

        var delimiter = candidate.IndexOfAny(['=', ':']);
        if (delimiter <= 0 || delimiter == candidate.Length - 1)
        {
            return Invalid("Twilio credential assignment is malformed");
        }

        var name = candidate[..delimiter].Trim().Trim('"', '\'', '`');
        var normalizedName = new string(name.Where(char.IsAsciiLetterOrDigit).Select(char.ToLowerInvariant).ToArray());
        if (normalizedName is not "twilioauthtoken" and not "twilioapisecret")
        {
            return Invalid("Candidate is not a Twilio Auth Token or API Secret assignment");
        }

        var value = candidate[(delimiter + 1)..]
            .Trim()
            .TrimEnd(';', ',')
            .Trim('"', '\'', '`');
        if (value.Length is < 1 or > 4096 || value.Any(char.IsWhiteSpace))
        {
            return Invalid("Twilio secret value is malformed");
        }

        if (LooksLikeRepeatedPlaceholder(value)
            || value.Contains("example", StringComparison.OrdinalIgnoreCase)
            || value.Contains("placeholder", StringComparison.OrdinalIgnoreCase))
        {
            return new ValidationResult
            {
                IsValid = true,
                Confidence = 0.15,
                Reason = "Twilio secret resembles a placeholder or weak value"
            };
        }

        return CheckCommonContextClues(context)
            ?? new ValidationResult { IsValid = true, Confidence = 1.0 };
    }

    private static ValidationResult Invalid(string reason) => new() { IsValid = false, Reason = reason };
}
