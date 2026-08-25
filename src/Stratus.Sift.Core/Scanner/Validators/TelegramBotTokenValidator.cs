using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class TelegramBotTokenValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.TelegramBotToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Missing Telegram bot token" };
        }

        var separatorIndex = candidate.IndexOf(':');
        if (separatorIndex <= 0 || separatorIndex == candidate.Length - 1)
        {
            return new ValidationResult { IsValid = false, Reason = "Telegram bot token shape is invalid" };
        }

        var botId = candidate[..separatorIndex];
        var secret = candidate[(separatorIndex + 1)..];

        if (botId.Length is < 8 or > 12 || !botId.All(char.IsAsciiDigit) || botId.All(static c => c == '0'))
        {
            return new ValidationResult { IsValid = false, Reason = "Telegram bot identifier is malformed" };
        }

        if (secret.Length is < 30 or > 50 || !IsAlphaNumericDashOrUnderscore(secret))
        {
            return new ValidationResult { IsValid = false, Reason = "Telegram bot secret is malformed" };
        }

        return CheckPlaceholderClues(secret, 12) ?? ValidWithContextReview(context);
    }
}
