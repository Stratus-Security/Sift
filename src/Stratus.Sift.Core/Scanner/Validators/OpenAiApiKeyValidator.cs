using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class OpenAiApiKeyValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.OpenAiApiKey;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Missing OpenAI API key" };
        }

        string suffix;
        if (candidate.StartsWith("sk-proj-", StringComparison.Ordinal))
        {
            suffix = candidate["sk-proj-".Length..];
        }
        else if (candidate.StartsWith("sk-svc-", StringComparison.Ordinal))
        {
            suffix = candidate["sk-svc-".Length..];
        }
        else if (candidate.StartsWith("sk-", StringComparison.Ordinal))
        {
            suffix = candidate["sk-".Length..];
        }
        else
        {
            return new ValidationResult { IsValid = false, Reason = "OpenAI API key prefix is invalid" };
        }

        if (suffix.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c == '-')))
        {
            return new ValidationResult { IsValid = false, Reason = "OpenAI API key contains invalid characters" };
        }

        if (suffix.Length < 32)
        {
            return new ValidationResult { IsValid = false, Reason = "OpenAI API key body is malformed" };
        }

        if (LooksLikePlaceholderToken(suffix, 12))
        {
            return new ValidationResult { IsValid = false, Reason = "OpenAI API key looks like a placeholder" };
        }

        return ValidWithContextReview(context);
    }
}
