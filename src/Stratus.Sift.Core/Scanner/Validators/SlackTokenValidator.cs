using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class SlackTokenValidator : StructuredTokenValidatorBase
{
    private static readonly HashSet<string> ValidPrefixes = new(StringComparer.Ordinal)
    {
        "xoxb",
        "xoxp",
        "xoxa",
        "xoxr",
        "xoxs",
        "xoxe"
    };

    public override string Name => ClassifierValidatorCatalog.SlackToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Missing Slack token" };
        }

        var segments = candidate.Split('-', StringSplitOptions.None);
        if (segments.Length < 3 || !ValidPrefixes.Contains(segments[0]))
        {
            return new ValidationResult { IsValid = false, Reason = "Slack token shape is invalid" };
        }

        for (var i = 1; i < segments.Length; i++)
        {
            var segment = segments[i];
            if (!IsAsciiAlphaNumeric(segment))
            {
                return new ValidationResult { IsValid = false, Reason = "Slack token contains invalid characters" };
            }

            if (LooksLikePlaceholderToken(segment))
            {
                return new ValidationResult { IsValid = false, Reason = "Slack token looks like a placeholder" };
            }
        }

        if (segments[^1].Length < 10)
        {
            return new ValidationResult { IsValid = false, Reason = "Slack token secret segment is too short" };
        }

        return ValidWithContextReview(context);
    }
}
