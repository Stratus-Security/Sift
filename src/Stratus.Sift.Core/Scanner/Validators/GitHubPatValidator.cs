using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class GitHubPatValidator : StructuredTokenValidatorBase
{
    private static readonly string[] ClassicPrefixes = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];

    public override string Name => ClassifierValidatorCatalog.GitHubPat;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Missing GitHub token" };
        }

        string suffix;
        if (candidate.StartsWith("github_pat_", StringComparison.Ordinal))
        {
            suffix = candidate["github_pat_".Length..];
            if (suffix.Length < 82)
            {
                return new ValidationResult { IsValid = false, Reason = "GitHub fine-grained token is malformed" };
            }

            if (suffix.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c == '_')))
            {
                return new ValidationResult { IsValid = false, Reason = "GitHub fine-grained token contains invalid characters" };
            }
        }
        else
        {
            var prefix = ClassicPrefixes.FirstOrDefault(prefix => candidate.StartsWith(prefix, StringComparison.Ordinal));
            if (prefix == null)
            {
                return new ValidationResult { IsValid = false, Reason = "GitHub token prefix is invalid" };
            }

            suffix = candidate[prefix.Length..];
            if (suffix.Length is < 36 or > 255 || !IsAsciiAlphaNumeric(suffix))
            {
                return new ValidationResult { IsValid = false, Reason = "GitHub classic token is malformed" };
            }
        }

        if (LooksLikePlaceholderToken(suffix, 12))
        {
            return new ValidationResult { IsValid = false, Reason = "GitHub token looks like a placeholder" };
        }

        return ValidWithContextReview(context);
    }
}
