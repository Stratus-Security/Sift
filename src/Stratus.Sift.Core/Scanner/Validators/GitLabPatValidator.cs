using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class GitLabPatValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.GitLabPat;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        const string prefix = "glpat-";

        if (string.IsNullOrWhiteSpace(candidate) || !candidate.StartsWith(prefix, StringComparison.Ordinal))
        {
            return new ValidationResult { IsValid = false, Reason = "GitLab token prefix is invalid" };
        }

        var suffix = candidate[prefix.Length..];
        if (suffix.Length is < 20 or > 255 || !IsAlphaNumericDashOrUnderscore(suffix))
        {
            return new ValidationResult { IsValid = false, Reason = "GitLab token body is malformed" };
        }

        return CheckPlaceholderClues(suffix, 10) ?? ValidWithContextReview(context);
    }
}
