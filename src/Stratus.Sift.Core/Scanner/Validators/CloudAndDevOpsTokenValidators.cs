using System.Text;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public sealed class AzureDevOpsPatValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.AzureDevOpsPat;

    public override ValidationResult Validate(ValidationContext context)
    {
        var token = context.Candidate.Trim().Trim('"', '\'', '`');
        if (!IsAsciiAlphaNumeric(token))
        {
            return Invalid("Azure DevOps PAT contains invalid characters");
        }

        if (token.Length == 84)
        {
            if (!token.AsSpan(75, 4).SequenceEqual("AZDO"))
            {
                return Invalid("Azure DevOps PAT signature is missing");
            }
        }
        else if (token.Length == 52)
        {
            if (!HasNearbyContext(context, "pat", "azuredevops", "azure_devops", "vsts", "dev.azure.com", "visualstudio.com"))
            {
                return Invalid("Legacy Azure DevOps PAT lacks provider context");
            }
        }
        else
        {
            return Invalid("Azure DevOps PAT length is invalid");
        }

        return CheckPlaceholderClues(token, 12) ?? ValidWithContextReview(context);
    }

    private static bool HasNearbyContext(ValidationContext context, params string[] indicators)
    {
        var start = Math.Clamp(context.Index - 100, 0, context.FullFileContent.Length);
        var length = Math.Min(context.FullFileContent.Length - start, context.Candidate.Length + 200);
        var surrounding = context.FullFileContent.AsSpan(start, length);
        foreach (var indicator in indicators)
        {
            if (surrounding.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static ValidationResult Invalid(string reason) => new() { IsValid = false, Reason = reason };
}

public sealed class AwsSessionTokenValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.AwsSessionToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate.Trim();
        var separator = candidate.IndexOfAny(['=', ':']);
        var token = (separator >= 0 ? candidate[(separator + 1)..] : candidate).Trim().Trim('"', '\'', '`');

        if (token.Length < 80 || token.Length > 4096 || token.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c is '/' or '+' or '=')))
        {
            return new ValidationResult { IsValid = false, Reason = "AWS session token is malformed" };
        }

        return CheckPlaceholderClues(token, 16) ?? ValidWithContextReview(context);
    }
}

public sealed class GitLabOperationalTokenValidator : StructuredTokenValidatorBase
{
    private static readonly string[] Prefixes =
    [
        "gloas-", "gldt-", "glrt-", "glrtr-", "glcbt-", "glptt-", "glft-", "glimt-",
        "glagent-", "glwt-", "glsoat-", "glffct-"
    ];

    public override string Name => ClassifierValidatorCatalog.GitLabOperationalToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate.Trim().Trim('"', '\'', '`');
        var prefix = Prefixes.FirstOrDefault(value => candidate.StartsWith(value, StringComparison.Ordinal));
        if (prefix is null)
        {
            return new ValidationResult { IsValid = false, Reason = "GitLab token prefix is invalid" };
        }

        var suffix = candidate[prefix.Length..];
        if (suffix.Length is < 12 or > 512 || !IsAlphaNumericDashOrUnderscore(suffix))
        {
            return new ValidationResult { IsValid = false, Reason = "GitLab token body is malformed" };
        }

        return CheckPlaceholderClues(suffix, 10) ?? ValidWithContextReview(context);
    }
}

public sealed class PyPiApiTokenValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.PyPiApiToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate.Trim().Trim('"', '\'', '`');
        const string prefix = "pypi-";
        if (!candidate.StartsWith(prefix, StringComparison.Ordinal))
        {
            return new ValidationResult { IsValid = false, Reason = "PyPI token prefix is invalid" };
        }

        var payload = candidate[prefix.Length..];
        if (payload.Length < 85 || payload.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
        {
            return new ValidationResult { IsValid = false, Reason = "PyPI token payload is malformed" };
        }

        return CheckPlaceholderClues(payload, 16) ?? ValidWithContextReview(context);
    }
}

public sealed class DockerAccessTokenValidator : StructuredTokenValidatorBase
{
    private static readonly string[] Prefixes = ["dckr_pat_", "dckr_oat_"];

    public override string Name => ClassifierValidatorCatalog.DockerAccessToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate.Trim().Trim('"', '\'', '`');
        var prefix = Prefixes.FirstOrDefault(value => candidate.StartsWith(value, StringComparison.Ordinal));
        if (prefix is null)
        {
            return new ValidationResult { IsValid = false, Reason = "Docker token prefix is invalid" };
        }

        var suffix = candidate[prefix.Length..];
        if (suffix.Length is < 12 or > 512 || !IsAlphaNumericDashOrUnderscore(suffix))
        {
            return new ValidationResult { IsValid = false, Reason = "Docker token body is malformed" };
        }

        return CheckPlaceholderClues(suffix, 10) ?? ValidWithContextReview(context);
    }
}

public sealed class DockerConfigAuthValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.DockerConfigAuth;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate;
        var colon = candidate.IndexOf(':');
        var encoded = (colon >= 0 ? candidate[(colon + 1)..] : candidate).Trim().Trim('"', '\'', '`');
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var separator = decoded.IndexOf(':');
            if (separator < 0 || decoded.Any(char.IsControl))
            {
                return new ValidationResult { IsValid = false, Reason = "Docker auth value is not username:secret" };
            }

            if (separator == 0 || separator == decoded.Length - 1)
            {
                return new ValidationResult
                {
                    IsValid = true,
                    Confidence = 0.4,
                    Reason = "Docker auth contains an empty username or secret"
                };
            }
        }
        catch (FormatException)
        {
            return new ValidationResult { IsValid = false, Reason = "Docker auth value is not valid Base64" };
        }

        return ValidWithContextReview(context);
    }
}
