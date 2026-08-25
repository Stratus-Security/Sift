using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public sealed class VaultTokenValidator : StructuredTokenValidatorBase
{
    private static readonly string[] CurrentPrefixes = ["hvs.", "hvb.", "hvr."];
    private static readonly string[] LegacyPrefixes = ["s.", "b.", "r."];

    public override string Name => ClassifierValidatorCatalog.VaultToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate.Trim().Trim('"', '\'', '`');
        var prefix = CurrentPrefixes.Concat(LegacyPrefixes)
            .FirstOrDefault(value => candidate.StartsWith(value, StringComparison.Ordinal));
        if (prefix is null)
        {
            return Invalid("Vault token prefix is invalid");
        }

        var payload = candidate[prefix.Length..];
        if (payload.Length < 24 || payload.Length > 4096 || payload.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')))
        {
            return Invalid("Vault token payload is malformed");
        }

        if (LegacyPrefixes.Contains(prefix, StringComparer.Ordinal) && !HasVaultContext(context))
        {
            return Invalid("Legacy Vault token lacks Vault context");
        }

        return CheckPlaceholderClues(payload, 12) ?? ValidWithContextReview(context);
    }

    private static bool HasVaultContext(ValidationContext context)
    {
        var start = Math.Clamp(context.Index - 80, 0, context.FullFileContent.Length);
        var length = Math.Min(context.FullFileContent.Length - start, context.Candidate.Length + 160);
        var surrounding = context.FullFileContent.AsSpan(start, length);
        return surrounding.Contains("vault", StringComparison.OrdinalIgnoreCase)
            || surrounding.Contains("X-Vault-Token", StringComparison.OrdinalIgnoreCase);
    }

    private static ValidationResult Invalid(string reason) => new() { IsValid = false, Reason = reason };
}

public sealed class TerraformTokenValidator : StructuredTokenValidatorBase
{
    public override string Name => ClassifierValidatorCatalog.TerraformToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate.Trim().Trim('"', '\'', '`');
        var isCurrent = candidate.StartsWith("tftk.", StringComparison.Ordinal);
        var isLegacy = candidate.Contains(".atlasv1.", StringComparison.Ordinal);
        if (!isCurrent && !isLegacy)
        {
            return new ValidationResult { IsValid = false, Reason = "Terraform token signature is invalid" };
        }

        if (candidate.Length < 21 || candidate.Length > 1024
            || candidate.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_')))
        {
            return new ValidationResult { IsValid = false, Reason = "Terraform token is malformed" };
        }

        return CheckPlaceholderClues(candidate, 12) ?? ValidWithContextReview(context);
    }
}

public sealed class CredentialedServiceUriValidator : BaseValidator
{
    private static readonly HashSet<string> SupportedSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "mysql", "mariadb", "redis", "rediss", "amqp", "amqps", "neo4j", "neo4j+s", "neo4j+ssc",
        "bolt", "bolt+s", "bolt+ssc"
    };

    public override string Name => ClassifierValidatorCatalog.CredentialedServiceUri;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = ExtractDelimitedContextToken(context);
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri) || !SupportedSchemes.Contains(uri.Scheme))
        {
            return new ValidationResult { IsValid = false, Reason = "Credentialed service URI is malformed" };
        }

        var separator = uri.UserInfo.IndexOf(':');
        if (separator <= 0 || separator == uri.UserInfo.Length - 1 || string.IsNullOrWhiteSpace(uri.Host))
        {
            return new ValidationResult { IsValid = false, Reason = "Service URI is missing username, password, or host" };
        }

        var password = Uri.UnescapeDataString(uri.UserInfo[(separator + 1)..]);
        if (password.Length < 4 || LooksLikeRepeatedPlaceholder(password))
        {
            return new ValidationResult
            {
                IsValid = true,
                Confidence = 0.25,
                Reason = "Service URI contains a weak-looking password"
            };
        }

        return CheckCommonContextClues(context) ?? new ValidationResult { IsValid = true, Confidence = 1.0 };
    }
}

public sealed class BearerTokenValidator : StructuredTokenValidatorBase
{
    private static readonly string[] ProviderPrefixes =
    [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "gloas-", "gldt-",
        "glrt-", "glrtr-", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-", "glwt-", "glsoat-",
        "glffct-", "pypi-", "dckr_pat_", "dckr_oat_", "hvs.", "hvb.", "hvr.", "tftk.", "npm_",
        "sk-", "sk_", "xox", "SG.", "sq0", "EAA", "AIza", "ya29.", "LWA", "hf_", "dapi"
    ];

    public override string Name => ClassifierValidatorCatalog.BearerToken;

    public override ValidationResult Validate(ValidationContext context)
    {
        var marker = context.Candidate.IndexOf("Bearer", StringComparison.OrdinalIgnoreCase);
        var token = (marker >= 0 ? context.Candidate[(marker + "Bearer".Length)..] : context.Candidate)
            .Trim().Trim('"', '\'', '`');
        if (ProviderPrefixes.Any(prefix => token.StartsWith(prefix, StringComparison.Ordinal)))
        {
            return new ValidationResult { IsValid = false, Reason = "Bearer token is handled by a provider-specific detector" };
        }

        if (token.Count(static c => c == '.') == 2)
        {
            return new ValidationResult { IsValid = false, Reason = "Bearer token is handled by the JWT detector" };
        }

        if (token.Length is < 1 or > 4096
            || token.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~' or '+' or '/' or '=')))
        {
            return new ValidationResult { IsValid = false, Reason = "Bearer token is malformed" };
        }

        if (token.Length < 12)
        {
            return new ValidationResult
            {
                IsValid = true,
                Confidence = 0.35,
                Reason = "Bearer token is unusually short but may be a weak credential"
            };
        }

        return CheckPlaceholderClues(token, 12) ?? ValidWithContextReview(context);
    }
}
