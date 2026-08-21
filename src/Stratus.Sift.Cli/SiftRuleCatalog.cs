using System.Text.RegularExpressions;

namespace Stratus.Sift.Cli;

internal sealed record SiftRule(
    string Id,
    string Name,
    string Severity,
    string Confidence,
    Regex Pattern,
    string? SecretGroup = null,
    Func<string, bool>? Validator = null);

internal static partial class SiftRuleCatalog
{
    internal static IReadOnlyList<SiftRule> Default { get; } =
    [
        Rule("private-key", "Private key", "critical", "high", PrivateKeyPattern()),
        Rule("aws-access-key", "AWS access key", "high", "high", AwsAccessKeyPattern()),
        Rule("aws-secret-key", "AWS secret access key", "critical", "high", AwsSecretKeyPattern(), "secret"),
        Rule("github-token", "GitHub token", "critical", "high", GitHubTokenPattern()),
        Rule("slack-token", "Slack token", "high", "high", SlackTokenPattern()),
        Rule("openai-key", "OpenAI API key", "critical", "high", OpenAiKeyPattern()),
        Rule("stripe-key", "Stripe secret key", "critical", "high", StripeKeyPattern()),
        Rule("jwt", "JSON Web Token", "medium", "medium", JsonWebTokenPattern()),
        Rule("connection-password", "Connection-string password", "critical", "high", ConnectionPasswordPattern(), "secret"),
        Rule("secret-assignment", "Secret assignment", "high", "medium", SecretAssignmentPattern(), "secret"),
        Rule("basic-auth-uri", "Credentialed service URI", "high", "high", BasicAuthUriPattern(), "secret"),
        Rule("payment-card", "Payment card number", "high", "medium", PaymentCardPattern(), Validator: IsValidPaymentCard),
        Rule("iban", "International bank account number", "medium", "medium", IbanPattern(), Validator: IsValidIban),
    ];

    private static SiftRule Rule(
        string id,
        string name,
        string severity,
        string confidence,
        Regex pattern,
        string? secretGroup = null,
        Func<string, bool>? Validator = null)
        => new(
            id,
            name,
            severity,
            confidence,
            pattern,
            secretGroup,
            Validator);

    [GeneratedRegex(
        @"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex PrivateKeyPattern();

    [GeneratedRegex(
        @"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex AwsAccessKeyPattern();

    [GeneratedRegex(
        @"\b(?:aws_secret_access_key|awsSecretAccessKey)\b\s*[:=]\s*[""']?(?<secret>[A-Za-z0-9/+=]{40})",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex AwsSecretKeyPattern();

    [GeneratedRegex(
        @"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex GitHubTokenPattern();

    [GeneratedRegex(
        @"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex SlackTokenPattern();

    [GeneratedRegex(
        @"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,200}\b",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex OpenAiKeyPattern();

    [GeneratedRegex(
        @"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex StripeKeyPattern();

    [GeneratedRegex(
        @"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex JsonWebTokenPattern();

    [GeneratedRegex(
        @"\b(?:password|pwd)\s*=\s*[""']?(?<secret>[^;\s,""']{4,})",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex ConnectionPasswordPattern();

    [GeneratedRegex(
        @"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b\s*[:=]\s*[""']?(?<secret>[A-Za-z0-9_./+=:@-]{8,})",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex SecretAssignmentPattern();

    [GeneratedRegex(
        @"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:(?<secret>[^\s/@]{4,})@[^\s]+",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex BasicAuthUriPattern();

    [GeneratedRegex(
        @"\b(?:\d[ -]*?){13,19}\b",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex PaymentCardPattern();

    [GeneratedRegex(
        @"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex IbanPattern();

    internal static bool IsValidPaymentCard(string value)
    {
        var digits = value.Where(char.IsDigit).Select(character => character - '0').ToArray();
        if (digits.Length is < 13 or > 19 || digits.All(digit => digit == digits[0]))
        {
            return false;
        }

        var sum = 0;
        var doubleDigit = false;
        for (var index = digits.Length - 1; index >= 0; index--)
        {
            var digit = digits[index];
            if (doubleDigit)
            {
                digit *= 2;
                if (digit > 9)
                {
                    digit -= 9;
                }
            }

            sum += digit;
            doubleDigit = !doubleDigit;
        }

        return sum % 10 == 0;
    }

    internal static bool IsValidIban(string value)
    {
        var normalized = new string(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());
        if (normalized.Length is < 15 or > 34 || !char.IsLetter(normalized[0]) || !char.IsLetter(normalized[1]))
        {
            return false;
        }

        var rearranged = normalized[4..] + normalized[..4];
        var remainder = 0;
        foreach (var character in rearranged)
        {
            if (char.IsDigit(character))
            {
                remainder = ((remainder * 10) + (character - '0')) % 97;
                continue;
            }

            var numeric = character - 'A' + 10;
            remainder = ((remainder * 10) + (numeric / 10)) % 97;
            remainder = ((remainder * 10) + (numeric % 10)) % 97;
        }

        return remainder == 1;
    }
}
