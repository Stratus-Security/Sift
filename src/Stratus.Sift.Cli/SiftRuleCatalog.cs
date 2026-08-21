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
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(250);

    internal static IReadOnlyList<SiftRule> Default { get; } =
    [
        Rule("private-key", "Private key", "critical", "high", @"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        Rule("aws-access-key", "AWS access key", "high", "high", @"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        Rule("aws-secret-key", "AWS secret access key", "critical", "high", @"(?im)\b(?:aws_secret_access_key|awsSecretAccessKey)\b\s*[:=]\s*[""']?(?<secret>[A-Za-z0-9/+=]{40})", "secret"),
        Rule("github-token", "GitHub token", "critical", "high", @"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
        Rule("slack-token", "Slack token", "high", "high", @"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b"),
        Rule("openai-key", "OpenAI API key", "critical", "high", @"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,200}\b"),
        Rule("stripe-key", "Stripe secret key", "critical", "high", @"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        Rule("jwt", "JSON Web Token", "medium", "medium", @"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        Rule("connection-password", "Connection-string password", "critical", "high", @"(?im)\b(?:password|pwd)\s*=\s*[""']?(?<secret>[^;\s,""']{4,})", "secret"),
        Rule("secret-assignment", "Secret assignment", "high", "medium", @"(?im)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b\s*[:=]\s*[""']?(?<secret>[A-Za-z0-9_./+=:@-]{8,})", "secret"),
        Rule("basic-auth-uri", "Credentialed service URI", "high", "high", @"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:(?<secret>[^\s/@]{4,})@[^\s]+", "secret"),
        Rule("payment-card", "Payment card number", "high", "medium", @"\b(?:\d[ -]*?){13,19}\b", Validator: IsValidPaymentCard),
        Rule("iban", "International bank account number", "medium", "medium", @"(?i)\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", Validator: IsValidIban),
    ];

    private static SiftRule Rule(
        string id,
        string name,
        string severity,
        string confidence,
        string pattern,
        string? secretGroup = null,
        Func<string, bool>? Validator = null)
        => new(
            id,
            name,
            severity,
            confidence,
            new Regex(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant, MatchTimeout),
            secretGroup,
            Validator);

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
