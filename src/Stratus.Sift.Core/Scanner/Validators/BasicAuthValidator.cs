using System.Text;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class BasicAuthValidator : BaseValidator
{
    private static readonly HashSet<string> ExampleCredentialIndicators = new(CommonTestIndicators, StringComparer.OrdinalIgnoreCase)
    {
        "example",
        "sample",
        "demo",
        "mock",
        "dummy",
        "placeholder"
    };

    public override string Name => ClassifierValidatorCatalog.BasicAuth;

    public override ValidationResult Validate(ValidationContext context)
    {
        var encodedValue = ExtractEncodedValue(context.Candidate);
        if (string.IsNullOrWhiteSpace(encodedValue))
        {
            return new ValidationResult { IsValid = false, Reason = "Missing Basic auth payload" };
        }

        var normalized = NormalizeBase64(encodedValue);
        if (!TryDecodeBase64(normalized, out var decoded))
        {
            return new ValidationResult { IsValid = false, Reason = "Malformed Basic auth payload" };
        }

        if (decoded.Any(char.IsControl))
        {
            return new ValidationResult { IsValid = false, Reason = "Decoded payload contains control characters" };
        }

        var separatorIndex = decoded.IndexOf(':');
        if (separatorIndex < 0)
        {
            return new ValidationResult { IsValid = false, Reason = "Decoded payload is not in username:password format" };
        }

        if (separatorIndex == 0 || separatorIndex == decoded.Length - 1)
        {
            return new ValidationResult
            {
                IsValid = true,
                Confidence = 0.4,
                Reason = "Basic auth contains an empty username or password"
            };
        }

        var contextResult = CheckCommonContextClues(context, ExampleCredentialIndicators);
        if (contextResult != null)
        {
            return contextResult;
        }

        return new ValidationResult { IsValid = true, Confidence = 1.0 };
    }

    private static string ExtractEncodedValue(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return string.Empty;
        }

        var markerIndex = candidate.IndexOf("Basic", StringComparison.OrdinalIgnoreCase);
        var payload = markerIndex >= 0
            ? candidate[(markerIndex + "Basic".Length)..]
            : candidate;

        return payload.Trim().Trim('"', '\'', '`');
    }

    private static string NormalizeBase64(string value)
    {
        var remainder = value.Length % 4;
        return remainder == 0 ? value : value.PadRight(value.Length + (4 - remainder), '=');
    }

    private static bool TryDecodeBase64(string value, out string decoded)
    {
        decoded = string.Empty;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(value));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
