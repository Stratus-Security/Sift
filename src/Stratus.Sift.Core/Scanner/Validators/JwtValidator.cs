using System.Text;
using System.Text.Json;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class JwtValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.Jwt;

    public override ValidationResult Validate(ValidationContext context)
    {
        if (string.IsNullOrWhiteSpace(context.Candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Empty JWT candidate" };
        }

        var segments = context.Candidate.Split('.');
        if (segments.Length != 3)
        {
            return new ValidationResult { IsValid = false, Reason = "JWT must have three segments" };
        }

        if (!TryDecodeBase64Url(segments[0], out var headerJson)
            || !TryDecodeBase64Url(segments[1], out var payloadJson))
        {
            return new ValidationResult { IsValid = false, Reason = "JWT segments are not valid base64url" };
        }

        if (!TryParseObject(headerJson, out var header))
        {
            return new ValidationResult { IsValid = false, Reason = "JWT header is not a valid JSON object" };
        }

        using (header)
        {
            if (!TryParseObject(payloadJson, out var payload))
            {
                return new ValidationResult { IsValid = false, Reason = "JWT payload is not a valid JSON object" };
            }

            using (payload)
            {
                if (!header.RootElement.TryGetProperty("alg", out var algorithm)
                    || algorithm.ValueKind != JsonValueKind.String
                    || string.IsNullOrWhiteSpace(algorithm.GetString()))
                {
                    return new ValidationResult { IsValid = false, Reason = "JWT header does not declare an algorithm" };
                }

                var algorithmName = algorithm.GetString();
                var hasSignature = segments[2].Length > 0;
                if (string.Equals(algorithmName, "none", StringComparison.OrdinalIgnoreCase) == hasSignature)
                {
                    return new ValidationResult { IsValid = false, Reason = "JWT signature does not match its declared algorithm" };
                }
            }
        }

        var contextResult = CheckCommonContextClues(context);
        if (contextResult != null)
        {
            return contextResult;
        }

        return new ValidationResult { IsValid = true, Confidence = 1.0 };
    }

    private static bool TryDecodeBase64Url(string value, out string decoded)
    {
        decoded = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Replace('-', '+').Replace('_', '/');
        var remainder = normalized.Length % 4;
        if (remainder != 0)
        {
            normalized = normalized.PadRight(normalized.Length + (4 - remainder), '=');
        }

        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool TryParseObject(string json, out JsonDocument document)
    {
        document = null!;
        try
        {
            document = JsonDocument.Parse(json);
            return document.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
