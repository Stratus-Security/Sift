using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public abstract class StructuredTokenValidatorBase : BaseValidator
{
    private static readonly HashSet<string> TokenExampleIndicators = new(CommonTestIndicators, StringComparer.OrdinalIgnoreCase)
    {
        "sample",
        "demo",
        "fixture",
        "readme",
        "tutorial",
        "quickstart",
        "guide"
    };

    private static readonly string[] PlaceholderTerms =
    [
        "example",
        "sample",
        "placeholder",
        "dummy",
        "changeme",
        "replace",
        "notreal",
        "yourtoken",
        "yourkey",
        "tokenhere",
        "keyhere",
        "insert"
    ];

    protected ValidationResult ValidWithContextReview(ValidationContext context)
    {
        var contextResult = CheckCommonContextClues(context, TokenExampleIndicators);
        return contextResult ?? new ValidationResult { IsValid = true, Confidence = 1.0 };
    }

    protected static bool IsAlphaNumericDashOrUnderscore(string value)
    {
        return !string.IsNullOrWhiteSpace(value)
            && value.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
    }

    protected static bool IsAsciiAlphaNumeric(string value)
    {
        return !string.IsNullOrWhiteSpace(value)
            && value.All(char.IsAsciiLetterOrDigit);
    }

    protected static bool IsAsciiHex(string value)
    {
        return !string.IsNullOrWhiteSpace(value)
            && value.All(static c => char.IsAsciiHexDigit(c));
    }

    protected static bool LooksLikePlaceholderToken(string value, int minimumLength = 8)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        if (LooksLikeRepeatedPlaceholder(value, minimumLength))
        {
            return true;
        }

        var normalized = NormalizeToken(value);
        if (normalized.Length < minimumLength)
        {
            return false;
        }

        if (PlaceholderTerms.Any(term => normalized.Contains(term, StringComparison.Ordinal)))
        {
            return true;
        }

        if (HasVeryLowCharacterDiversity(normalized))
        {
            return true;
        }

        if (HasRepeatedHalf(normalized))
        {
            return true;
        }

        return false;
    }

    private static string NormalizeToken(string value)
    {
        Span<char> buffer = stackalloc char[Math.Min(value.Length, 256)];
        var count = 0;

        foreach (var character in value)
        {
            if (!char.IsLetterOrDigit(character))
            {
                continue;
            }

            if (count < buffer.Length)
            {
                buffer[count] = char.ToLowerInvariant(character);
            }

            count++;
        }

        if (count == 0)
        {
            return string.Empty;
        }

        if (count <= buffer.Length)
        {
            return new string(buffer[..count]);
        }

        return new string(value.Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray());
    }

    private static bool HasVeryLowCharacterDiversity(string value)
    {
        Span<bool> seenDigits = stackalloc bool[10];
        Span<bool> seenLetters = stackalloc bool[26];
        var distinctCount = 0;

        foreach (var character in value)
        {
            if (character is >= '0' and <= '9')
            {
                var index = character - '0';
                if (!seenDigits[index])
                {
                    seenDigits[index] = true;
                    distinctCount++;
                }
            }
            else if (character is >= 'a' and <= 'z')
            {
                var index = character - 'a';
                if (!seenLetters[index])
                {
                    seenLetters[index] = true;
                    distinctCount++;
                }
            }

            if (distinctCount > 2)
            {
                return false;
            }
        }

        return distinctCount <= 2;
    }

    private static bool HasRepeatedHalf(string value)
    {
        return value.Length >= 16
            && value.Length % 2 == 0
            && string.Equals(
                value[..(value.Length / 2)],
                value[(value.Length / 2)..],
                StringComparison.Ordinal);
    }
}
