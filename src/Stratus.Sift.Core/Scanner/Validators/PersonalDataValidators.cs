using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public sealed class IbanValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.Iban;

    public override ValidationResult Validate(ValidationContext context)
    {
        Span<char> iban = stackalloc char[34];
        var length = 0;
        foreach (var character in context.Candidate)
        {
            if (!char.IsLetterOrDigit(character)) continue;
            if (length == iban.Length) return Invalid("IBAN structure is invalid");
            iban[length++] = char.ToUpperInvariant(character);
        }

        var value = iban[..length];
        if (value.Length is < 15 or > 34 || !char.IsAsciiLetterUpper(value[0]) || !char.IsAsciiLetterUpper(value[1])
            || !char.IsAsciiDigit(value[2]) || !char.IsAsciiDigit(value[3]))
        {
            return Invalid("IBAN structure is invalid");
        }

        var remainder = 0;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[(index + 4) % value.Length];
            if (char.IsAsciiDigit(character))
            {
                remainder = ((remainder * 10) + (character - '0')) % 97;
            }
            else if (char.IsAsciiLetterUpper(character))
            {
                var numericValue = character - 'A' + 10;
                remainder = ((remainder * 100) + numericValue) % 97;
            }
            else
            {
                return Invalid("IBAN contains invalid characters");
            }
        }

        return remainder == 1
            ? CheckCommonContextClues(context) ?? new ValidationResult { IsValid = true, Confidence = 1.0 }
            : Invalid("IBAN checksum failed");
    }

    private static ValidationResult Invalid(string reason) => new() { IsValid = false, Reason = reason };
}

public sealed class AustralianTfnValidator : BaseValidator
{
    private static readonly int[] Weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];

    public override string Name => ClassifierValidatorCatalog.AustralianTfn;

    public override ValidationResult Validate(ValidationContext context)
    {
        Span<char> digits = stackalloc char[9];
        var length = PersonalDataValidation.CopyAsciiDigits(context.Candidate, digits);
        if (length != digits.Length)
        {
            return new ValidationResult { IsValid = false, Reason = "TFN must contain nine digits" };
        }

        var sum = 0;
        for (var index = 0; index < digits.Length; index++)
        {
            sum += (digits[index] - '0') * Weights[index];
        }
        return sum % 11 == 0
            ? CheckCommonContextClues(context) ?? new ValidationResult { IsValid = true, Confidence = 1.0 }
            : new ValidationResult { IsValid = false, Reason = "TFN checksum failed" };
    }
}

public sealed class AustralianMedicareValidator : BaseValidator
{
    private static readonly int[] Weights = [1, 3, 7, 9, 1, 3, 7, 9];

    public override string Name => ClassifierValidatorCatalog.AustralianMedicare;

    public override ValidationResult Validate(ValidationContext context)
    {
        Span<char> digits = stackalloc char[11];
        var length = PersonalDataValidation.CopyAsciiDigits(context.Candidate, digits);
        if (length is < 10 or > 11 || digits[0] is < '2' or > '6')
        {
            return new ValidationResult { IsValid = false, Reason = "Medicare number structure is invalid" };
        }

        var checksumTotal = 0;
        for (var index = 0; index < 8; index++)
        {
            checksumTotal += (digits[index] - '0') * Weights[index];
        }
        var checksum = checksumTotal % 10;
        return checksum == digits[8] - '0'
            ? CheckCommonContextClues(context) ?? new ValidationResult { IsValid = true, Confidence = 1.0 }
            : new ValidationResult { IsValid = false, Reason = "Medicare checksum failed" };
    }
}

file static class PersonalDataValidation
{
    public static int CopyAsciiDigits(string candidate, Span<char> destination)
    {
        var length = 0;
        foreach (var character in candidate)
        {
            if (!char.IsAsciiDigit(character)) continue;
            if (length == destination.Length) return destination.Length + 1;
            destination[length++] = character;
        }

        return length;
    }
}

public sealed class ContextualIdentifierValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.ContextualIdentifier;

    public override ValidationResult Validate(ValidationContext context)
    {
        var separator = context.Candidate.IndexOfAny(['=', ':']);
        var value = (separator >= 0 ? context.Candidate[(separator + 1)..] : context.Candidate)
            .Trim().Trim('"', '\'', '`');
        if (value.Length is < 5 or > 32 || value.All(char.IsLetter) || value.All(char.IsDigit) && value.Distinct().Count() < 3)
        {
            return new ValidationResult { IsValid = false, Reason = "Contextual identifier is not sufficiently distinctive" };
        }

        return CheckCommonContextClues(context) ?? new ValidationResult { IsValid = true, Confidence = 0.8 };
    }
}
