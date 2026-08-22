using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public sealed class IbanValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.Iban;

    public override ValidationResult Validate(ValidationContext context)
    {
        var iban = new string(context.Candidate.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        if (iban.Length is < 15 or > 34 || !char.IsAsciiLetterUpper(iban[0]) || !char.IsAsciiLetterUpper(iban[1])
            || !char.IsAsciiDigit(iban[2]) || !char.IsAsciiDigit(iban[3]))
        {
            return Invalid("IBAN structure is invalid");
        }

        var remainder = 0;
        foreach (var character in iban[4..].Concat(iban[..4]))
        {
            if (char.IsAsciiDigit(character))
            {
                remainder = ((remainder * 10) + (character - '0')) % 97;
            }
            else if (char.IsAsciiLetterUpper(character))
            {
                var value = character - 'A' + 10;
                remainder = ((remainder * 100) + value) % 97;
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
        var digits = new string(context.Candidate.Where(char.IsAsciiDigit).ToArray());
        if (digits.Length != 9)
        {
            return new ValidationResult { IsValid = false, Reason = "TFN must contain nine digits" };
        }

        var sum = digits.Select((digit, index) => (digit - '0') * Weights[index]).Sum();
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
        var digits = new string(context.Candidate.Where(char.IsAsciiDigit).ToArray());
        if (digits.Length is < 10 or > 11 || digits[0] is < '2' or > '6')
        {
            return new ValidationResult { IsValid = false, Reason = "Medicare number structure is invalid" };
        }

        var checksum = digits.Take(8).Select((digit, index) => (digit - '0') * Weights[index]).Sum() % 10;
        return checksum == digits[8] - '0'
            ? CheckCommonContextClues(context) ?? new ValidationResult { IsValid = true, Confidence = 1.0 }
            : new ValidationResult { IsValid = false, Reason = "Medicare checksum failed" };
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
