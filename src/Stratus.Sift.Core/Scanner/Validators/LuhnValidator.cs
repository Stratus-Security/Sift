using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Core.Validation;

namespace Stratus.Sift.Scanner.Validators;

public class LuhnValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.Luhn;

    public override ValidationResult Validate(ValidationContext context)
    {
        string candidate = context.Candidate;

        // 1. FAST FAIL: Basic cleanup check
        if (string.IsNullOrWhiteSpace(candidate)) 
            return new ValidationResult { IsValid = false, Reason = "Empty" };

        // 2. MATH CHECK (Optimized)
        // We perform the math first because it is CPU-cheap compared to string searching.
        if (!PassesLuhnMath(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Checksum Mismatch" };
        }

        // 3. CONTEXT CHECK (The "Smart" Layer)
        // If the math passes, we now check if it's likely a False Positive.
        var contextResult = CheckCommonContextClues(context);
        if (contextResult != null) return contextResult;

        // If we passed math and found no "test" indicators, it's a High Confidence finding.
        return new ValidationResult { IsValid = true, Confidence = 1.0 };
    }

    /// <summary>
    /// High-performance, zero-allocation Luhn implementation.
    /// Avoids LINQ to reduce Garbage Collection pressure during massive scans.
    /// </summary>
    private bool PassesLuhnMath(string candidate)
    {
        int sum = 0;
        bool doubleDigit = false;
        bool hasDigits = false;

        // Iterate backwards through the string manually
        for (int i = candidate.Length - 1; i >= 0; i--)
        {
            char c = candidate[i];
            
            // Skip non-digits (dashes/spaces) without creating new strings
            if (c < '0' || c > '9') continue;

            hasDigits = true;
            int digit = c - '0';

            if (doubleDigit)
            {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }

            sum += digit;
            doubleDigit = !doubleDigit;
        }

        return hasDigits && (sum % 10) == 0;
    }
}
