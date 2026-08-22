using System;
using System.Collections.Generic;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class HerokuValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.Heroku;

    // Common fake UUIDs developers paste into config files
    private static readonly HashSet<string> _knownFakes = new(StringComparer.OrdinalIgnoreCase)
    {
        "00000000-0000-0000-0000-000000000000", // Nil UUID
        "12345678-1234-1234-1234-123456789012", // Sequence
        "12345678-1234-1234-1234-123456789abc", // Sequence Hex
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", // Repeated
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    };

    public override ValidationResult Validate(ValidationContext context)
    {
        string candidate = context.Candidate;

        // 1. SANITY CHECK: Is it actually a UUID?
        // The Regex is pretty strict, but Guid.TryParse confirms it's valid hex.
        if (!Guid.TryParse(candidate, out Guid parsedGuid))
        {
             return new ValidationResult { IsValid = false, Reason = "Malformed UUID" };
        }

        // 2. BLOCKLIST CHECK: Is it a known placeholder?
        if (_knownFakes.Contains(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Known Placeholder UUID" };
        }

        // 3. CONTEXT CHECK: Is it in a test file?
        var contextResult = CheckCommonContextClues(context);
        if (contextResult != null) return contextResult;

        return new ValidationResult { IsValid = true, Confidence = 1.0 };
    }
}
