using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public abstract class BaseValidator : IValidator
{
    public abstract string Name { get; }
    public abstract ValidationResult Validate(ValidationContext context);

    protected static readonly HashSet<string> CommonTestIndicators = new(StringComparer.OrdinalIgnoreCase)
    {
        "mock", "dummy", "test", "example", "fake", "placeholder", "template", "stub"
    };

    protected ValidationResult? CheckCommonContextClues(ValidationContext context, HashSet<string>? customIndicators = null)
    {
        // 1. File Path Check
        // Consolidating check logic from both validators
        if (context.FilePath.Contains("test", StringComparison.OrdinalIgnoreCase) || 
            context.FilePath.EndsWith(".spec.ts", StringComparison.OrdinalIgnoreCase) || 
            context.FilePath.EndsWith(".Test.cs", StringComparison.OrdinalIgnoreCase))
        {
             return new ValidationResult { IsValid = true, Confidence = 0.1, Reason = "Found in Test File" };
        }

        // 2. Surrounding Text Check
        string candidate = context.Candidate;
        int start = Math.Max(0, context.Index - 50);
        int length = Math.Min(context.FullFileContent.Length - start, 100 + candidate.Length);
        string surroundingText = context.FullFileContent.Substring(start, length);

        var indicators = customIndicators ?? CommonTestIndicators;
        
        foreach (var indicator in indicators)
        {
            if (surroundingText.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                 return new ValidationResult { IsValid = true, Confidence = 0.2, Reason = $"Context contains '{indicator}'" };
            }
        }

        return null;
    }

    protected static string ExtractDelimitedContextToken(ValidationContext context, int maxLength = 512)
    {
        ArgumentNullException.ThrowIfNull(context);

        var text = context.FullFileContent ?? string.Empty;
        if (text.Length == 0)
        {
            return context.Candidate;
        }

        var start = Math.Clamp(context.Index, 0, text.Length);
        while (start > 0 && !IsTokenBoundary(text[start - 1]))
        {
            start--;
        }

        var end = Math.Clamp(context.Index + Math.Max(context.Candidate?.Length ?? 0, 0), 0, text.Length);
        while (end < text.Length && !IsTokenBoundary(text[end]) && (end - start) < maxLength)
        {
            end++;
        }

        return text[start..end];
    }

    protected static bool LooksLikeRepeatedPlaceholder(string value, int minimumLength = 8)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < minimumLength)
        {
            return false;
        }

        return value.All(c => c == value[0]);
    }

    private static bool IsTokenBoundary(char value)
    {
        return char.IsWhiteSpace(value)
            || value is '"' or '\'' or '`' or ',' or ';' or '<' or '>' or '(' or ')' or '[' or ']' or '{' or '}' or '=';
    }
}
