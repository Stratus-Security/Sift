using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class AzureSasValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.AzureSas;

    public override ValidationResult Validate(ValidationContext context)
    {
        var queryLikeFragment = ExtractQueryLikeFragment(context);
        var queryIndex = queryLikeFragment.IndexOf('?');
        var fragment = queryIndex >= 0 ? queryLikeFragment[(queryIndex + 1)..] : queryLikeFragment.TrimStart('&');
        var pairs = fragment.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in pairs)
        {
            var separator = pair.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            var key = pair[..separator];
            var value = pair[(separator + 1)..];
            parameters[key] = value;
        }

        if (!parameters.TryGetValue("sig", out var signature)
            || !string.Equals(signature, context.Candidate, StringComparison.Ordinal))
        {
            return new ValidationResult { IsValid = false, Reason = "SAS signature is not part of a coherent query string" };
        }

        if (!parameters.ContainsKey("sv"))
        {
            return new ValidationResult { IsValid = false, Reason = "SAS token is missing sv" };
        }

        var supportingParameterCount = 0;
        foreach (var key in new[] { "se", "sp", "sr", "srt", "si" })
        {
            if (parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                supportingParameterCount++;
            }
        }

        if (supportingParameterCount < 2)
        {
            return new ValidationResult { IsValid = false, Reason = "SAS token is missing expected access parameters" };
        }

        var contextResult = CheckCommonContextClues(context);
        if (contextResult != null)
        {
            return contextResult;
        }

        return new ValidationResult { IsValid = true, Confidence = 1.0 };
    }

    private static string ExtractQueryLikeFragment(ValidationContext context)
    {
        var text = context.FullFileContent ?? string.Empty;
        if (text.Length == 0)
        {
            return context.Candidate;
        }

        var start = Math.Clamp(context.Index, 0, text.Length);
        while (start > 0 && !char.IsWhiteSpace(text[start - 1]) && text[start - 1] is not '"' and not '\'' and not '`')
        {
            start--;
        }

        var end = Math.Clamp(context.Index + Math.Max(context.Candidate?.Length ?? 0, 0), 0, text.Length);
        while (end < text.Length && !char.IsWhiteSpace(text[end]) && text[end] is not '"' and not '\'' and not '`')
        {
            end++;
        }

        return text[start..end];
    }
}
