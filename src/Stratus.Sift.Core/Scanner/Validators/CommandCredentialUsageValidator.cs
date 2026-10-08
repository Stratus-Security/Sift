using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public sealed class CommandCredentialUsageValidator : BaseValidator
{
    private static readonly HashSet<string> NonValueSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "age", "algorithm", "complexity", "enabled", "encoding", "env", "environment",
        "envvar", "expire", "expiry", "file", "filename", "filepath", "format",
        "generator", "hash", "hint", "length", "mask", "maxlength", "minlength",
        "mode", "path", "policy", "prompt", "required", "salt", "stdin",
        "strength", "type", "var", "variable"
    };

    private static readonly HashSet<string> NonSecretValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "false", "none", "null", "prompt", "stdin", "true", "undefined"
    };

    public override string Name => ClassifierValidatorCatalog.CommandCredentialUsage;

    public override ValidationResult Validate(ValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var candidate = context.Candidate.Trim();
        if (candidate.Length == 0)
        {
            return Invalid("Empty command credential match");
        }

        string value;
        if (candidate[0] is '-' or '/')
        {
            var optionEnd = candidate.IndexOfAny([' ', '\t', '=', ':'], 1);
            if (optionEnd < 0)
            {
                return Invalid("Password switch has no value");
            }

            var option = candidate[1..optionEnd].TrimStart('-');
            if (HasNonValueSuffix(option))
            {
                return Invalid("Password switch names a setting or a reference instead of a value");
            }

            value = candidate[(optionEnd + 1)..].Trim();
        }
        else
        {
            value = GetTrailingValue(candidate);
        }

        var isQuoted = value.Length >= 2 && (value[0] is '"' or '\'') && value[^1] == value[0];
        if (isQuoted)
        {
            value = value[1..^1];
        }

        if (value.Length == 0 || (!isQuoted && (value[0] is '-' or '/'))
            || NonSecretValues.Contains(value)
            || value.All(static character => character == '*')
            || IsVariableReference(value)
            || value.StartsWith('<') && value.EndsWith('>'))
        {
            return Invalid("Command has no credible inline credential value");
        }

        return new ValidationResult { IsValid = true, Confidence = 0.95 };
    }

    private static string GetTrailingValue(string candidate)
    {
        var last = candidate.Length - 1;
        if (candidate[last] is '"' or '\'')
        {
            var quoteStart = candidate.LastIndexOf(candidate[last], last - 1);
            if (quoteStart >= 0)
            {
                return candidate[quoteStart..];
            }
        }

        var separator = candidate.LastIndexOfAny([' ', '\t']);
        var token = candidate[(separator + 1)..];
        var assignment = token.LastIndexOfAny([':', '=']);
        return assignment >= 0 && token.StartsWith("/pass", StringComparison.OrdinalIgnoreCase)
            ? token[(assignment + 1)..]
            : token;
    }

    private static bool HasNonValueSuffix(string option)
    {
        var markerIndex = option.IndexOf("password", StringComparison.OrdinalIgnoreCase);
        var markerLength = "password".Length;
        if (markerIndex < 0)
        {
            markerIndex = option.IndexOf("passwd", StringComparison.OrdinalIgnoreCase);
            markerLength = "passwd".Length;
        }
        if (markerIndex < 0)
        {
            return false;
        }

        var suffix = new string(option[(markerIndex + markerLength)..]
            .Where(static character => character is not ('-' or '_'))
            .ToArray());
        return NonValueSuffixes.Contains(suffix);
    }

    private static bool IsVariableReference(string value)
    {
        if (value.Length > 2 && (value[0], value[^1]) is ('%', '%') or ('!', '!'))
        {
            return value[1..^1].All(static character => char.IsAsciiLetterOrDigit(character) || character == '_');
        }

        return value.Length > 2 && value[0] == '$' && value[1] == '{' && value.EndsWith('}')
            || value.StartsWith("$(", StringComparison.Ordinal) && value.EndsWith(')');
    }

    private static ValidationResult Invalid(string reason) => new()
    {
        IsValid = false,
        Reason = reason
    };
}
