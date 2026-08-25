using System.Text.RegularExpressions;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public sealed partial class PowerShellCredentialUsageValidator : BaseValidator
{
    private enum AssignmentKind
    {
        Literal,
        Dynamic,
        Ambiguous
    }

    public override string Name => ClassifierValidatorCatalog.PowerShellCredentialUsage;

    public override ValidationResult Validate(ValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var candidate = context.Candidate ?? string.Empty;
        var (statement, statementStart) = GetCurrentStatement(context);

        if (IsPlaintextMaterialization(candidate))
        {
            return Valid(0.95, "PowerShell credential material is converted back to plaintext");
        }

        if (candidate.Contains("-AsPlainText", StringComparison.OrdinalIgnoreCase))
        {
            if (statement.Contains("ConvertFrom-SecureString", StringComparison.OrdinalIgnoreCase))
            {
                return Valid(1.0, "SecureString is explicitly converted to plaintext");
            }

            if (!statement.Contains("ConvertTo-SecureString", StringComparison.OrdinalIgnoreCase))
            {
                return Valid(0.6, "Ambiguous -AsPlainText usage retained for recall");
            }

            return ValidateConvertToSecureString(context, statement, statementStart);
        }

        if (candidate.Contains("-SecureString", StringComparison.OrdinalIgnoreCase))
        {
            if (statement.Contains("ConvertTo-SecureString", StringComparison.OrdinalIgnoreCase)
                && statement.Contains("-AsPlainText", StringComparison.OrdinalIgnoreCase))
            {
                return ValidateConvertToSecureString(context, statement, statementStart);
            }

            if (statement.Contains("ConvertFrom-SecureString", StringComparison.OrdinalIgnoreCase)
                && !statement.Contains("-AsPlainText", StringComparison.OrdinalIgnoreCase)
                && !statement.Contains("ConvertTo-SecureString", StringComparison.OrdinalIgnoreCase)
                && !ContainsQuotedExpression(statement))
            {
                return Invalid("ConvertFrom-SecureString is serializing an existing SecureString");
            }

            return Valid(0.55, "Ambiguous -SecureString usage retained for recall");
        }

        return Valid(0.7, "PowerShell credential-handling usage retained for recall");
    }

    private static ValidationResult ValidateConvertToSecureString(
        ValidationContext context,
        string statement,
        int statementStart)
    {
        if (ContainsQuotedExpression(statement))
        {
            return Valid(1.0, "ConvertTo-SecureString contains an inline string expression");
        }

        var commandIndex = statement.IndexOf("ConvertTo-SecureString", StringComparison.OrdinalIgnoreCase);
        var arguments = commandIndex >= 0
            ? statement[(commandIndex + "ConvertTo-SecureString".Length)..]
            : statement;
        var variables = VariableRegex()
            .Matches(arguments)
            .Cast<Match>()
            .Select(match => NormalizeVariableName(match.Groups["name"].Value))
            .Where(static name => name.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (variables.Length == 0)
        {
            return Valid(0.85, "ConvertTo-SecureString uses a non-variable plaintext expression");
        }

        var sawDynamicAssignment = false;
        foreach (var variable in variables)
        {
            var assignment = FindLastAssignment(context.FullFileContent, statementStart, variable);
            if (assignment is null)
            {
                return Valid(0.6, "Plaintext source could not be proven dynamic; retained for recall");
            }

            switch (ClassifyAssignment(assignment))
            {
                case AssignmentKind.Literal:
                    return Valid(1.0, "Plaintext variable is assigned a literal value");
                case AssignmentKind.Ambiguous:
                    return Valid(0.7, "Plaintext variable assignment is ambiguous; retained for recall");
                case AssignmentKind.Dynamic:
                    sawDynamicAssignment = true;
                    break;
            }
        }

        return sawDynamicAssignment
            ? Invalid("Plaintext variables are populated by runtime expressions")
            : Valid(0.6, "Credential usage retained for recall");
    }

    private static bool IsPlaintextMaterialization(string candidate)
    {
        return candidate.Contains("NetworkCredential", StringComparison.OrdinalIgnoreCase)
            || candidate.Contains("GetNetworkCredential", StringComparison.OrdinalIgnoreCase)
            || candidate.Contains("SecureStringToBSTR", StringComparison.OrdinalIgnoreCase);
    }

    private static (string Statement, int Start) GetCurrentStatement(ValidationContext context)
    {
        var text = context.FullFileContent ?? string.Empty;
        if (text.Length == 0)
        {
            return (context.Candidate, 0);
        }

        var index = Math.Clamp(context.Index, 0, text.Length);
        var start = index > 0 ? text.LastIndexOfAny(['\r', '\n'], index - 1) + 1 : 0;
        var end = text.IndexOfAny(['\r', '\n'], index);
        if (end < 0)
        {
            end = text.Length;
        }

        return (text[start..end], start);
    }

    private static string? FindLastAssignment(string content, int beforeIndex, string variableName)
    {
        string? value = null;
        foreach (Match match in AssignmentRegex().Matches(content))
        {
            if (match.Index >= beforeIndex)
            {
                break;
            }

            if (NormalizeVariableName(match.Groups["name"].Value)
                .Equals(variableName, StringComparison.OrdinalIgnoreCase))
            {
                value = match.Groups["value"].Value.Trim();
            }
        }

        return value;
    }

    private static AssignmentKind ClassifyAssignment(string expression)
    {
        var value = TrimWrappingParentheses(expression.Trim());
        if (IsEntireQuotedExpression(value))
        {
            return value[0] == '"' && PureInterpolationRegex().IsMatch(value[1..^1].Trim())
                ? AssignmentKind.Dynamic
                : AssignmentKind.Literal;
        }

        if (PureInterpolationRegex().IsMatch(value)
            || RuntimeSourceExpressionRegex().IsMatch(value))
        {
            return AssignmentKind.Dynamic;
        }

        if (!value.Any(char.IsWhiteSpace)
            && value.IndexOfAny(['[', ']', '(', ')']) < 0)
        {
            return AssignmentKind.Literal;
        }

        return AssignmentKind.Ambiguous;
    }

    private static string TrimWrappingParentheses(string value)
    {
        while (value.Length >= 2 && value[0] == '(' && value[^1] == ')')
        {
            value = value[1..^1].Trim();
        }

        return value;
    }

    private static bool IsEntireQuotedExpression(string value)
    {
        return value.Length >= 2
            && value[0] is '\'' or '"'
            && value[^1] == value[0];
    }

    private static bool ContainsQuotedExpression(string statement)
    {
        for (var index = 0; index < statement.Length; index++)
        {
            var quote = statement[index];
            if (quote is not ('\'' or '"'))
            {
                continue;
            }

            for (var end = index + 1; end < statement.Length; end++)
            {
                if (statement[end] == '`')
                {
                    end++;
                    continue;
                }

                if (statement[end] != quote)
                {
                    continue;
                }

                if (quote == '\'' && end + 1 < statement.Length && statement[end + 1] == '\'')
                {
                    end++;
                    continue;
                }

                return end > index + 1;
            }
        }

        return false;
    }

    private static string NormalizeVariableName(string value)
    {
        var separator = value.IndexOf(':');
        return separator >= 0 ? value[(separator + 1)..] : value;
    }

    private static ValidationResult Valid(double confidence, string reason) => new()
    {
        IsValid = true,
        Confidence = confidence,
        Reason = reason
    };

    private static ValidationResult Invalid(string reason) => new()
    {
        IsValid = false,
        Reason = reason
    };

    [GeneratedRegex(
        @"\$(?<name>(?:(?:global|script|local|private):)?[A-Za-z_][A-Za-z0-9_]*)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex VariableRegex();

    [GeneratedRegex(
        @"^[ \t]*\$(?<name>(?:(?:global|script|local|private):)?[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?<value>[^\r\n;]+)",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex AssignmentRegex();

    [GeneratedRegex(
        @"^\$(?:\{[^}\r\n]+\}|\([^\r\n]*\)|(?:(?:global|script|local|private|env):)?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PureInterpolationRegex();

    [GeneratedRegex(
        @"^(?:Read-Host|Get-(?:Content|Secret|Credential|Random|ItemProperty)|Invoke-(?:RestMethod|WebRequest)|\[(?:(?:System\.)?Text\.RegularExpressions\.)?Regex\]::Match)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RuntimeSourceExpressionRegex();
}
