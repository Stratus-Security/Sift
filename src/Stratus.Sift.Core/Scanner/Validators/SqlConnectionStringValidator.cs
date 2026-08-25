using System.Data.Common;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class SqlConnectionStringValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.SqlConnectionString;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = context.Candidate?.Trim().Trim('"', '\'', '`');
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return new ValidationResult { IsValid = false, Reason = "Empty connection string candidate" };
        }

        DbConnectionStringBuilder builder = new();
        try
        {
            builder.ConnectionString = candidate;
        }
        catch (ArgumentException)
        {
            return new ValidationResult { IsValid = false, Reason = "Malformed connection string" };
        }

        var hasPassword = TryGetValue(builder, out var password, "Password", "Pwd");
        if (!hasPassword && !ContainsEmptyValue(candidate, "Password", "Pwd"))
        {
            return new ValidationResult { IsValid = false, Reason = "Connection string does not contain a password value" };
        }

        password ??= string.Empty;

        if (!TryGetValue(builder, out var host, "Server", "Data Source", "Host", "Addr", "Address", "Network Address")
            || string.IsNullOrWhiteSpace(host))
        {
            return new ValidationResult { IsValid = false, Reason = "Connection string does not contain a server or host value" };
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            return new ValidationResult
            {
                IsValid = true,
                Confidence = 0.25,
                Reason = "Connection string contains an empty password"
            };
        }

        if (password.Length < 4 || LooksLikeRepeatedPlaceholder(password))
        {
            return new ValidationResult
            {
                IsValid = true,
                Confidence = 0.25,
                Reason = "Connection string contains a weak-looking password"
            };
        }

        var contextResult = CheckCommonContextClues(context);
        if (contextResult != null)
        {
            return contextResult;
        }

        return new ValidationResult { IsValid = true, Confidence = 1.0 };
    }

    private static bool TryGetValue(DbConnectionStringBuilder builder, out string? value, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (builder.TryGetValue(key, out var rawValue) && rawValue is not null)
            {
                value = Convert.ToString(rawValue);
                return true;
            }
        }

        value = null;
        return false;
    }

    private static bool ContainsEmptyValue(string connectionString, params string[] keys)
    {
        foreach (var segment in connectionString.Split(';', StringSplitOptions.TrimEntries))
        {
            var separator = segment.IndexOf('=');
            if (separator <= 0 || !string.IsNullOrWhiteSpace(segment[(separator + 1)..]))
            {
                continue;
            }

            var key = segment[..separator].Trim();
            if (keys.Any(candidate => key.Equals(candidate, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }
}
