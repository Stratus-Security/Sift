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

        if (!TryGetValue(builder, out var password, "Password", "Pwd")
            || string.IsNullOrWhiteSpace(password))
        {
            return new ValidationResult { IsValid = false, Reason = "Connection string does not contain a password value" };
        }

        if (!TryGetValue(builder, out var host, "Server", "Data Source", "Host", "Addr", "Address", "Network Address")
            || string.IsNullOrWhiteSpace(host))
        {
            return new ValidationResult { IsValid = false, Reason = "Connection string does not contain a server or host value" };
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
}
