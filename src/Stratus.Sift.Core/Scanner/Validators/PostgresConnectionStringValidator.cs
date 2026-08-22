using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Validators;

public class PostgresConnectionStringValidator : BaseValidator
{
    public override string Name => ClassifierValidatorCatalog.PostgresConnectionString;

    public override ValidationResult Validate(ValidationContext context)
    {
        var candidate = ExtractDelimitedContextToken(context);
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
        {
            return new ValidationResult { IsValid = false, Reason = "Malformed PostgreSQL URI" };
        }

        if (!uri.Scheme.Equals("postgres", StringComparison.OrdinalIgnoreCase)
            && !uri.Scheme.Equals("postgresql", StringComparison.OrdinalIgnoreCase))
        {
            return new ValidationResult { IsValid = false, Reason = "Candidate is not a PostgreSQL URI" };
        }

        if (string.IsNullOrWhiteSpace(uri.UserInfo) || !uri.UserInfo.Contains(':'))
        {
            return new ValidationResult { IsValid = false, Reason = "PostgreSQL URI is missing user or password information" };
        }

        if (string.IsNullOrWhiteSpace(uri.Host))
        {
            return new ValidationResult { IsValid = false, Reason = "PostgreSQL URI is missing a host" };
        }

        var contextResult = CheckCommonContextClues(context);
        if (contextResult != null)
        {
            return contextResult;
        }

        return new ValidationResult { IsValid = true, Confidence = 1.0 };
    }
}
