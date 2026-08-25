namespace Stratus.Sift.Core.Validation;

public static class ClassifierValidatorCatalog
{
    public const string Luhn = "Luhn";
    public const string Heroku = "Heroku";
    public const string BasicAuth = "BasicAuth";
    public const string Jwt = "Jwt";
    public const string SqlConnectionString = "SqlConnectionString";
    public const string MongoConnectionString = "MongoConnectionString";
    public const string PostgresConnectionString = "PostgresConnectionString";
    public const string AzureSas = "AzureSas";
    public const string Twilio = "Twilio";
    public const string SlackToken = "SlackToken";
    public const string StripeSecretKey = "StripeSecretKey";
    public const string OpenAiApiKey = "OpenAiApiKey";
    public const string GitHubPat = "GitHubPat";
    public const string GitLabPat = "GitLabPat";
    public const string NpmAccessToken = "NpmAccessToken";
    public const string SendGridApiKey = "SendGridApiKey";
    public const string TelegramBotToken = "TelegramBotToken";
    public const string MailchimpApiKey = "MailchimpApiKey";
    public const string AzureDevOpsPat = "AzureDevOpsPat";
    public const string AwsSessionToken = "AwsSessionToken";
    public const string GitLabOperationalToken = "GitLabOperationalToken";
    public const string PyPiApiToken = "PyPiApiToken";
    public const string DockerAccessToken = "DockerAccessToken";
    public const string DockerConfigAuth = "DockerConfigAuth";
    public const string VaultToken = "VaultToken";
    public const string TerraformToken = "TerraformToken";
    public const string CredentialedServiceUri = "CredentialedServiceUri";
    public const string BearerToken = "BearerToken";
    public const string Iban = "Iban";
    public const string AustralianTfn = "AustralianTfn";
    public const string AustralianMedicare = "AustralianMedicare";
    public const string ContextualIdentifier = "ContextualIdentifier";
    public const string EnvironmentSecretAssignment = "EnvironmentSecretAssignment";
    public const string PowerShellCredentialUsage = "PowerShellCredentialUsage";

    public static IReadOnlyList<string> All { get; } =
    [
        Luhn,
        Heroku,
        BasicAuth,
        Jwt,
        SqlConnectionString,
        MongoConnectionString,
        PostgresConnectionString,
        AzureSas,
        Twilio,
        SlackToken,
        StripeSecretKey,
        OpenAiApiKey,
        GitHubPat,
        GitLabPat,
        NpmAccessToken,
        SendGridApiKey,
        TelegramBotToken,
        MailchimpApiKey,
        AzureDevOpsPat,
        AwsSessionToken,
        GitLabOperationalToken,
        PyPiApiToken,
        DockerAccessToken,
        DockerConfigAuth,
        VaultToken,
        TerraformToken,
        CredentialedServiceUri,
        BearerToken,
        Iban,
        AustralianTfn,
        AustralianMedicare,
        ContextualIdentifier,
        EnvironmentSecretAssignment,
        PowerShellCredentialUsage
    ];

    public static bool IsKnown(string? validatorName)
    {
        if (string.IsNullOrWhiteSpace(validatorName))
        {
            return false;
        }

        return All.Contains(validatorName.Trim(), StringComparer.OrdinalIgnoreCase);
    }
}
