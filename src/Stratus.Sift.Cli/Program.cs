using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.FileSystem;
using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli;

public class Program
{
    public static Task<int> Main(string[] args)
    {
        return RunAsync(args);
    }

    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        var rootCommand = BuildRootCommand();
        var result = rootCommand.Parse(args);
        try
        {
            return await result.InvokeAsync(new InvocationConfiguration(), cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliExitCodes.Cancelled;
        }
    }

    internal static RootCommand BuildRootCommand()
    {
        return CliCommandFactory.BuildRootCommand();
    }

    internal static IHost CreateHost()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);

        builder.Services.AddSingleton<CliCheckpointStore>();
        builder.Services.AddSingleton<StandardFileSystemEnumerator>();
        builder.Services.AddSingleton<FileScanner>();
        builder.Services.AddSingleton<IScanner>(sp => sp.GetRequiredService<FileScanner>());
        builder.Services.AddTransient<ContentExtractor>();
        builder.Services.AddSingleton<RemoteDriveScanner>();
        builder.Services.AddSingleton<ThrottleNotificationHub>();
        builder.Services.AddSingleton<SmbDiscoveryService>();
        builder.Services.AddSingleton<SmbKerberosService>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.LuhnValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.HerokuValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.BasicAuthValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.JwtValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.SqlConnectionStringValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.MongoConnectionStringValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.PostgresConnectionStringValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.AzureSasValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.TwilioValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.SlackTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.StripeSecretKeyValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.OpenAiApiKeyValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.GitHubPatValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.GitLabPatValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.NpmAccessTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.SendGridApiKeyValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.TelegramBotTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.MailchimpApiKeyValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.AzureDevOpsPatValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.AwsSessionTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.GitLabOperationalTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.PyPiApiTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.DockerAccessTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.DockerConfigAuthValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.VaultTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.TerraformTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.CredentialedServiceUriValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.BearerTokenValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.IbanValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.AustralianTfnValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.AustralianMedicareValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.ContextualIdentifierValidator>();
        builder.Services.AddSingleton<IValidator, Stratus.Sift.Scanner.Validators.EnvironmentSecretAssignmentValidator>();
        builder.Services.AddSingleton<ValidatorFactory>();

        builder.Services.AddHttpClient();

        builder.Services.AddTransient<IConnector, Stratus.Sift.Connectors.SharePoint.SharePointConnector>();
        builder.Services.AddTransient<IConnector, Stratus.Sift.Connectors.Slack.SlackConnector>();
        builder.Services.AddTransient<IConnector, Stratus.Sift.Connectors.Slack.SlackExportConnector>();
        builder.Services.AddTransient<IConnector, Stratus.Sift.Connectors.Atlassian.AtlassianConnector>();

        return builder.Build();
    }
}

internal static class CliExitCodes
{
    internal const int Success = 0;
    internal const int Failed = 2;
    internal const int Partial = 3;
    internal const int Cancelled = 130;
}
