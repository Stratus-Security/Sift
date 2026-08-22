using System.CommandLine;
using System.CommandLine.Parsing;
using Stratus.Sift.Core;

namespace Stratus.Sift.Cli;

internal static class CliCommandFactory
{
    internal static RootCommand BuildRootCommand()
    {
        var rootCommand = new RootCommand("Stratus Sift CLI - Scan local folders, SMB targets, Microsoft 365, Slack, Slack exports, and Atlassian");
        rootCommand.Add(CreateLocalCommand());
        rootCommand.Add(CreateDomainCommand());
        rootCommand.Add(CreateNetworkCommand());
        rootCommand.Add(CreateSharePointCommand());
        rootCommand.Add(CreateSlackCommand());
        rootCommand.Add(CreateSlackExportCommand());
        rootCommand.Add(CreateJiraCommand());
        rootCommand.Add(CreateAnalyzeCommand());
        return rootCommand;
    }

    private static Command CreateAnalyzeCommand()
    {
        var inputOption = new Option<string>("--input")
        {
            Description = "Path to a saved CLI JSON result file produced with --output-format json."
        };
        inputOption.Aliases.Add("-i");
        inputOption.Required = true;

        var outputFormatOption = new Option<string>("--output-format")
        {
            Description = "Output file format when --output is supplied. Supported values: cli, json."
        };
        outputFormatOption.Aliases.Add("-f");
        outputFormatOption.Validators.Add(result =>
        {
            var value = result.GetValue(outputFormatOption);
            if (!string.IsNullOrWhiteSpace(value) && !IsValidOutputFormat(value))
            {
                result.AddError("The --output-format value must be either 'cli' or 'json'.");
            }
        });

        var outputOption = new Option<string>("--output")
        {
            Description = "Write replayed or re-analyzed output to a file."
        };
        outputOption.Aliases.Add("-o");

        var snafflerModeOption = new Option<bool>("--snaffler-mode")
        {
            Description = "Render console and CLI text output in Snaffler's logging style."
        };
        snafflerModeOption.Aliases.Add("--snaffler");

        var llmValidateOption = new Option<bool>("--llm-validate")
        {
            Description = "Re-analyze saved findings with a local Ollama model."
        };

        var sensitiveOnlyOption = new Option<bool>("--sensitive-only")
        {
            Description = "Only keep findings marked sensitive. With --llm-validate, the filter uses the fresh LLM verdict."
        };

        var ollamaUrlOption = new Option<string>("--ollama-url")
        {
            Description = "Base URL for the Ollama server.",
            DefaultValueFactory = _ => "http://localhost:11434"
        };

        var ollamaModelOption = new Option<string>("--ollama-model")
        {
            Description = "Ollama model to use for classifier validation. If omitted with --llm-validate, an interactive prompt is used when possible."
        };

        var llmTimeoutSecondsOption = new Option<int>("--llm-timeout-seconds")
        {
            Description = "Timeout for each Ollama validation request in seconds.",
            DefaultValueFactory = _ => 20
        };
        llmTimeoutSecondsOption.Validators.Add(result =>
        {
            if (result.GetValue(llmTimeoutSecondsOption) <= 0)
            {
                result.AddError("The --llm-timeout-seconds value must be greater than zero.");
            }
        });

        var command = new Command("analyze", "Replay saved JSON findings and optionally re-run LLM validation offline")
        {
            inputOption,
            llmValidateOption,
            sensitiveOnlyOption,
            ollamaUrlOption,
            ollamaModelOption,
            llmTimeoutSecondsOption,
            snafflerModeOption,
            outputOption,
            outputFormatOption
        };

        command.SetAction(async (result, cancellationToken) =>
        {
            return await ExecuteAsync(() => CliAnalysisRunner.RunAnalyzeAsync(
                result.GetValue(inputOption)!,
                result.GetValue(sensitiveOnlyOption),
                BuildAnalyzeLlmOptions(result, llmValidateOption, sensitiveOnlyOption, ollamaUrlOption, ollamaModelOption, llmTimeoutSecondsOption),
                BuildOutputOptions(result, outputOption, outputFormatOption, snafflerModeOption),
                cancellationToken), cancellationToken);
        });

        return command;
    }

    private static Command CreateLocalCommand()
    {
        var pathOption = new Option<string>("--path")
        {
            Description = "Folder path to scan."
        };
        pathOption.Aliases.Add("-p");
        pathOption.Required = true;

        var commonOptions = CreateCommonScanOptions();
        var command = new Command("local", "Scan a local folder")
        {
            pathOption,
            commonOptions.Binary,
            commonOptions.EnumOnly,
            commonOptions.LlmValidate,
            commonOptions.LlmSensitiveOnly,
            commonOptions.OllamaUrl,
            commonOptions.OllamaModel,
            commonOptions.LlmTimeoutSeconds,
            commonOptions.SnafflerMode,
            commonOptions.Rules,
            commonOptions.Output,
            commonOptions.OutputFormat
        };

        command.SetAction(async (result, cancellationToken) =>
        {
            var path = result.GetValue(pathOption);
            var binary = result.GetValue(commonOptions.Binary);
            var enumOnly = result.GetValue(commonOptions.EnumOnly);
            var rulesPath = result.GetValue(commonOptions.Rules);
            return await ExecuteAsync(() => CliScanRunner.RunScanAsync(
                new FileSystemScanTarget(FileSystemScanMode.Folder, path!),
                binary,
                rulesPath,
                enumerateOnly: enumOnly,
                llmOptions: BuildLlmOptions(result, commonOptions),
                outputOptions: BuildOutputOptions(result, commonOptions),
                cancellationToken: cancellationToken), cancellationToken);
        });

        return command;
    }

    private static Command CreateDomainCommand()
    {
        var commonOptions = CreateCommonScanOptions();
        var credentialOptions = CreateWindowsCredentialOptions("-d");
        var kerberosOption = CreateKerberosOption();
        var domainControllerOption = new Option<string>("--domain-controller")
        {
            Description = "Domain controller hostname or IP address to use for LDAP discovery. If omitted, Windows auto-discovers a domain controller."
        };
        domainControllerOption.Aliases.Add("--dc");
        domainControllerOption.Aliases.Add("-dc");
        domainControllerOption.Validators.Add(result =>
        {
            var value = result.GetValue(domainControllerOption);
            if (!string.IsNullOrWhiteSpace(value) && !SmbDiscoveryService.IsValidDomainController(value))
            {
                result.AddError("The --domain-controller value must be a hostname or IP address without a scheme, port, or path.");
            }
        });
        var command = new Command("domain", "Crawl the current Active Directory domain by auto-discovering accessible SMB shares. Kerberos is preferred, with per-host NTLM fallback unless --kerberos is specified")
        {
            commonOptions.Binary,
            commonOptions.EnumOnly,
            commonOptions.LlmValidate,
            commonOptions.LlmSensitiveOnly,
            commonOptions.OllamaUrl,
            commonOptions.OllamaModel,
            commonOptions.LlmTimeoutSeconds,
            commonOptions.SnafflerMode,
            commonOptions.Rules,
            commonOptions.Output,
            commonOptions.OutputFormat,
            credentialOptions.UserName,
            credentialOptions.Password,
            credentialOptions.Domain,
            credentialOptions.Local,
            kerberosOption,
            domainControllerOption
        };
        AddCredentialValidators(command, credentialOptions);
        AddKerberosValidators(command, credentialOptions, kerberosOption);

        command.SetAction(async (result, cancellationToken) =>
        {
            var binary = result.GetValue(commonOptions.Binary);
            var enumOnly = result.GetValue(commonOptions.EnumOnly);
            var rulesPath = result.GetValue(commonOptions.Rules);
            var credential = CliWindowsCredential.Create(
                result.GetValue(credentialOptions.UserName),
                result.GetValue(credentialOptions.Password),
                result.GetValue(credentialOptions.Domain),
                result.GetValue(credentialOptions.Local),
                preferDomainAccount: !result.GetValue(credentialOptions.Local));

            return await ExecuteAsync(() => CliScanRunner.RunScanAsync(
                new FileSystemScanTarget(
                    FileSystemScanMode.Domain,
                    string.IsNullOrWhiteSpace(result.GetValue(domainControllerOption))
                        ? "current domain"
                        : result.GetValue(domainControllerOption)!.Trim()),
                binary,
                rulesPath,
                enumerateOnly: enumOnly,
                credential,
                BuildLlmOptions(result, commonOptions),
                BuildOutputOptions(result, commonOptions),
                kerberos: result.GetValue(kerberosOption),
                cancellationToken: cancellationToken), cancellationToken);
        });

        return command;
    }

    private static Command CreateNetworkCommand()
    {
        var subnetOption = new Option<string>("--subnet")
        {
            Description = "Subnet in CIDR notation or a single IPv4 address, for example 10.0.0.0/24 or 10.0.0.10."
        };
        subnetOption.Aliases.Add("-s");

        var deviceOption = new Option<string>("--device")
        {
            Description = "Single device hostname, IPv4 address, or UNC share root."
        };
        deviceOption.Aliases.Add("-d");

        var commonOptions = CreateCommonScanOptions();
        var credentialOptions = CreateWindowsCredentialOptions("-a");
        var kerberosOption = CreateKerberosOption();
        var command = new Command("network", "Crawl SMB targets on a subnet or a single device. Kerberos is preferred, with per-host NTLM fallback unless --kerberos is specified")
        {
            subnetOption,
            deviceOption,
            commonOptions.Binary,
            commonOptions.EnumOnly,
            commonOptions.LlmValidate,
            commonOptions.LlmSensitiveOnly,
            commonOptions.OllamaUrl,
            commonOptions.OllamaModel,
            commonOptions.LlmTimeoutSeconds,
            commonOptions.SnafflerMode,
            commonOptions.Rules,
            commonOptions.Output,
            commonOptions.OutputFormat,
            credentialOptions.UserName,
            credentialOptions.Password,
            credentialOptions.Domain,
            credentialOptions.Local,
            kerberosOption
        };
        AddCredentialValidators(command, credentialOptions);
        AddKerberosValidators(command, credentialOptions, kerberosOption);

        command.Validators.Add(result =>
        {
            var hasSubnet = !string.IsNullOrWhiteSpace(result.GetValue(subnetOption));
            var hasDevice = !string.IsNullOrWhiteSpace(result.GetValue(deviceOption));
            if (hasSubnet == hasDevice)
            {
                result.AddError("Specify exactly one of --subnet or --device.");
            }
        });

        subnetOption.Validators.Add(result =>
        {
            var subnet = result.GetValue(subnetOption);
            if (!string.IsNullOrWhiteSpace(subnet) && !SmbDiscoveryService.IsValidSubnetOrSingleHost(subnet))
            {
                result.AddError("The --subnet value must be an IPv4 CIDR range like 10.0.0.0/24 or a single IPv4 address like 10.0.0.10.");
            }
        });

        command.SetAction(async (result, cancellationToken) =>
        {
            var subnet = result.GetValue(subnetOption);
            var device = result.GetValue(deviceOption);
            var binary = result.GetValue(commonOptions.Binary);
            var enumOnly = result.GetValue(commonOptions.EnumOnly);
            var rulesPath = result.GetValue(commonOptions.Rules);
            var credential = CliWindowsCredential.Create(
                result.GetValue(credentialOptions.UserName),
                result.GetValue(credentialOptions.Password),
                result.GetValue(credentialOptions.Domain),
                result.GetValue(credentialOptions.Local),
                preferDomainAccount: !result.GetValue(credentialOptions.Local));
            var target = FileSystemScanTarget.Parse(null, domain: false, subnet, device);
            return await ExecuteAsync(() => CliScanRunner.RunScanAsync(
                target,
                binary,
                rulesPath,
                enumerateOnly: enumOnly,
                credential,
                BuildLlmOptions(result, commonOptions),
                BuildOutputOptions(result, commonOptions),
                kerberos: result.GetValue(kerberosOption),
                cancellationToken: cancellationToken), cancellationToken);
        });

        return command;
    }

    private static Command CreateSharePointCommand()
    {
        var options = CreateSharePointOptions();
        var command = new Command("sharepoint", "Scan Microsoft 365 content, including SharePoint, OneDrive, and Teams channel files")
        {
            options.Config,
            options.TenantId,
            options.ClientId,
            options.ClientSecret,
            options.Interactive,
            options.DeviceCode,
            options.SiteUrls,
            options.SharePointUrl,
            options.DriveIds,
            options.Binary,
            options.EnumOnly,
            options.LlmValidate,
            options.LlmSensitiveOnly,
            options.OllamaUrl,
            options.OllamaModel,
            options.LlmTimeoutSeconds,
            options.SnafflerMode,
            options.Rules,
            options.Output,
            options.OutputFormat
        };

        command.Aliases.Add("m365");
        command.Aliases.Add("office365");
        command.SetAction(async (result, cancellationToken) =>
        {
            var connectorConfig = CliConnectorConfiguration.BuildConnectorConfig(
                CommonConstants.ConnectorProviders.Microsoft365,
                result.GetValue(options.Config),
                result.GetValue(options.TenantId),
                result.GetValue(options.ClientId),
                result.GetValue(options.ClientSecret),
                result.GetValue(options.Interactive),
                result.GetValue(options.DeviceCode),
                result.GetValue(options.SiteUrls),
                result.GetValue(options.SharePointUrl),
                result.GetValue(options.DriveIds));

            return await ExecuteAsync(() => CliScanRunner.RunConnectorScanAsync(
                CommonConstants.ConnectorProviders.Microsoft365,
                connectorConfig,
                result.GetValue(options.Binary),
                result.GetValue(options.EnumOnly),
                result.GetValue(options.Rules),
                BuildLlmOptions(result, options.LlmValidate, options.LlmSensitiveOnly, options.OllamaUrl, options.OllamaModel, options.LlmTimeoutSeconds),
                BuildOutputOptions(result, options.Output, options.OutputFormat, options.SnafflerMode),
                cancellationToken: cancellationToken), cancellationToken);
        });

        return command;
    }

    private static Command CreateSlackCommand()
    {
        var tokenOption = new Option<string>("--token")
        {
            Description = "Slack bot/user token. Prefer the SLACK_BOT_TOKEN environment variable to avoid shell history."
        };
        tokenOption.Aliases.Add("-t");
        var browserOption = new Option<bool>("--browser")
        {
            Description = "Authenticate in an isolated browser and scan all public channels plus private channels and DMs the user belongs to, without installing an app or joining channels."
        };
        browserOption.Aliases.Add("--browser-login");
        var workspaceUrlOption = new Option<string>("--workspace-url")
        {
            Description = "Optional Slack workspace URL to open for browser authentication, for example https://example.slack.com."
        };
        workspaceUrlOption.Validators.Add(result =>
        {
            var value = result.GetValue(workspaceUrlOption);
            if (!string.IsNullOrWhiteSpace(value)
                && (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
                    || uri.Scheme != Uri.UriSchemeHttps
                    || !(uri.Host.Equals("slack.com", StringComparison.OrdinalIgnoreCase)
                         || uri.Host.EndsWith(".slack.com", StringComparison.OrdinalIgnoreCase))))
            {
                result.AddError("The --workspace-url value must be an HTTPS slack.com URL.");
            }
        });
        var browserChannelOption = new Option<string>("--browser-channel")
        {
            Description = "Installed browser channel for interactive Slack authentication: msedge or chrome.",
            DefaultValueFactory = _ => OperatingSystem.IsWindows() ? "msedge" : "chrome"
        };
        browserChannelOption.Validators.Add(result =>
        {
            var value = result.GetValue(browserChannelOption);
            if (value is not null
                && !value.Equals("msedge", StringComparison.OrdinalIgnoreCase)
                && !value.Equals("chrome", StringComparison.OrdinalIgnoreCase))
            {
                result.AddError("The --browser-channel value must be 'msedge' or 'chrome'.");
            }
        });
        var channelOption = new Option<string[]>("--channel")
        {
            Description = "Channel name or ID to scan. Repeat to select multiple channels; omit to scan all accessible channels, including unjoined public channels in browser mode.",
            AllowMultipleArgumentsPerToken = true
        };
        channelOption.Aliases.Add("-c");
        var fullScanOption = new Option<bool>("--full-scan")
        {
            Description = "Ignore saved Slack checkpoints and rescan all accessible message history so existing findings are reported again. This is the default.",
            DefaultValueFactory = _ => CliScanRunner.DefaultFullScan
        };
        var configOption = new Option<string[]>("--config")
        {
            Description = "Additional connector configuration as Key=Value entries.",
            AllowMultipleArgumentsPerToken = true
        };
        var common = CreateCommonScanOptions();
        var command = new Command("slack", "Scan accessible Slack channel messages and attachments")
        {
            tokenOption, browserOption, workspaceUrlOption, browserChannelOption, channelOption, fullScanOption, configOption,
            common.Binary, common.EnumOnly, common.LlmValidate, common.LlmSensitiveOnly,
            common.OllamaUrl, common.OllamaModel, common.LlmTimeoutSeconds, common.SnafflerMode,
            common.Rules, common.Output, common.OutputFormat
        };
        command.Validators.Add(result =>
        {
#if SIFT_NATIVE_AOT
            if (result.GetValue(browserOption))
            {
                result.AddError("Interactive browser authentication is not included in Native AOT builds. Supply a Slack token instead.");
                return;
            }
#endif
            if (!result.GetValue(browserOption))
            {
                return;
            }

            var config = CliConnectorConfiguration.ParseConnectorConfig(result.GetValue(configOption));
            if (!string.IsNullOrWhiteSpace(result.GetValue(tokenOption)) || config.ContainsKey("Token"))
            {
                result.AddError("Use either --browser or a Slack token, not both.");
            }
        });

        command.SetAction(async (result, cancellationToken) =>
        {
            return await ExecuteAsync(async () =>
            {
                var config = CliConnectorConfiguration.ParseConnectorConfig(result.GetValue(configOption));
                AddConnectorValues(config, "Channel", result.GetValue(channelOption));
                if (result.GetValue(browserOption))
                {
#if SIFT_NATIVE_AOT
                    throw new PlatformNotSupportedException("Interactive browser authentication is not included in Native AOT builds. Supply a Slack token instead.");
#else
                    SetConnectorValue(config, "BrowserChannel", result.GetValue(browserChannelOption));
                    SetConnectorValue(config, "WorkspaceUrl", result.GetValue(workspaceUrlOption));
                    await using var browserConnector = new SlackBrowserConnector();
                    return await CliScanRunner.RunConnectorScanAsync(
                        CommonConstants.ConnectorProviders.Slack,
                        config,
                        result.GetValue(common.Binary),
                        result.GetValue(common.EnumOnly),
                        result.GetValue(common.Rules),
                        BuildLlmOptions(result, common),
                        BuildOutputOptions(result, common),
                        connectorOverride: browserConnector,
                        fullScan: result.GetValue(fullScanOption),
                        cancellationToken: cancellationToken);
#endif
                }

                SetConnectorValue(config, "Token", result.GetValue(tokenOption));
                return await CliScanRunner.RunConnectorScanAsync(
                    CommonConstants.ConnectorProviders.Slack,
                    config,
                    result.GetValue(common.Binary),
                    result.GetValue(common.EnumOnly),
                    result.GetValue(common.Rules),
                    BuildLlmOptions(result, common),
                    BuildOutputOptions(result, common),
                    fullScan: result.GetValue(fullScanOption),
                    cancellationToken: cancellationToken);
            }, cancellationToken);
        });

        return command;
    }

    private static Command CreateSlackExportCommand()
    {
        var inputOption = new Option<string>("--input")
        {
            Description = "Path to an official Slack export ZIP file or extracted export directory.",
            Required = true
        };
        inputOption.Aliases.Add("-i");
        inputOption.Validators.Add(result =>
        {
            var value = result.GetValue(inputOption);
            if (!string.IsNullOrWhiteSpace(value) && !File.Exists(value) && !Directory.Exists(value))
            {
                result.AddError($"Slack export input '{value}' was not found.");
            }
        });

        var filesRootOption = new Option<string>("--files-root")
        {
            Description = "Optional directory containing files supplied with or downloaded for the export."
        };
        filesRootOption.Validators.Add(result =>
        {
            var value = result.GetValue(filesRootOption);
            if (!string.IsNullOrWhiteSpace(value) && !Directory.Exists(value))
            {
                result.AddError($"Slack files directory '{value}' was not found.");
            }
        });

        var browserFilesOption = new Option<bool>("--download-files-with-browser")
        {
            Description = "Open an isolated browser for interactive Slack login, download file links from the export, scan them, and delete the temporary browser data."
        };
        browserFilesOption.Aliases.Add("--browser-files");

        var browserChannelOption = new Option<string>("--browser-channel")
        {
            Description = "Installed Chromium browser channel used for interactive downloads: msedge or chrome.",
            DefaultValueFactory = _ => OperatingSystem.IsWindows() ? "msedge" : "chrome"
        };
        browserChannelOption.Validators.Add(result =>
        {
            var value = result.GetValue(browserChannelOption);
            if (value is not null && !value.Equals("msedge", StringComparison.OrdinalIgnoreCase) && !value.Equals("chrome", StringComparison.OrdinalIgnoreCase))
            {
                result.AddError("The --browser-channel value must be 'msedge' or 'chrome'.");
            }
        });

        var common = CreateCommonScanOptions();
        var command = new Command("slack-export", "Scan an official Slack workspace export without installing an app")
        {
            inputOption, filesRootOption, browserFilesOption, browserChannelOption,
            common.Binary, common.EnumOnly, common.LlmValidate, common.LlmSensitiveOnly,
            common.OllamaUrl, common.OllamaModel, common.LlmTimeoutSeconds, common.SnafflerMode,
            common.Rules, common.Output, common.OutputFormat
        };
        command.Validators.Add(result =>
        {
#if SIFT_NATIVE_AOT
            if (result.GetValue(browserFilesOption))
            {
                result.AddError("Interactive browser downloads are not included in Native AOT builds. Supply --files-root instead.");
                return;
            }
#endif
            if (result.GetValue(browserFilesOption) && !string.IsNullOrWhiteSpace(result.GetValue(filesRootOption)))
            {
                result.AddError("Specify either --files-root or --download-files-with-browser, not both.");
            }

            if (result.GetValue(browserFilesOption) && result.GetValue(common.EnumOnly))
            {
                result.AddError("--download-files-with-browser cannot be combined with --enum-only.");
            }
        });

        command.SetAction(async (result, cancellationToken) =>
        {
            return await ExecuteAsync(async () =>
            {
                var input = result.GetValue(inputOption)!;
#if !SIFT_NATIVE_AOT
                SlackBrowserDownloadSession? browserSession = null;
#endif
                try
                {
                    var filesRoot = result.GetValue(filesRootOption);
                    if (result.GetValue(browserFilesOption))
                    {
#if SIFT_NATIVE_AOT
                        throw new PlatformNotSupportedException("Interactive browser downloads are not included in Native AOT builds. Supply --files-root instead.");
#else
                        browserSession = await SlackBrowserFileDownloader.DownloadAsync(
                            input,
                            result.GetValue(browserChannelOption) ?? "msedge",
                            cancellationToken);
                        filesRoot = browserSession.DownloadDirectory;
#endif
                    }

                    var config = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Input"] = input };
                    SetConnectorValue(config, "FilesRoot", filesRoot);
                    return await CliScanRunner.RunConnectorScanAsync(
                        CommonConstants.ConnectorProviders.SlackExport,
                        config,
                        result.GetValue(common.Binary),
                        result.GetValue(common.EnumOnly),
                        result.GetValue(common.Rules),
                        BuildLlmOptions(result, common),
                        BuildOutputOptions(result, common),
                        cancellationToken: cancellationToken);
                }
                finally
                {
#if !SIFT_NATIVE_AOT
                    if (browserSession != null) await browserSession.DisposeAsync();
#endif
                }
            }, cancellationToken);
        });

        return command;
    }

    private static Command CreateJiraCommand()
    {
        var urlOption = new Option<string>("--url")
        {
            Description = "Atlassian Cloud site URL, for example https://example.atlassian.net. Alternatively set ATLASSIAN_URL."
        };
        var emailOption = new Option<string>("--email")
        {
            Description = "Atlassian account email for API-token authentication. Alternatively set ATLASSIAN_EMAIL."
        };
        var cloudIdOption = new Option<string>("--cloud-id")
        {
            Description = "Atlassian Cloud ID for OAuth bearer authentication. If omitted, it is discovered from the token. Alternatively set ATLASSIAN_CLOUD_ID."
        };
        var tokenOption = new Option<string>("--token")
        {
            Description = "Atlassian API token (with --email) or OAuth access token. Prefer ATLASSIAN_API_TOKEN to avoid shell history."
        };
        tokenOption.Aliases.Add("-t");
        var projectOption = new Option<string[]>("--project")
        {
            Description = "Jira project key or ID. Repeat to select multiple projects; omit to scan all accessible projects.",
            AllowMultipleArgumentsPerToken = true
        };
        projectOption.Aliases.Add("-p");
        var spaceOption = new Option<string[]>("--space")
        {
            Description = "Confluence space key or ID. Repeat to select multiple spaces; omit to scan all accessible spaces.",
            AllowMultipleArgumentsPerToken = true
        };
        spaceOption.Aliases.Add("-s");
        var jqlOption = new Option<string>("--jql")
        {
            Description = "Additional JQL filter applied within each selected project."
        };
        var fullScanOption = new Option<bool>("--full-scan")
        {
            Description = "Ignore saved Atlassian checkpoints and rescan all accessible Jira and Confluence content. This is the default.",
            DefaultValueFactory = _ => CliScanRunner.DefaultFullScan
        };
        var resumeOption = new Option<bool>("--resume")
        {
            Description = "Resume from saved per-project and per-space checkpoints. The interrupted project or space restarts if it did not finish."
        };
        resumeOption.Aliases.Add("--incremental");
        var configOption = new Option<string[]>("--config")
        {
            Description = "Additional connector configuration as Key=Value entries.",
            AllowMultipleArgumentsPerToken = true
        };
        var common = CreateCommonScanOptions();
        var command = new Command("atlassian", "Scan accessible Jira projects and Confluence pages, blog posts, comments, and attachments")
        {
            urlOption, emailOption, cloudIdOption, tokenOption, projectOption, spaceOption, jqlOption,
            fullScanOption, resumeOption, configOption,
            common.Binary, common.EnumOnly, common.LlmValidate, common.LlmSensitiveOnly,
            common.OllamaUrl, common.OllamaModel, common.LlmTimeoutSeconds, common.SnafflerMode,
            common.Rules, common.Output, common.OutputFormat
        };
        command.Aliases.Add("jira");

        command.SetAction(async (result, cancellationToken) =>
        {
            var config = CliConnectorConfiguration.ParseConnectorConfig(result.GetValue(configOption));
            SetConnectorValue(config, "Url", result.GetValue(urlOption));
            SetConnectorValue(config, "Email", result.GetValue(emailOption));
            SetConnectorValue(config, "CloudId", result.GetValue(cloudIdOption));
            SetConnectorValue(config, "Token", result.GetValue(tokenOption));
            SetConnectorValue(config, "Jql", result.GetValue(jqlOption));
            AddConnectorValues(config, "Project", result.GetValue(projectOption));
            AddConnectorValues(config, "Space", result.GetValue(spaceOption));
            return await ExecuteAsync(() => CliScanRunner.RunConnectorScanAsync(
                CommonConstants.ConnectorProviders.Atlassian,
                config,
                result.GetValue(common.Binary),
                result.GetValue(common.EnumOnly),
                result.GetValue(common.Rules),
                BuildLlmOptions(result, common),
                BuildOutputOptions(result, common),
                fullScan: result.GetValue(fullScanOption) && !result.GetValue(resumeOption),
                cancellationToken: cancellationToken), cancellationToken);
        });

        return command;
    }

    private static async Task<int> ExecuteAsync(Func<Task<int>> action, CancellationToken cancellationToken)
    {
        try
        {
            return await action();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Console.Error.WriteLine("Scan cancelled.");
            return CliExitCodes.Cancelled;
        }
    }

    private static void SetConnectorValue(IDictionary<string, string> config, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            config[key] = value;
        }
    }

    private static void AddConnectorValues(IDictionary<string, string> config, string key, IEnumerable<string>? values)
    {
        foreach (var value in values ?? [])
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            config[key] = config.TryGetValue(key, out var existing)
                ? string.Concat(existing, Environment.NewLine, value)
                : value;
        }
    }

    private static CommonScanOptions CreateCommonScanOptions()
    {
        var outputFormatOption = new Option<string>("--output-format")
        {
            Description = "Output file format. Supported values: cli, json."
        };
        outputFormatOption.Aliases.Add("-f");
        outputFormatOption.Validators.Add(result =>
        {
            var value = result.GetValue(outputFormatOption);
            if (!string.IsNullOrWhiteSpace(value) && !IsValidOutputFormat(value))
            {
                result.AddError("The --output-format value must be either 'cli' or 'json'.");
            }
        });

        var binaryOption = new Option<bool>("--binary")
        {
            Description = "Include binary files in scan."
        };
        binaryOption.Aliases.Add("-b");

        var enumOnlyOption = new Option<bool>("--enum-only")
        {
            Description = "Enumerate discovered drives, shares, or roots and exit without scanning file content."
        };
        enumOnlyOption.Aliases.Add("-e");

        var llmValidateOption = new Option<bool>("--llm-validate")
        {
            Description = "Validate classifier matches with a local Ollama model before reporting findings."
        };

        var llmSensitiveOnlyOption = new Option<bool>("--llm-sensitive-only")
        {
            Description = "Only keep findings that the LLM classifies as sensitive. Requires --llm-validate."
        };
        llmSensitiveOnlyOption.Validators.Add(result =>
        {
            if (result.GetValue(llmSensitiveOnlyOption) && !result.GetValue(llmValidateOption))
            {
                result.AddError("The --llm-sensitive-only option requires --llm-validate.");
            }
        });

        var ollamaUrlOption = new Option<string>("--ollama-url")
        {
            Description = "Base URL for the Ollama server.",
            DefaultValueFactory = _ => "http://localhost:11434"
        };

        var ollamaModelOption = new Option<string>("--ollama-model")
        {
            Description = "Ollama model to use for classifier validation. If omitted with --llm-validate, an interactive prompt is used when possible."
        };

        var llmTimeoutSecondsOption = new Option<int>("--llm-timeout-seconds")
        {
            Description = "Timeout for each Ollama validation request in seconds.",
            DefaultValueFactory = _ => 20
        };
        llmTimeoutSecondsOption.Validators.Add(result =>
        {
            if (result.GetValue(llmTimeoutSecondsOption) <= 0)
            {
                result.AddError("The --llm-timeout-seconds value must be greater than zero.");
            }
        });

        var snafflerModeOption = new Option<bool>("--snaffler-mode")
        {
            Description = "Render console and CLI text output in Snaffler's logging style."
        };
        snafflerModeOption.Aliases.Add("--snaffler");

        var rulesOption = new Option<string>("--rules")
        {
            Description = "Path to a folder containing classifier/policy files (JSON). If not provided, bundled defaults are used."
        };
        rulesOption.Aliases.Add("-r");

        var outputOption = new Option<string>("--output")
        {
            Description = "Write scan output to a file. Resume/incremental scans append to an existing file; full scans replace it."
        };
        outputOption.Aliases.Add("-o");

        return new CommonScanOptions(
            binaryOption,
            enumOnlyOption,
            llmValidateOption,
            llmSensitiveOnlyOption,
            ollamaUrlOption,
            ollamaModelOption,
            llmTimeoutSecondsOption,
            snafflerModeOption,
            rulesOption,
            outputOption,
            outputFormatOption);
    }

    private static WindowsCredentialOptions CreateWindowsCredentialOptions(string domainShortAlias)
    {
        var userNameOption = new Option<string>("--username")
        {
            Description = "Windows username for SMB/LDAP impersonation. Accepts user, domain\\user, or user@domain."
        };
        userNameOption.Aliases.Add("-u");

        var passwordOption = new Option<string>("--password")
        {
            Description = "Windows password for SMB/LDAP impersonation."
        };
        passwordOption.Aliases.Add("-p");

        var domainOption = new Option<string>("--domain")
        {
            Description = "Windows/AD domain for impersonation when --username is not already qualified."
        };
        domainOption.Aliases.Add(domainShortAlias);

        var localOption = new Option<bool>("--local")
        {
            Description = "Use the local machine account namespace instead of a domain account."
        };
        localOption.Aliases.Add("-l");

        return new WindowsCredentialOptions(
            userNameOption,
            passwordOption,
            domainOption,
            localOption);
    }

    private static Option<bool> CreateKerberosOption()
    {
        var option = new Option<bool>("--kerberos")
        {
            Description = "Require Kerberos for SMB authentication and reject the default per-host NTLM fallback. IP targets are resolved to the DNS hostname required by the cifs service principal."
        };
        option.Aliases.Add("-k");
        return option;
    }

    private static void AddKerberosValidators(
        Command command,
        WindowsCredentialOptions credentialOptions,
        Option<bool> kerberosOption)
    {
        command.Validators.Add(result =>
        {
            if (result.GetValue(kerberosOption) && result.GetValue(credentialOptions.Local))
            {
                result.AddError("--kerberos cannot be combined with --local because Kerberos requires an Active Directory account.");
            }
        });
    }

    private static void AddCredentialValidators(Command command, WindowsCredentialOptions credentialOptions)
    {
        command.Validators.Add(result =>
        {
            var username = result.GetValue(credentialOptions.UserName);
            var password = result.GetValue(credentialOptions.Password);
            var domain = result.GetValue(credentialOptions.Domain);
            var useLocal = result.GetValue(credentialOptions.Local);

            var hasUsername = !string.IsNullOrWhiteSpace(username);
            var hasPassword = !string.IsNullOrWhiteSpace(password);
            var hasDomain = !string.IsNullOrWhiteSpace(domain);

            if (hasUsername != hasPassword)
            {
                result.AddError("Specify both --username and --password when supplying SMB impersonation credentials.");
            }

            if (hasDomain && !hasUsername)
            {
                result.AddError("--domain requires --username and --password.");
            }

            if (useLocal && !hasUsername)
            {
                result.AddError("--local requires --username and --password.");
            }

            if (useLocal && hasDomain)
            {
                result.AddError("Use either --domain or --local, not both.");
            }

            if (hasDomain && hasUsername &&
                (username!.Contains('\\', StringComparison.Ordinal) || username.Contains('@', StringComparison.Ordinal)))
            {
                result.AddError("Use either a qualified --username or --domain, not both.");
            }

            if (useLocal && hasUsername &&
                (username!.Contains('\\', StringComparison.Ordinal) || username.Contains('@', StringComparison.Ordinal)))
            {
                result.AddError("Use either a qualified --username or --local, not both.");
            }
        });
    }

    private static SharePointCommandOptions CreateSharePointOptions()
    {
        var outputFormatOption = new Option<string>("--output-format")
        {
            Description = "Output file format. Supported values: cli, json."
        };
        outputFormatOption.Aliases.Add("-f");
        outputFormatOption.Validators.Add(result =>
        {
            var value = result.GetValue(outputFormatOption);
            if (!string.IsNullOrWhiteSpace(value) && !IsValidOutputFormat(value))
            {
                result.AddError("The --output-format value must be either 'cli' or 'json'.");
            }
        });

        var configOption = new Option<string[]>("--config")
        {
            Description = "Configuration key-value pairs. Repeat SiteUrl=..., SeedUrl=..., or DriveId=... to target specific locations. Tenant-wide scans discover SharePoint, OneDrive, followed locations, and Teams channel drives by default; use DiscoverFollowedLocations=false or DiscoverTeamsChannels=false to opt out.",
            Arity = ArgumentArity.ZeroOrMore
        };
        configOption.Aliases.Add("-g");

        var tenantIdOption = new Option<string>("--tenant-id")
        {
            Description = "Tenant ID for Microsoft 365 authentication. Optional for delegated auth; omitted values are discovered from sign-in."
        };
        tenantIdOption.Aliases.Add("-t");

        var clientIdOption = new Option<string>("--client-id")
        {
            Description = "Client ID for Microsoft 365 Graph auth. Optional for delegated SharePoint-native CLI scans when --sharepoint-url or --site-url is supplied."
        };
        clientIdOption.Aliases.Add("-c");

        var clientSecretOption = new Option<string>("--client-secret")
        {
            Description = "Client secret for app-only Microsoft 365 scans."
        };
        clientSecretOption.Aliases.Add("-S");

        var interactiveOption = new Option<bool>("--interactive")
        {
            Description = "Use interactive browser authentication. This is the default unless app-only credentials are supplied."
        };
        interactiveOption.Aliases.Add("-i");

        var deviceCodeOption = new Option<bool>("--device-code")
        {
            Description = "Use device code authentication."
        };

        var siteUrlOption = new Option<string[]>("--site-url")
        {
            Description = "Target one or more SharePoint site, library, folder, AllItems, or Teams-backed SharePoint URLs. Deep browser links are resolved back to their containing site. Omit this for tenant-wide discovery.",
            Arity = ArgumentArity.ZeroOrMore
        };
        siteUrlOption.Aliases.Add("-s");

        var sharePointUrlOption = new Option<string>("--sharepoint-url")
        {
            Description = "Root SharePoint URL for delegated SharePoint-native discovery when --client-id is omitted, for example https://contoso.sharepoint.com"
        };
        sharePointUrlOption.Aliases.Add("-p");

        var driveIdOption = new Option<string[]>("--drive-id")
        {
            Description = "Target one or more Microsoft Graph drive IDs.",
            Arity = ArgumentArity.ZeroOrMore
        };
        driveIdOption.Aliases.Add("-d");

        var binaryOption = new Option<bool>("--binary")
        {
            Description = "Include binary files in scan."
        };
        binaryOption.Aliases.Add("-b");

        var enumOnlyOption = new Option<bool>("--enum-only")
        {
            Description = "Enumerate discovered SharePoint, OneDrive, and Teams drives and exit without scanning file content."
        };
        enumOnlyOption.Aliases.Add("-e");

        var llmValidateOption = new Option<bool>("--llm-validate")
        {
            Description = "Validate classifier matches with a local Ollama model before reporting findings."
        };

        var llmSensitiveOnlyOption = new Option<bool>("--llm-sensitive-only")
        {
            Description = "Only keep findings that the LLM classifies as sensitive. Requires --llm-validate."
        };
        llmSensitiveOnlyOption.Validators.Add(result =>
        {
            if (result.GetValue(llmSensitiveOnlyOption) && !result.GetValue(llmValidateOption))
            {
                result.AddError("The --llm-sensitive-only option requires --llm-validate.");
            }
        });

        var ollamaUrlOption = new Option<string>("--ollama-url")
        {
            Description = "Base URL for the Ollama server.",
            DefaultValueFactory = _ => "http://localhost:11434"
        };

        var ollamaModelOption = new Option<string>("--ollama-model")
        {
            Description = "Ollama model to use for classifier validation. If omitted with --llm-validate, an interactive prompt is used when possible."
        };

        var llmTimeoutSecondsOption = new Option<int>("--llm-timeout-seconds")
        {
            Description = "Timeout for each Ollama validation request in seconds.",
            DefaultValueFactory = _ => 20
        };
        llmTimeoutSecondsOption.Validators.Add(result =>
        {
            if (result.GetValue(llmTimeoutSecondsOption) <= 0)
            {
                result.AddError("The --llm-timeout-seconds value must be greater than zero.");
            }
        });

        var snafflerModeOption = new Option<bool>("--snaffler-mode")
        {
            Description = "Render console and CLI text output in Snaffler's logging style."
        };
        snafflerModeOption.Aliases.Add("--snaffler");

        var rulesOption = new Option<string>("--rules")
        {
            Description = "Path to a folder containing classifier/policy files (JSON). If not provided, bundled defaults are used."
        };
        rulesOption.Aliases.Add("-r");

        var outputOption = new Option<string>("--output")
        {
            Description = "Write scan output to a file. Resume/incremental scans append to an existing file; full scans replace it."
        };
        outputOption.Aliases.Add("-o");

        return new SharePointCommandOptions(
            configOption,
            tenantIdOption,
            clientIdOption,
            clientSecretOption,
            interactiveOption,
            deviceCodeOption,
            siteUrlOption,
            sharePointUrlOption,
            driveIdOption,
            binaryOption,
            enumOnlyOption,
            llmValidateOption,
            llmSensitiveOnlyOption,
            ollamaUrlOption,
            ollamaModelOption,
            llmTimeoutSecondsOption,
            snafflerModeOption,
            rulesOption,
            outputOption,
            outputFormatOption);
    }

    private static CliOutputOptions? BuildOutputOptions(ParseResult result, CommonScanOptions options)
    {
        return BuildOutputOptions(result, options.Output, options.OutputFormat, options.SnafflerMode);
    }

    private static bool IsValidOutputFormat(string value)
    {
        return string.Equals(value, "cli", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(value, "json", StringComparison.OrdinalIgnoreCase);
    }

    private static CliOutputOptions? BuildOutputOptions(ParseResult result, Option<string> outputOption, Option<string> outputFormatOption, Option<bool> snafflerModeOption)
    {
        var outputPath = result.GetValue(outputOption);
        var formatValue = result.GetValue(outputFormatOption);
        var format = string.IsNullOrWhiteSpace(formatValue)
            ? CliOutputFormat.Cli
            : Enum.Parse<CliOutputFormat>(formatValue, ignoreCase: true);
        var style = result.GetValue(snafflerModeOption)
            ? CliOutputStyle.Snaffler
            : CliOutputStyle.Default;

        return new CliOutputOptions(outputPath, format, style);
    }

    private static CliLlmOptions? BuildLlmOptions(ParseResult result, CommonScanOptions options)
    {
        return BuildLlmOptions(result, options.LlmValidate, options.LlmSensitiveOnly, options.OllamaUrl, options.OllamaModel, options.LlmTimeoutSeconds);
    }

    private static CliLlmOptions? BuildAnalyzeLlmOptions(ParseResult result, Option<bool> llmValidate, Option<bool> sensitiveOnly, Option<string> ollamaUrl, Option<string> ollamaModel, Option<int> llmTimeoutSeconds)
    {
        if (!result.GetValue(llmValidate))
        {
            return null;
        }

        return new CliLlmOptions(
            true,
            result.GetValue(ollamaUrl) ?? "http://localhost:11434",
            result.GetValue(ollamaModel) ?? string.Empty,
            result.GetValue(llmTimeoutSeconds),
            result.GetValue(sensitiveOnly));
    }

    private static CliLlmOptions? BuildLlmOptions(ParseResult result, Option<bool> llmValidate, Option<bool> llmSensitiveOnly, Option<string> ollamaUrl, Option<string> ollamaModel, Option<int> llmTimeoutSeconds)
    {
        if (!result.GetValue(llmValidate))
        {
            return null;
        }

        return new CliLlmOptions(
            true,
            result.GetValue(ollamaUrl) ?? "http://localhost:11434",
            result.GetValue(ollamaModel) ?? string.Empty,
            result.GetValue(llmTimeoutSeconds),
            result.GetValue(llmSensitiveOnly));
    }

    private sealed record CommonScanOptions(
        Option<bool> Binary,
        Option<bool> EnumOnly,
        Option<bool> LlmValidate,
        Option<bool> LlmSensitiveOnly,
        Option<string> OllamaUrl,
        Option<string> OllamaModel,
        Option<int> LlmTimeoutSeconds,
        Option<bool> SnafflerMode,
        Option<string> Rules,
        Option<string> Output,
        Option<string> OutputFormat);
    private sealed record WindowsCredentialOptions(Option<string> UserName, Option<string> Password, Option<string> Domain, Option<bool> Local);

    private sealed record SharePointCommandOptions(
        Option<string[]> Config,
        Option<string> TenantId,
        Option<string> ClientId,
        Option<string> ClientSecret,
        Option<bool> Interactive,
        Option<bool> DeviceCode,
        Option<string[]> SiteUrls,
        Option<string> SharePointUrl,
        Option<string[]> DriveIds,
        Option<bool> Binary,
        Option<bool> EnumOnly,
        Option<bool> LlmValidate,
        Option<bool> LlmSensitiveOnly,
        Option<string> OllamaUrl,
        Option<string> OllamaModel,
        Option<int> LlmTimeoutSeconds,
        Option<bool> SnafflerMode,
        Option<string> Rules,
        Option<string> Output,
        Option<string> OutputFormat);
}
