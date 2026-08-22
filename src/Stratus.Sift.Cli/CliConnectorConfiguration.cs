using Stratus.Sift.Core;

namespace Stratus.Sift.Cli;

internal static class CliConnectorConfiguration
{
    internal static Dictionary<string, string> ParseConnectorConfig(string[]? configEntries)
    {
        var config = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in configEntries ?? Array.Empty<string>())
        {
            var parts = entry.Split('=', 2);
            if (parts.Length != 2)
            {
                continue;
            }

            if (config.TryGetValue(parts[0], out var existingValue))
            {
                config[parts[0]] = string.Concat(existingValue, Environment.NewLine, parts[1]);
            }
            else
            {
                config[parts[0]] = parts[1];
            }
        }

        return config;
    }

    internal static Dictionary<string, string> BuildConnectorConfig(
        string providerName,
        string[]? configEntries,
        string? tenantId,
        string? clientId,
        string? clientSecret,
        bool interactive,
        bool deviceCode,
        string[]? siteUrls,
        string? sharePointUrl,
        string[]? driveIds)
    {
        var config = ParseConnectorConfig(configEntries);

        SetConfigValue(config, "TenantId", tenantId);
        SetConfigValue(config, "ClientId", clientId);
        SetConfigValue(config, "ClientSecret", clientSecret);
        SetConfigValue(config, "SharePointUrl", sharePointUrl);
        AddConfigValues(config, "SiteUrl", siteUrls);
        AddConfigValues(config, "DriveId", driveIds);

        var normalizedProviderName = NormalizeProviderName(providerName);
        if (!normalizedProviderName.Equals(CommonConstants.ConnectorProviders.Microsoft365, StringComparison.OrdinalIgnoreCase))
        {
            return config;
        }

        if (interactive && deviceCode)
        {
            throw new ArgumentException("Specify only one of --interactive or --device-code.");
        }

        if (deviceCode)
        {
            config["AuthMode"] = "DeviceCode";
        }
        else if (interactive || (!config.ContainsKey("AuthMode") && string.IsNullOrWhiteSpace(config.GetValueOrDefault("ClientSecret"))))
        {
            config["AuthMode"] = "Interactive";
        }
        else if (!config.ContainsKey("AuthMode") && !string.IsNullOrWhiteSpace(config.GetValueOrDefault("ClientSecret")))
        {
            config["AuthMode"] = "AppOnly";
        }

        return config;
    }

    internal static string NormalizeProviderName(string providerName)
    {
        if (string.IsNullOrWhiteSpace(providerName))
        {
            return providerName;
        }

        var normalized = string.Concat(providerName.Where(ch => !char.IsWhiteSpace(ch) && ch != '-')).ToLowerInvariant();
        return normalized switch
        {
            "m365" or "microsoft365" or "office365" or "sharepoint" or "sharepointonline" => CommonConstants.ConnectorProviders.Microsoft365,
            "slack" => CommonConstants.ConnectorProviders.Slack,
            "slackexport" => CommonConstants.ConnectorProviders.SlackExport,
            "jira" or "atlassian" or "atlassianjira" or "confluence" => CommonConstants.ConnectorProviders.Atlassian,
            _ => providerName.Trim()
        };
    }

    private static void SetConfigValue(IDictionary<string, string> config, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            config[key] = value;
        }
    }

    private static void AddConfigValues(IDictionary<string, string> config, string key, IEnumerable<string>? values)
    {
        foreach (var value in values ?? Array.Empty<string>())
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (config.TryGetValue(key, out var existingValue))
            {
                config[key] = string.Concat(existingValue, Environment.NewLine, value);
            }
            else
            {
                config[key] = value;
            }
        }
    }
}
