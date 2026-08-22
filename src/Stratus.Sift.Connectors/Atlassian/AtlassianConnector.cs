using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core;

namespace Stratus.Sift.Connectors.Atlassian;

public sealed class AtlassianConnector : IConnector
{
    private readonly HttpClient _httpClient;
    private readonly ILogger? _logger;
    private AtlassianApiClient? _jiraApi;
    private AtlassianApiClient? _confluenceApi;
    private Uri? _siteUri;
    private HashSet<string>? _projectFilter;
    private HashSet<string>? _spaceFilter;
    private string? _additionalJql;
    private IReadOnlyDictionary<string, string> _customFields = new Dictionary<string, string>();

    public AtlassianConnector(HttpClient httpClient, ILogger<AtlassianConnector>? logger = null)
        : this(httpClient, (ILogger?)logger)
    {
    }

    internal AtlassianConnector(HttpClient httpClient, ILogger? logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public string ProviderName => CommonConstants.ConnectorProviders.Atlassian;

    public async Task InitializeAsync(Dictionary<string, string> configuration, CancellationToken cancellationToken = default)
    {
        var baseUrl = configuration.GetValueOrDefault("Url")
            ?? Environment.GetEnvironmentVariable("ATLASSIAN_URL")
            ?? Environment.GetEnvironmentVariable("JIRA_URL");
        var email = configuration.GetValueOrDefault("Email")
            ?? Environment.GetEnvironmentVariable("ATLASSIAN_EMAIL")
            ?? Environment.GetEnvironmentVariable("JIRA_EMAIL");
        var token = configuration.GetValueOrDefault("Token")
            ?? Environment.GetEnvironmentVariable("ATLASSIAN_API_TOKEN")
            ?? Environment.GetEnvironmentVariable("JIRA_API_TOKEN");
        var configuredCloudId = configuration.GetValueOrDefault("CloudId")
            ?? Environment.GetEnvironmentVariable("ATLASSIAN_CLOUD_ID")
            ?? Environment.GetEnvironmentVariable("JIRA_CLOUD_ID");
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Atlassian URL is required and must be an absolute HTTPS URL. Use --url or set ATLASSIAN_URL.");
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("Atlassian API or OAuth token is required. Use --token or set ATLASSIAN_API_TOKEN.");
        }

        _siteUri = new Uri(uri.AbsoluteUri.TrimEnd('/') + "/");
        _projectFilter = SplitValues(configuration.GetValueOrDefault("Project"));
        _spaceFilter = SplitValues(configuration.GetValueOrDefault("Space"));
        _additionalJql = configuration.GetValueOrDefault("Jql")?.Trim();
        _httpClient.DefaultRequestHeaders.Accept.Clear();
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        Uri jiraApiBaseUri;
        Uri confluenceApiBaseUri;
        if (!string.IsNullOrWhiteSpace(email))
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{email.Trim()}:{token.Trim()}")));
            jiraApiBaseUri = _siteUri;
            confluenceApiBaseUri = _siteUri;
        }
        else
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Trim());
            var cloudId = string.IsNullOrWhiteSpace(configuredCloudId)
                ? await DiscoverCloudIdAsync(_siteUri, cancellationToken)
                : configuredCloudId.Trim();
            jiraApiBaseUri = new Uri($"https://api.atlassian.com/ex/jira/{Uri.EscapeDataString(cloudId)}/");
            confluenceApiBaseUri = new Uri($"https://api.atlassian.com/ex/confluence/{Uri.EscapeDataString(cloudId)}/");
        }

        _jiraApi = new AtlassianApiClient(_httpClient, jiraApiBaseUri, _logger);
        _confluenceApi = new AtlassianApiClient(_httpClient, confluenceApiBaseUri, _logger);
        try
        {
            using var _ = await _jiraApi.GetJsonAsync("rest/api/3/myself", cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.LogWarning(ex, "Jira is not accessible with the supplied Atlassian credentials; Confluence will still be attempted.");
            _jiraApi = null;
            _customFields = new Dictionary<string, string>();
        }

        if (_jiraApi != null)
        {
            try
            {
                _customFields = await LoadCustomFieldsAsync(cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger?.LogWarning(ex, "Jira custom-field metadata is not accessible; Jira issues will still be scanned using standard fields.");
                _customFields = new Dictionary<string, string>();
            }
        }
    }

    public async Task<IEnumerable<IRemoteDrive>> GetDrivesAsync(CancellationToken cancellationToken = default)
    {
        EnsureInitialized();
        var drives = new List<IRemoteDrive>();
        var productAccessible = false;
        if (_jiraApi != null)
        {
            try
            {
                await AddJiraDrivesAsync(drives, cancellationToken);
                productAccessible = true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger?.LogWarning(ex, "Jira projects are not accessible with the supplied Atlassian credentials; Confluence will still be scanned.");
            }
        }

        try
        {
            await AddConfluenceDrivesAsync(drives, cancellationToken);
            productAccessible = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.LogWarning(ex, "Confluence is not accessible with the supplied Atlassian credentials; Jira results will still be scanned.");
        }

        if (!productAccessible)
        {
            throw new InvalidOperationException("The supplied Atlassian credentials could not access Jira or Confluence.");
        }

        return drives;
    }

    private async Task AddJiraDrivesAsync(List<IRemoteDrive> drives, CancellationToken cancellationToken)
    {
        var startAt = 0;

        while (true)
        {
            using var document = await _jiraApi!.GetJsonAsync(
                $"rest/api/3/project/search?startAt={startAt}&maxResults=50&orderBy=key",
                cancellationToken);
            var root = document.RootElement;
            var values = root.GetProperty("values");
            foreach (var project in values.EnumerateArray())
            {
                var id = GetScalarString(project, "id") ?? string.Empty;
                var key = GetScalarString(project, "key") ?? id;
                var name = GetScalarString(project, "name") ?? key;
                if (_projectFilter is { Count: > 0 } && !_projectFilter.Contains(key) && !_projectFilter.Contains(id))
                {
                    continue;
                }

                drives.Add(new JiraDrive(_jiraApi, _siteUri!, id, key, name, _additionalJql, _customFields));
            }

            var count = values.GetArrayLength();
            var total = root.TryGetProperty("total", out var totalElement) && totalElement.TryGetInt32(out var parsedTotal)
                ? parsedTotal
                : startAt + count;
            startAt += count;
            if (count == 0 || startAt >= total)
            {
                break;
            }
        }

    }

    private async Task AddConfluenceDrivesAsync(List<IRemoteDrive> drives, CancellationToken cancellationToken)
    {
        string? cursor = null;
        do
        {
            var path = "wiki/api/v2/spaces?status=current&limit=100";
            if (!string.IsNullOrWhiteSpace(cursor)) path += "&cursor=" + Uri.EscapeDataString(cursor);
            using var document = await _confluenceApi!.GetJsonAsync(path, cancellationToken);
            foreach (var space in document.RootElement.GetProperty("results").EnumerateArray())
            {
                var id = GetScalarString(space, "id") ?? string.Empty;
                var key = GetScalarString(space, "key") ?? id;
                var name = GetScalarString(space, "name") ?? key;
                if (_spaceFilter is { Count: > 0 } && !_spaceFilter.Contains(id) && !_spaceFilter.Contains(key)) continue;
                drives.Add(new ConfluenceDrive(_confluenceApi, _siteUri!, id, key, name));
            }

            cursor = ConfluenceDrive.GetNextCursor(document.RootElement);
        }
        while (!string.IsNullOrWhiteSpace(cursor));
    }

    private async Task<string> DiscoverCloudIdAsync(Uri siteUri, CancellationToken cancellationToken)
    {
        var discoveryApi = new AtlassianApiClient(_httpClient, new Uri("https://api.atlassian.com/"), _logger);
        using var document = await discoveryApi.GetJsonAsync("oauth/token/accessible-resources", cancellationToken);
        foreach (var resource in document.RootElement.EnumerateArray())
        {
            var url = GetScalarString(resource, "url");
            if (Uri.TryCreate(url, UriKind.Absolute, out var resourceUri)
                && resourceUri.Host.Equals(siteUri.Host, StringComparison.OrdinalIgnoreCase))
            {
                return GetScalarString(resource, "id")
                    ?? throw new InvalidOperationException($"Atlassian OAuth resource for '{siteUri.Host}' did not include a Cloud ID.");
            }
        }

        throw new InvalidOperationException(
            $"The Atlassian OAuth token does not grant access to '{siteUri.Host}'. Supply a matching token or --cloud-id.");
    }

    private async Task<IReadOnlyDictionary<string, string>> LoadCustomFieldsAsync(CancellationToken cancellationToken)
    {
        using var document = await _jiraApi!.GetJsonAsync("rest/api/3/field", cancellationToken);
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in document.RootElement.EnumerateArray())
        {
            var id = GetScalarString(field, "id");
            var isCustom = field.TryGetProperty("custom", out var customElement) && customElement.ValueKind == JsonValueKind.True;
            if (isCustom && !string.IsNullOrWhiteSpace(id))
            {
                fields[id] = GetScalarString(field, "name") ?? id;
            }
        }

        return fields;
    }

    private void EnsureInitialized()
    {
        if (_confluenceApi == null || _siteUri == null)
        {
            throw new InvalidOperationException("Atlassian connector has not been initialized.");
        }
    }

    internal static string? GetScalarString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null
        };
    }

    private static HashSet<string>? SplitValues(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Split(['\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }
}
