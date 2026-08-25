using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core;

namespace Stratus.Sift.Connectors.Slack;

public sealed class SlackConnector : IConnector, IConnectorCheckpointScopeProvider
{
    private const int MaximumApiAttempts = 8;
    private readonly HttpClient _httpClient;
    private readonly ILogger<SlackConnector>? _logger;
    private readonly SlackRateLimitGate _rateLimits = new();
    private readonly SlackRateLimitNoticeLimiter _rateLimitNotices = new();
    private HttpClient? _client;
    private HashSet<string>? _channelFilter;
    private string _workspaceId = string.Empty;
    private string _workspaceName = "Slack";
    private string _workspaceUrl = "https://slack.com";
    private string _checkpointScope = string.Empty;

    public SlackConnector(HttpClient httpClient, ILogger<SlackConnector>? logger = null)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public string ProviderName => CommonConstants.ConnectorProviders.Slack;
    public string CheckpointScope => !string.IsNullOrWhiteSpace(_checkpointScope)
        ? _checkpointScope
        : throw new InvalidOperationException("The Slack connector has not been initialized.");

    public async Task InitializeAsync(Dictionary<string, string> configuration, CancellationToken cancellationToken = default)
    {
        var token = configuration.GetValueOrDefault("Token") ?? Environment.GetEnvironmentVariable("SLACK_BOT_TOKEN");
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("Slack token is required. Use --token or set SLACK_BOT_TOKEN.");
        }

        _channelFilter = SplitValues(configuration.GetValueOrDefault("Channel"));
        _client = _httpClient;
        _client.BaseAddress = new Uri("https://slack.com/api/");
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Trim());
        _checkpointScope = ConnectorCheckpointIdentity.Create("slack", token);

        using var document = await GetSlackDocumentAsync("auth.test", null, cancellationToken);
        var root = document.RootElement;
        _workspaceId = root.GetProperty("team_id").GetString() ?? string.Empty;
        _workspaceName = root.GetProperty("team").GetString() ?? "Slack";
        _workspaceUrl = root.TryGetProperty("url", out var url) ? url.GetString() ?? _workspaceUrl : _workspaceUrl;
    }

    public async Task<IEnumerable<IRemoteDrive>> GetDrivesAsync(CancellationToken cancellationToken = default)
    {
        EnsureInitialized();
        var drives = new List<IRemoteDrive>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var successfulQueries = 0;
        foreach (var type in new[] { "public_channel", "private_channel", "mpim", "im" })
        {
            try
            {
                await AddConversationDrivesAsync(type, drives, seen, cancellationToken);
                successfulQueries++;
            }
            catch (InvalidOperationException ex) when (
                ex.Message.Contains("missing_scope", StringComparison.OrdinalIgnoreCase)
                || ex.Message.Contains("not_allowed_token_type", StringComparison.OrdinalIgnoreCase))
            {
                _logger?.LogWarning("Slack conversation type {ConversationType} is not accessible to this token: {Message}", type, ex.Message);
            }
        }

        if (successfulQueries == 0)
        {
            throw new InvalidOperationException("The Slack token cannot enumerate any supported conversation type. Check the app scopes and installation.");
        }

        return drives;
    }

    private async Task AddConversationDrivesAsync(
        string type,
        List<IRemoteDrive> drives,
        HashSet<string> seen,
        CancellationToken cancellationToken)
    {
        string? cursor = null;

        do
        {
            var query = new Dictionary<string, string?>
            {
                ["types"] = type,
                ["exclude_archived"] = "false",
                ["limit"] = "200",
                ["cursor"] = cursor
            };
            using var document = await GetSlackDocumentAsync("conversations.list", query, cancellationToken);
            var root = document.RootElement;
            foreach (var channel in root.GetProperty("channels").EnumerateArray())
            {
                var id = channel.GetProperty("id").GetString() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(id) || !seen.Add(id))
                {
                    continue;
                }

                var name = channel.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? id : id;
                if (name == id && channel.TryGetProperty("is_im", out var isIm) && isIm.ValueKind == JsonValueKind.True)
                {
                    name = "dm-" + (channel.TryGetProperty("user", out var user) ? user.GetString() ?? id : id);
                }
                else if (name == id && channel.TryGetProperty("is_mpim", out var isMpim) && isMpim.ValueKind == JsonValueKind.True)
                {
                    name = "group-dm-" + id;
                }
                if (_channelFilter is { Count: > 0 } && !_channelFilter.Contains(id) && !_channelFilter.Contains(name))
                {
                    continue;
                }

                drives.Add(new SlackDrive(_client!, this, _workspaceId, _workspaceName, _workspaceUrl, id, name));
            }

            cursor = GetNextCursor(root);
        }
        while (!string.IsNullOrWhiteSpace(cursor));
    }

    internal async Task<JsonDocument> GetSlackDocumentAsync(
        string method,
        IReadOnlyDictionary<string, string?>? query,
        CancellationToken cancellationToken)
    {
        EnsureInitialized(allowAuthTest: method == "auth.test");
        var uri = method;
        if (query != null)
        {
            var values = query
                .Where(pair => !string.IsNullOrWhiteSpace(pair.Value))
                .Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value!)}");
            var queryString = string.Join('&', values);
            if (queryString.Length > 0)
            {
                uri += "?" + queryString;
            }
        }

        for (var attempt = 0; attempt < MaximumApiAttempts; attempt++)
        {
            using var rateLimitLease = await _rateLimits.EnterAsync(method, cancellationToken);
            using var response = await _client!.GetAsync(uri, cancellationToken);
            if ((int)response.StatusCode == 429)
            {
                if (attempt >= MaximumApiAttempts - 1)
                {
                    throw new HttpRequestException(
                        $"Slack API call '{method}' remained rate limited after {MaximumApiAttempts} attempts.",
                        inner: null,
                        response.StatusCode);
                }

                var observation = _rateLimits.ReportRateLimit(method, GetRetryAfter(response), attempt);
                if (_rateLimitNotices.ShouldReport(method))
                {
                    _logger?.LogInformation(
                        "Slack rate limiting detected for {Method}. Pausing for {RetryDelay} and enabling adaptive pacing at {PacingInterval} or slower; further handled notices for this method are suppressed.",
                        method,
                        observation.RetryDelay,
                        observation.PacingInterval);
                }
                continue;
            }

            if ((int)response.StatusCode is 408 or 500 or 502 or 503 or 504
                && attempt < MaximumApiAttempts - 1)
            {
                await Task.Delay(SlackRateLimitGate.GetTransientRetryDelay(attempt), cancellationToken);
                continue;
            }

            response.EnsureSuccessStatusCode();
            var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
            if (!document.RootElement.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
            {
                var error = document.RootElement.TryGetProperty("error", out var errorElement)
                    ? errorElement.GetString()
                    : "unknown_error";
                var retryAfter = SlackRateLimitGate.GetRetryAfter(document.RootElement);
                document.Dispose();
                if (string.Equals(error, "ratelimited", StringComparison.OrdinalIgnoreCase)
                    && attempt < MaximumApiAttempts - 1)
                {
                    var observation = _rateLimits.ReportRateLimit(method, retryAfter, attempt);
                    if (_rateLimitNotices.ShouldReport(method))
                    {
                        _logger?.LogInformation(
                            "Slack rate limiting detected for {Method}. Enabling adaptive pacing at {PacingInterval} or slower; further handled notices for this method are suppressed.",
                            method,
                            observation.PacingInterval);
                    }
                    continue;
                }

                throw new InvalidOperationException($"Slack API call '{method}' failed: {error}.");
            }

            _rateLimits.ReportSuccess(method);
            return document;
        }

        throw new HttpRequestException(
            $"Slack API call '{method}' exhausted its retry loop.");
    }

    private static TimeSpan? GetRetryAfter(HttpResponseMessage response)
    {
        var retryAfter = response.Headers.RetryAfter?.Delta
            ?? (response.Headers.RetryAfter?.Date - DateTimeOffset.UtcNow);
        return retryAfter < TimeSpan.Zero ? TimeSpan.Zero : retryAfter;
    }

    internal static string? GetNextCursor(JsonElement root)
    {
        return root.TryGetProperty("response_metadata", out var metadata)
            && metadata.TryGetProperty("next_cursor", out var cursor)
            ? cursor.GetString()
            : null;
    }

    private void EnsureInitialized(bool allowAuthTest = false)
    {
        if (_client == null || (!allowAuthTest && string.IsNullOrWhiteSpace(_workspaceId)))
        {
            throw new InvalidOperationException("Slack connector has not been initialized.");
        }
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
