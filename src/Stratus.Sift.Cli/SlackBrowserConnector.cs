using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Playwright;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Connectors.Slack;
using Stratus.Sift.Core;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Cli;

internal sealed class SlackBrowserConnector : IConnector, IConnectorCheckpointScopeProvider, IAsyncDisposable
{
    private SlackBrowserSession? _session;
    private HashSet<string>? _channelFilter;
    private string _workspaceId = string.Empty;
    private string _workspaceName = "Slack";
    private string _workspaceUrl = "https://app.slack.com";

    public string ProviderName => CommonConstants.ConnectorProviders.Slack;
    public string CheckpointScope => _session?.CheckpointScope
        ?? throw new InvalidOperationException("The Slack browser connector has not been initialized.");

    public async Task InitializeAsync(Dictionary<string, string> configuration, CancellationToken cancellationToken = default)
    {
        if (Console.IsInputRedirected)
        {
            throw new InvalidOperationException("Slack browser authentication requires an interactive terminal.");
        }

        _channelFilter = SplitValues(configuration.GetValueOrDefault("Channel"));
        var channel = configuration.GetValueOrDefault("BrowserChannel")
            ?? (OperatingSystem.IsWindows() ? "msedge" : "chrome");
        var workspaceUrl = configuration.GetValueOrDefault("WorkspaceUrl");
        _session = await SlackBrowserSession.OpenAsync(channel, workspaceUrl, cancellationToken);
        _workspaceId = _session.WorkspaceId;
        _workspaceName = _session.WorkspaceName;
        _workspaceUrl = _session.WorkspaceUrl;

        // The authenticated page URL or observed API request normally identifies the team.
        // Keep auth.test only as a compatibility fallback because the live Slack client can
        // consume the same per-method rate-limit bucket while it is open.
        if (string.IsNullOrWhiteSpace(_workspaceId))
        {
            using var document = await _session.CallAsync("auth.test", null, cancellationToken);
            var root = document.RootElement;
            _workspaceId = GetString(root, "team_id") ?? string.Empty;
            _workspaceName = GetString(root, "team") ?? _workspaceName;
            _workspaceUrl = GetString(root, "url") ?? _workspaceUrl;
        }
    }

    public async Task<IEnumerable<IRemoteDrive>> GetDrivesAsync(CancellationToken cancellationToken = default)
    {
        EnsureInitialized();
        var conversations = await DiscoverConversationsAsync(
            _session!,
            _workspaceId,
            _channelFilter,
            warning => Console.WriteLine($"Slack discovery warning: {warning}"),
            cancellationToken);
        return conversations
            .Select(conversation => (IRemoteDrive)new SlackBrowserDrive(
                _session!,
                _workspaceId,
                _workspaceName,
                _workspaceUrl,
                conversation.Id,
                conversation.Name))
            .ToList();
    }

    internal static async Task<IReadOnlyList<SlackBrowserConversation>> DiscoverConversationsAsync(
        ISlackBrowserSession session,
        string workspaceId,
        IReadOnlySet<string>? channelFilter = null,
        Action<string>? onWarning = null,
        CancellationToken cancellationToken = default)
    {
        var conversations = new Dictionary<string, SlackBrowserConversation>(StringComparer.Ordinal);
        var publicDiscoverySucceeded = false;

        try
        {
            await AddConversationsAsync("conversations.list", "public_channel");
            publicDiscoverySucceeded = true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            onWarning?.Invoke($"unjoined public channels could not be listed ({ex.Message}); continuing with conversations the signed-in user has joined.");
        }

        await AddConversationsAsync(
            "users.conversations",
            publicDiscoverySucceeded ? "private_channel,mpim,im" : "public_channel,private_channel,mpim,im");

        return conversations.Values
            .Where(conversation => channelFilter is not { Count: > 0 }
                || channelFilter.Contains(conversation.Id)
                || channelFilter.Contains(conversation.Name))
            .OrderBy(conversation => conversation.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        async Task AddConversationsAsync(string method, string types)
        {
            string? cursor = null;
            do
            {
                using var document = await session.CallAsync(
                    method,
                    new Dictionary<string, string?>
                    {
                        ["types"] = types,
                        ["exclude_archived"] = "false",
                        ["limit"] = "200",
                        ["team_id"] = workspaceId,
                        ["cursor"] = cursor
                    },
                    cancellationToken);

                foreach (var conversation in document.RootElement.GetProperty("channels").EnumerateArray())
                {
                    var id = GetString(conversation, "id") ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(id))
                    {
                        conversations.TryAdd(id, new SlackBrowserConversation(id, GetConversationName(conversation, id)));
                    }
                }

                cursor = GetNextCursor(document.RootElement);
            }
            while (!string.IsNullOrWhiteSpace(cursor));
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_session != null)
        {
            await _session.DisposeAsync();
            _session = null;
        }
    }

    private void EnsureInitialized()
    {
        if (_session == null || string.IsNullOrWhiteSpace(_workspaceId))
        {
            throw new InvalidOperationException("Slack browser connector has not been initialized.");
        }
    }

    internal static string? GetNextCursor(JsonElement root)
        => root.TryGetProperty("response_metadata", out var metadata)
           && metadata.TryGetProperty("next_cursor", out var cursor)
            ? cursor.GetString()
            : null;

    internal static string? GetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string GetConversationName(JsonElement conversation, string id)
    {
        var name = GetString(conversation, "name") ?? GetString(conversation, "name_normalized");
        if (!string.IsNullOrWhiteSpace(name)) return name;
        if (conversation.TryGetProperty("is_im", out var isIm) && isIm.ValueKind == JsonValueKind.True)
        {
            return "dm-" + (GetString(conversation, "user") ?? id);
        }

        return conversation.TryGetProperty("is_mpim", out var isMpim) && isMpim.ValueKind == JsonValueKind.True
            ? "group-dm-" + id
            : id;
    }

    private static HashSet<string>? SplitValues(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? null
            : value.Split(['\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
}

internal interface ISlackBrowserSession
{
    Task<JsonDocument> CallAsync(string method, IReadOnlyDictionary<string, string?>? parameters, CancellationToken cancellationToken);
    Task<Stream> DownloadAsync(Uri uri, long? rangeStart, long? rangeEnd, CancellationToken cancellationToken);
}

internal sealed record SlackBrowserConversation(string Id, string Name);

internal sealed partial class SlackBrowserSession : ISlackBrowserSession, IAsyncDisposable
{
    private const int MaximumApiAttempts = 8;
    private readonly IPlaywright _playwright;
    private readonly IBrowserContext _context;
    private readonly string _rootDirectory;
    private readonly SlackRateLimitGate _rateLimits = new();
    private readonly SlackRateLimitNoticeLimiter _rateLimitNotices = new();
    private string _token;
    private readonly Uri _apiBaseUri;

    private SlackBrowserSession(
        IPlaywright playwright,
        IBrowserContext context,
        string rootDirectory,
        string token,
        Uri apiBaseUri,
        string workspaceId,
        string workspaceName,
        string workspaceUrl)
    {
        _playwright = playwright;
        _context = context;
        _rootDirectory = rootDirectory;
        _token = token;
        _apiBaseUri = apiBaseUri;
        CheckpointScope = CliResumeIdentity.Hash($"slack-browser\0{token}");
        WorkspaceId = workspaceId;
        WorkspaceName = workspaceName;
        WorkspaceUrl = workspaceUrl;
    }

    internal string WorkspaceId { get; }
    internal string WorkspaceName { get; }
    internal string WorkspaceUrl { get; }
    internal string CheckpointScope { get; }

    internal static async Task<SlackBrowserSession> OpenAsync(
        string browserChannel,
        string? workspaceUrl,
        CancellationToken cancellationToken)
    {
        var root = Path.Combine(Path.GetTempPath(), "StratusSift", "slack-live-browser", Guid.NewGuid().ToString("N"));
        var profile = Path.Combine(root, "browser-profile");
        var downloads = Path.Combine(root, "browser-downloads");
        Directory.CreateDirectory(profile);
        Directory.CreateDirectory(downloads);

        IPlaywright? playwright = null;
        IBrowserContext? context = null;
        try
        {
            playwright = await Playwright.CreateAsync();
            context = await playwright.Chromium.LaunchPersistentContextAsync(profile, new BrowserTypeLaunchPersistentContextOptions
            {
                Channel = browserChannel.ToLowerInvariant(),
                Headless = false,
                AcceptDownloads = false,
                DownloadsPath = downloads
            });
            var credentialSource = new TaskCompletionSource<SlackBrowserCredential>(TaskCreationOptions.RunContinuationsAsynchronously);
            var credentialLock = new object();
            SlackBrowserCredential? latestCredential = null;
            var page = context.Pages.FirstOrDefault() ?? await context.NewPageAsync();
            page.Request += (_, request) =>
            {
                if (SlackBrowserCredential.TryExtract(request.Url, request.PostData, out var credential))
                {
                    lock (credentialLock)
                    {
                        latestCredential = credential;
                    }
                    credentialSource.TrySetResult(credential);
                }
            };

            var loginUrl = string.IsNullOrWhiteSpace(workspaceUrl) ? "https://app.slack.com/client" : workspaceUrl.Trim();
            await page.GotoAsync(loginUrl, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = 60_000
            });

            Console.WriteLine();
            Console.WriteLine("An isolated Slack browser session has opened. Sign in, complete SSO/MFA, and wait until the workspace is fully loaded.");
            Console.WriteLine("When Slack is ready, return to this terminal and press Enter (or type 'cancel' and press Enter to stop).");
            var response = Console.ReadLine();
            if (string.Equals(response?.Trim(), "cancel", StringComparison.OrdinalIgnoreCase))
            {
                throw new OperationCanceledException("Slack browser authentication was canceled.");
            }

            if (!credentialSource.Task.IsCompleted)
            {
                await page.ReloadAsync(new PageReloadOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 60_000 });
            }

            SlackBrowserCredential credential;
            try
            {
                var firstCredential = await credentialSource.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
                lock (credentialLock)
                {
                    credential = latestCredential ?? firstCredential;
                }
            }
            catch (TimeoutException)
            {
                throw new InvalidOperationException(
                    "Slack was open, but no authenticated web-client API session was observed. Confirm the workspace finished loading and try again.");
            }

            var authenticatedUri = Uri.TryCreate(page.Url, UriKind.Absolute, out var parsedPageUri)
                ? parsedPageUri
                : null;
            var workspaceId = GetWorkspaceId(authenticatedUri) ?? credential.WorkspaceId;
            var resolvedWorkspaceUrl = ResolveWorkspaceUrl(workspaceUrl, workspaceId, authenticatedUri);
            var workspaceName = GetWorkspaceName(resolvedWorkspaceUrl, workspaceId);

            // Stop the live Slack client from polling and consuming the same web API rate-limit
            // buckets. The browser context and its authenticated cookies remain alive.
            await page.GotoAsync("about:blank", new PageGotoOptions
            {
                WaitUntil = WaitUntilState.Commit,
                Timeout = 10_000
            });
            Console.WriteLine("Slack sign-in captured. The browser is idle while the scan runs.");

            return new SlackBrowserSession(
                playwright,
                context,
                root,
                credential.Token,
                credential.ApiBaseUri,
                workspaceId ?? string.Empty,
                workspaceName,
                resolvedWorkspaceUrl);
        }
        catch
        {
            if (context != null) await context.DisposeAsync();
            playwright?.Dispose();
            await DeleteDirectoryAsync(root);
            throw;
        }
    }

    public async Task<JsonDocument> CallAsync(
        string method,
        IReadOnlyDictionary<string, string?>? parameters,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < MaximumApiAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var rateLimitLease = await _rateLimits.EnterAsync(method, cancellationToken);
            var form = _context.APIRequest.CreateFormData();
            form.Set("token", _token);
            if (parameters != null)
            {
                foreach (var pair in parameters.Where(pair => !string.IsNullOrWhiteSpace(pair.Value)))
                {
                    form.Set(pair.Key, pair.Value!);
                }
            }

            var response = await _context.APIRequest.PostAsync(
                new Uri(_apiBaseUri, method).AbsoluteUri,
                new APIRequestContextOptions
                {
                    Form = form,
                    Timeout = 30_000
                });
            try
            {
                if (response.Status == 429 && attempt < MaximumApiAttempts - 1)
                {
                    var observation = _rateLimits.ReportRateLimit(method, GetRetryAfter(response.Headers), attempt);
                    ReportRateLimitOnce(method, observation);
                    continue;
                }

                if (response.Status is 408 or 500 or 502 or 503 or 504
                    && attempt < MaximumApiAttempts - 1)
                {
                    var delay = SlackRateLimitGate.GetTransientRetryDelay(attempt);
                    await Task.Delay(delay, cancellationToken);
                    continue;
                }

                var body = await response.TextAsync();
                if (!response.Ok)
                {
                    throw new HttpRequestException(
                        $"Slack browser API call '{method}' failed with HTTP {response.Status}.",
                        null,
                        (System.Net.HttpStatusCode)response.Status);
                }

                var document = JsonDocument.Parse(body);
                if (!document.RootElement.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
                {
                    var error = SlackBrowserConnector.GetString(document.RootElement, "error") ?? "unknown_error";
                    var retryAfter = SlackRateLimitGate.GetRetryAfter(document.RootElement);
                    document.Dispose();
                    if (error.Equals("ratelimited", StringComparison.OrdinalIgnoreCase)
                        && attempt < MaximumApiAttempts - 1)
                    {
                        ReportRateLimitOnce(method, _rateLimits.ReportRateLimit(method, retryAfter, attempt));
                        continue;
                    }

                    throw new InvalidOperationException($"Slack browser API call '{method}' failed: {error}.");
                }

                _rateLimits.ReportSuccess(method);
                return document;
            }
            finally
            {
                await response.DisposeAsync();
            }
        }

        throw new InvalidOperationException($"Slack browser API call '{method}' exhausted its retry loop.");
    }

    private void ReportRateLimitOnce(string method, SlackRateLimitObservation observation)
    {
        if (!_rateLimitNotices.ShouldReport(method))
        {
            return;
        }

        Console.WriteLine(
            $"Slack rate limiting detected for '{method}'. Pausing for {observation.RetryDelay.TotalSeconds:N0}s and " +
            $"enabling adaptive pacing at {observation.PacingInterval.TotalSeconds:N0}s or slower; further handled notices are suppressed.");
    }

    public async Task<Stream> DownloadAsync(Uri uri, long? rangeStart, long? rangeEnd, CancellationToken cancellationToken)
    {
        if (!IsSlackUri(uri))
        {
            throw new RemoteContentUnavailableException("Slack attachment URL was outside the slack.com domain.", false);
        }

        var headers = new Dictionary<string, string> { ["Authorization"] = "Bearer " + _token };
        if (rangeStart.HasValue && rangeEnd.HasValue)
        {
            headers["Range"] = $"bytes={rangeStart.Value}-{rangeEnd.Value}";
        }

        for (var attempt = 0; attempt < MaximumApiAttempts; attempt++)
        {
            using var rateLimitLease = await _rateLimits.EnterAsync("files.download", cancellationToken);
            var response = await _context.APIRequest.GetAsync(
                uri.AbsoluteUri,
                new APIRequestContextOptions { Headers = headers, Timeout = 30_000 });
            try
            {
                if (response.Status == 429 && attempt < MaximumApiAttempts - 1)
                {
                    _rateLimits.ReportRateLimit("files.download", GetRetryAfter(response.Headers), attempt);
                    continue;
                }

                if (response.Status is 408 or 500 or 502 or 503 or 504
                    && attempt < MaximumApiAttempts - 1)
                {
                    await Task.Delay(SlackRateLimitGate.GetTransientRetryDelay(attempt), cancellationToken);
                    continue;
                }

                if (!response.Ok)
                {
                    var retryable = response.Status is 408 or 429 or 500 or 502 or 503 or 504;
                    throw new RemoteContentUnavailableException(
                        $"Slack attachment download failed with HTTP {response.Status}.",
                        retryable,
                        response.Status);
                }

                _rateLimits.ReportSuccess("files.download");
                return new MemoryStream(await response.BodyAsync(), writable: false);
            }
            finally
            {
                await response.DisposeAsync();
            }
        }

        throw new RemoteContentUnavailableException(
            "Slack attachment download remained rate limited after retries.",
            shouldRetry: true,
            statusCode: 429);
    }

    public async ValueTask DisposeAsync()
    {
        _token = string.Empty;
        await _context.DisposeAsync();
        _playwright.Dispose();
        await DeleteDirectoryAsync(_rootDirectory);
    }

    private static TimeSpan? GetRetryAfter(IReadOnlyDictionary<string, string> headers)
    {
        var value = headers.FirstOrDefault(pair => pair.Key.Equals("retry-after", StringComparison.OrdinalIgnoreCase)).Value;
        return int.TryParse(value, out var seconds) ? TimeSpan.FromSeconds(seconds) : null;
    }

    private static bool IsSlackUri(Uri uri)
        => uri.Scheme == Uri.UriSchemeHttps
           && (uri.Host.Equals("slack.com", StringComparison.OrdinalIgnoreCase)
               || uri.Host.EndsWith(".slack.com", StringComparison.OrdinalIgnoreCase));

    private static string? GetWorkspaceId(Uri? pageUri)
    {
        if (pageUri == null) return null;
        var segments = pageUri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var clientIndex = Array.FindIndex(segments, segment => segment.Equals("client", StringComparison.OrdinalIgnoreCase));
        return clientIndex >= 0 && clientIndex + 1 < segments.Length && segments[clientIndex + 1].StartsWith('T')
            ? segments[clientIndex + 1]
            : null;
    }

    private static string ResolveWorkspaceUrl(string? configuredUrl, string? workspaceId, Uri? pageUri)
    {
        if (Uri.TryCreate(configuredUrl, UriKind.Absolute, out var configured)
            && configured.Scheme == Uri.UriSchemeHttps)
        {
            return configured.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        }

        if (pageUri != null && !pageUri.Host.Equals("app.slack.com", StringComparison.OrdinalIgnoreCase))
        {
            return pageUri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        }

        return string.IsNullOrWhiteSpace(workspaceId)
            ? "https://app.slack.com"
            : $"https://app.slack.com/client/{Uri.EscapeDataString(workspaceId)}";
    }

    private static string GetWorkspaceName(string workspaceUrl, string? workspaceId)
    {
        if (Uri.TryCreate(workspaceUrl, UriKind.Absolute, out var uri)
            && uri.Host.EndsWith(".slack.com", StringComparison.OrdinalIgnoreCase)
            && !uri.Host.Equals("app.slack.com", StringComparison.OrdinalIgnoreCase))
        {
            return uri.Host[..^".slack.com".Length];
        }

        return string.IsNullOrWhiteSpace(workspaceId) ? "Slack" : workspaceId;
    }

    private static async Task DeleteDirectoryAsync(string root)
    {
        var expectedRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "StratusSift", "slack-live-browser"))
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var resolved = Path.GetFullPath(root);
        if (!resolved.StartsWith(expectedRoot, StringComparison.OrdinalIgnoreCase)) return;

        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                if (Directory.Exists(resolved)) Directory.Delete(resolved, recursive: true);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException && attempt < 2)
            {
                await Task.Delay(200 * (attempt + 1));
            }
        }
    }
}

internal sealed partial record SlackBrowserCredential(string Token, Uri ApiBaseUri, string? WorkspaceId)
{
    [GeneratedRegex(@"xoxc-[A-Za-z0-9-]+", RegexOptions.CultureInvariant)]
    private static partial Regex TokenRegex();

    internal static bool TryExtract(string requestUrl, string? postData, out SlackBrowserCredential credential)
    {
        credential = null!;
        if (!Uri.TryCreate(requestUrl, UriKind.Absolute, out var requestUri)
            || requestUri.Scheme != Uri.UriSchemeHttps
            || !(requestUri.Host.Equals("slack.com", StringComparison.OrdinalIgnoreCase)
                 || requestUri.Host.EndsWith(".slack.com", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        var apiIndex = requestUri.AbsolutePath.IndexOf("/api/", StringComparison.OrdinalIgnoreCase);
        if (apiIndex < 0) return false;
        var candidate = Uri.UnescapeDataString((postData ?? string.Empty).Replace('+', ' '));
        var match = TokenRegex().Match(candidate);
        if (!match.Success) return false;

        var apiPath = requestUri.AbsolutePath[..(apiIndex + 5)];
        credential = new SlackBrowserCredential(
            match.Value,
            new Uri(requestUri.GetLeftPart(UriPartial.Authority) + apiPath),
            GetFormValue(postData, "team_id") ?? GetFormValue(postData, "team"));
        return true;
    }

    private static string? GetFormValue(string? postData, string key)
    {
        foreach (var pair in (postData ?? string.Empty).Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 && Uri.UnescapeDataString(parts[0]).Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                return Uri.UnescapeDataString(parts[1].Replace('+', ' '));
            }
        }

        return null;
    }
}

internal sealed class SlackBrowserDrive : IRemoteDrive
{
    private readonly ISlackBrowserSession _session;
    private readonly string _workspaceName;
    private readonly string _workspaceUrl;

    internal SlackBrowserDrive(
        ISlackBrowserSession session,
        string workspaceId,
        string workspaceName,
        string workspaceUrl,
        string channelId,
        string channelName)
    {
        _session = session;
        _workspaceName = workspaceName;
        _workspaceUrl = workspaceUrl.TrimEnd('/');
        Id = channelId;
        Name = channelName;
        ConnectionId = $"slack-browser://{workspaceId}/{channelId}";
    }

    public string Id { get; }
    public string Name { get; }
    public string ConnectionId { get; }
    public string WebUrl => _workspaceUrl.StartsWith("https://app.slack.com/client/", StringComparison.OrdinalIgnoreCase)
        ? $"{_workspaceUrl}/{Id}"
        : $"{_workspaceUrl}/archives/{Id}";
    public DatastoreType DriveType => DatastoreType.Slack;
    public long? TotalSize => null;
    public long? UsedSize => null;

    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? deltaToken, CancellationToken cancellationToken = default)
    {
        var changes = new List<IRemoteFile>();
        var token = await ProcessChangesAsync(deltaToken, file => { changes.Add(file); return Task.CompletedTask; }, null, cancellationToken);
        return (changes, token);
    }

    public async Task<string> ProcessChangesAsync(
        string? deltaToken,
        Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint = null,
        CancellationToken cancellationToken = default)
    {
        var resume = SlackDrive.ParseCheckpoint(deltaToken);
        var boundary = resume.Boundary;
        var cursor = resume.Cursor;
        var newest = resume.Newest ?? boundary;
        var threadParents = resume.ThreadParents.ToList();
        var seenThreadParents = threadParents.ToHashSet(StringComparer.Ordinal);
        if (!resume.RepliesPhase)
        {
            do
            {
                using var document = await _session.CallAsync("conversations.history", new Dictionary<string, string?>
                {
                    ["channel"] = Id,
                    ["limit"] = "100",
                    ["cursor"] = cursor
                }, cancellationToken);
                foreach (var message in document.RootElement.GetProperty("messages").EnumerateArray())
                {
                    var timestamp = SlackBrowserConnector.GetString(message, "ts") ?? string.Empty;
                    var edited = message.TryGetProperty("edited", out var editedObject)
                        ? SlackBrowserConnector.GetString(editedObject, "ts")
                        : null;
                    newest = MaxTimestamp(newest, timestamp);
                    newest = MaxTimestamp(newest, edited);
                    if (string.IsNullOrWhiteSpace(boundary) || IsAfter(timestamp, boundary) || IsAfter(edited, boundary))
                    {
                        await EmitMessageAsync(message, onChange);
                    }

                    if (message.TryGetProperty("reply_count", out var replyCount)
                        && replyCount.TryGetInt32(out var count)
                        && count > 0)
                    {
                        var latestReply = message.TryGetProperty("latest_reply", out var latestReplyElement)
                            ? latestReplyElement.GetString()
                            : null;
                        if (string.IsNullOrWhiteSpace(boundary) || IsAfter(latestReply, boundary))
                        {
                            newest = MaxTimestamp(newest, latestReply);
                            if (!string.IsNullOrWhiteSpace(timestamp) && seenThreadParents.Add(timestamp))
                            {
                                threadParents.Add(timestamp);
                            }
                        }
                    }
                }

                cursor = SlackBrowserConnector.GetNextCursor(document.RootElement);
                if (onCheckpoint != null)
                {
                    await onCheckpoint(SlackDrive.CreateCheckpoint(
                        boundary,
                        cursor,
                        newest,
                        repliesPhase: string.IsNullOrWhiteSpace(cursor),
                        threadParents));
                }
            }
            while (!string.IsNullOrWhiteSpace(cursor));
        }

        while (threadParents.Count > 0)
        {
            var parentTimestamp = threadParents[0];
            newest = MaxTimestamp(newest, await EmitRepliesAsync(parentTimestamp, boundary, onChange, cancellationToken));
            threadParents.RemoveAt(0);
            if (onCheckpoint != null)
            {
                await onCheckpoint(SlackDrive.CreateCheckpoint(boundary, null, newest, repliesPhase: true, threadParents));
            }
        }

        return newest ?? string.Empty;
    }

    private async Task<string?> EmitRepliesAsync(
        string parentTimestamp,
        string? deltaToken,
        Func<IRemoteFile, Task> onChange,
        CancellationToken cancellationToken)
    {
        string? cursor = null;
        string? newest = deltaToken;
        do
        {
            using var document = await _session.CallAsync("conversations.replies", new Dictionary<string, string?>
            {
                ["channel"] = Id,
                ["ts"] = parentTimestamp,
                ["limit"] = "100",
                ["oldest"] = deltaToken,
                ["cursor"] = cursor
            }, cancellationToken);
            foreach (var reply in document.RootElement.GetProperty("messages").EnumerateArray())
            {
                var timestamp = SlackBrowserConnector.GetString(reply, "ts") ?? string.Empty;
                newest = MaxTimestamp(newest, timestamp);
                if (!timestamp.Equals(parentTimestamp, StringComparison.Ordinal)
                    && (string.IsNullOrWhiteSpace(deltaToken) || IsAfter(timestamp, deltaToken)))
                {
                    await EmitMessageAsync(reply, onChange);
                }
            }

            cursor = SlackBrowserConnector.GetNextCursor(document.RootElement);
        }
        while (!string.IsNullOrWhiteSpace(cursor));
        return newest;
    }

    private async Task EmitMessageAsync(JsonElement message, Func<IRemoteFile, Task> onChange)
    {
        var timestamp = SlackBrowserConnector.GetString(message, "ts") ?? Guid.NewGuid().ToString("N");
        var name = $"message-{timestamp.Replace('.', '-')}.txt";
        var content = $"Workspace: {_workspaceName}{Environment.NewLine}Conversation: {Name}{Environment.NewLine}User: {SlackBrowserConnector.GetString(message, "user")}{Environment.NewLine}Timestamp: {timestamp}{Environment.NewLine}{Environment.NewLine}{SlackDrive.ExtractMessageText(message)}";
        var permalink = _workspaceUrl.StartsWith("https://app.slack.com/client/", StringComparison.OrdinalIgnoreCase)
            ? WebUrl
            : $"{WebUrl}/p{timestamp.Replace(".", string.Empty, StringComparison.Ordinal)}";
        await onChange(new SlackBrowserRemoteFile($"{Id}:{timestamp}", name, $"slack-browser://{_workspaceName}/{Name}/{name}", permalink, content));

        if (!message.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Array) return;
        foreach (var file in files.EnumerateArray())
        {
            var url = SlackBrowserConnector.GetString(file, "url_private_download") ?? SlackBrowserConnector.GetString(file, "url_private");
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) continue;
            var id = SlackBrowserConnector.GetString(file, "id") ?? Guid.NewGuid().ToString("N");
            var fileName = SlackBrowserConnector.GetString(file, "name") ?? SlackBrowserConnector.GetString(file, "title") ?? id;
            var size = file.TryGetProperty("size", out var sizeElement) && sizeElement.TryGetInt64(out var parsedSize) ? parsedSize : (long?)null;
            await onChange(new SlackBrowserRemoteFile(
                id,
                fileName,
                $"slack-browser://{_workspaceName}/{Name}/attachments/{fileName}",
                SlackBrowserConnector.GetString(file, "permalink") ?? permalink,
                size,
                SlackBrowserConnector.GetString(file, "mimetype"),
                _session,
                uri));
        }
    }

    private static string? MaxTimestamp(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(right)) return left;
        if (string.IsNullOrWhiteSpace(left)) return right;
        return decimal.TryParse(left, NumberStyles.Number, CultureInfo.InvariantCulture, out var leftValue)
               && decimal.TryParse(right, NumberStyles.Number, CultureInfo.InvariantCulture, out var rightValue)
               && rightValue > leftValue
            ? right
            : left;
    }

    private static bool IsAfter(string? candidate, string? boundary)
        => !string.IsNullOrWhiteSpace(candidate)
           && (string.IsNullOrWhiteSpace(boundary)
               || decimal.TryParse(candidate, NumberStyles.Number, CultureInfo.InvariantCulture, out var candidateValue)
               && decimal.TryParse(boundary, NumberStyles.Number, CultureInfo.InvariantCulture, out var boundaryValue)
               && candidateValue > boundaryValue);
}

internal sealed class SlackBrowserRemoteFile : IRemoteFile
{
    private readonly byte[]? _content;
    private readonly ISlackBrowserSession? _session;
    private readonly Uri? _downloadUri;

    internal SlackBrowserRemoteFile(string id, string name, string path, string webUrl, string content)
    {
        Id = id;
        Name = name;
        Path = path;
        WebUrl = webUrl;
        ContentType = "text/plain";
        _content = Encoding.UTF8.GetBytes(content);
        Size = _content.LongLength;
    }

    internal SlackBrowserRemoteFile(string id, string name, string path, string webUrl, long? size, string? contentType, ISlackBrowserSession session, Uri downloadUri)
    {
        Id = id;
        Name = name;
        Path = path;
        WebUrl = webUrl;
        Size = size;
        ContentType = contentType;
        _session = session;
        _downloadUri = downloadUri;
    }

    public string Id { get; }
    public string Name { get; }
    public string Path { get; }
    public string WebUrl { get; }
    public long? Size { get; }
    public string? ContentType { get; }
    public bool IsDeleted => false;
    public bool IsDirectory => false;
    public bool IsLink => false;
    public bool IsExternal => false;

    public Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default)
        => _content != null
            ? Task.FromResult<Stream?>(new MemoryStream(_content, writable: false))
            : DownloadAsync(null, null, cancellationToken);

    public Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(start);
        if (end < start) throw new ArgumentOutOfRangeException(nameof(end));
        if (_content != null)
        {
            if (start >= _content.LongLength) return Task.FromResult<Stream?>(new MemoryStream());
            var availableEnd = Math.Min(end, _content.LongLength - 1);
            return Task.FromResult<Stream?>(new MemoryStream(_content, (int)start, (int)(availableEnd - start + 1), writable: false));
        }

        return DownloadAsync(start, end, cancellationToken);
    }

    private async Task<Stream?> DownloadAsync(long? start, long? end, CancellationToken cancellationToken)
        => _session == null || _downloadUri == null
            ? null
            : await _session.DownloadAsync(_downloadUri, start, end, cancellationToken);
}
