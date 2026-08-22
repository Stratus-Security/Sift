using System.Text;
using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.Jira;

internal sealed class ConfluenceDrive : IRemoteDrive
{
    private const string NewestFirstSort = "-modified-date";

    private readonly JiraApiClient _api;
    private readonly Uri _siteUri;
    private readonly string _spaceKey;

    internal ConfluenceDrive(JiraApiClient api, Uri siteUri, string spaceId, string spaceKey, string spaceName)
    {
        _api = api;
        _siteUri = siteUri;
        _spaceKey = spaceKey;
        Id = spaceId;
        Name = $"Confluence: {spaceKey} - {spaceName}";
    }

    public string Id { get; }
    public string Name { get; }
    public string ConnectionId => $"atlassian://{_siteUri.Host}/confluence/{_spaceKey}";
    public string WebUrl => new Uri(_siteUri, $"wiki/spaces/{Uri.EscapeDataString(_spaceKey)}").AbsoluteUri;
    public DatastoreType DriveType => DatastoreType.Confluence;
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
        var boundary = ParseDelta(deltaToken);
        var newest = boundary;
        newest = MaxTimestamp(newest, await ProcessContentTypeAsync(
            "pages", "page", boundary, onChange, cancellationToken));
        newest = MaxTimestamp(newest, await ProcessContentTypeAsync(
            "blogposts", "blogpost", boundary, onChange, cancellationToken));
        return newest ?? DateTimeOffset.UtcNow.ToString("O");
    }

    private async Task<string?> ProcessContentTypeAsync(
        string collection,
        string contentType,
        string? boundary,
        Func<IRemoteFile, Task> onChange,
        CancellationToken cancellationToken)
    {
        string? newest = boundary;
        string? cursor = null;
        do
        {
            var path = $"wiki/api/v2/spaces/{Uri.EscapeDataString(Id)}/{collection}?status=current&limit=100&body-format=atlas_doc_format&sort={NewestFirstSort}";
            if (!string.IsNullOrWhiteSpace(cursor)) path += "&cursor=" + Uri.EscapeDataString(cursor);
            using var document = await _api.GetJsonAsync(path, cancellationToken);
            foreach (var content in document.RootElement.GetProperty("results").EnumerateArray())
            {
                var contentId = JiraConnector.GetScalarString(content, "id") ?? string.Empty;
                if (string.IsNullOrWhiteSpace(contentId)) continue;
                var updated = GetNestedString(content, "version", "createdAt");
                newest = MaxTimestamp(newest, updated);
                if (IsAfter(updated, boundary) || string.IsNullOrWhiteSpace(boundary))
                {
                    await EmitContentAsync(content, collection, contentType, onChange);
                }

                newest = MaxTimestamp(newest, await EmitCommentsAsync(collection, contentId, "footer", boundary, onChange, cancellationToken));
                newest = MaxTimestamp(newest, await EmitCommentsAsync(collection, contentId, "inline", boundary, onChange, cancellationToken));
                newest = MaxTimestamp(newest, await EmitAttachmentsAsync(collection, contentId, boundary, onChange, cancellationToken));
            }

            cursor = GetNextCursor(document.RootElement);
        }
        while (!string.IsNullOrWhiteSpace(cursor));

        return newest;
    }

    private async Task EmitContentAsync(
        JsonElement content,
        string collection,
        string contentType,
        Func<IRemoteFile, Task> onChange)
    {
        var id = JiraConnector.GetScalarString(content, "id")!;
        var title = JiraConnector.GetScalarString(content, "title") ?? id;
        var builder = new StringBuilder();
        Append(builder, "Space", _spaceKey);
        Append(builder, "Content type", contentType);
        Append(builder, "Title", title);
        Append(builder, "Content ID", id);
        Append(builder, "Author", JiraConnector.GetScalarString(content, "authorId"));
        Append(builder, "Created", JiraConnector.GetScalarString(content, "createdAt"));
        Append(builder, "Updated", GetNestedString(content, "version", "createdAt"));
        var body = GetBodyText(content);
        if (!string.IsNullOrWhiteSpace(body)) builder.AppendLine().AppendLine(body);
        var fallback = contentType == "page"
            ? $"wiki/spaces/{Uri.EscapeDataString(_spaceKey)}/pages/{Uri.EscapeDataString(id)}"
            : $"wiki/spaces/{Uri.EscapeDataString(_spaceKey)}/blog/{Uri.EscapeDataString(id)}";
        var webUrl = GetWebUrl(content, fallback);
        await onChange(new SimpleRemoteFile(
            id,
            SanitizeFileName(title) + ".txt",
            $"atlassian://{_siteUri.Host}/confluence/{_spaceKey}/{collection}/{id}.txt",
            webUrl,
            builder.ToString()));
    }

    private async Task<string?> EmitCommentsAsync(
        string collection,
        string contentId,
        string kind,
        string? boundary,
        Func<IRemoteFile, Task> onChange,
        CancellationToken cancellationToken)
    {
        var endpoint = $"wiki/api/v2/{collection}/{Uri.EscapeDataString(contentId)}/{kind}-comments";
        var visited = new HashSet<string>(StringComparer.Ordinal);
        var contentPath = $"{collection}/{contentId}";
        return await EmitCommentPageAsync(endpoint, contentPath, kind, boundary, onChange, visited, cancellationToken);
    }

    private async Task<string?> EmitCommentPageAsync(
        string endpoint,
        string contentPath,
        string kind,
        string? boundary,
        Func<IRemoteFile, Task> onChange,
        HashSet<string> visited,
        CancellationToken cancellationToken)
    {
        string? cursor = null;
        string? newest = boundary;
        do
        {
            var path = endpoint + (endpoint.Contains('?') ? "&" : "?") + $"limit=100&body-format=atlas_doc_format&sort={NewestFirstSort}";
            if (!string.IsNullOrWhiteSpace(cursor)) path += "&cursor=" + Uri.EscapeDataString(cursor);
            using var document = await _api.GetJsonAsync(path, cancellationToken);
            foreach (var comment in document.RootElement.GetProperty("results").EnumerateArray())
            {
                var id = JiraConnector.GetScalarString(comment, "id") ?? string.Empty;
                if (string.IsNullOrWhiteSpace(id) || !visited.Add(id)) continue;
                var updated = GetNestedString(comment, "version", "createdAt");
                newest = MaxTimestamp(newest, updated);
                if (string.IsNullOrWhiteSpace(boundary) || IsAfter(updated, boundary))
                {
                    var content = new StringBuilder();
                    Append(content, "Space", _spaceKey);
                    Append(content, "Content", contentPath);
                    Append(content, "Comment type", kind);
                    Append(content, "Comment ID", id);
                    Append(content, "Author", GetNestedString(comment, "version", "authorId"));
                    Append(content, "Updated", updated);
                    var body = GetBodyText(comment);
                    if (!string.IsNullOrWhiteSpace(body)) content.AppendLine().AppendLine(body);
                    await onChange(new SimpleRemoteFile(
                        id,
                        $"{kind}-comment-{id}.txt",
                        $"atlassian://{_siteUri.Host}/confluence/{_spaceKey}/{contentPath}/{kind}-comments/{id}.txt",
                        GetWebUrl(comment, $"wiki/spaces/{Uri.EscapeDataString(_spaceKey)}"),
                        content.ToString()));
                }

                var childrenEndpoint = $"wiki/api/v2/{kind}-comments/{Uri.EscapeDataString(id)}/children";
                newest = MaxTimestamp(newest, await EmitCommentPageAsync(childrenEndpoint, contentPath, kind, boundary, onChange, visited, cancellationToken));
            }

            cursor = GetNextCursor(document.RootElement);
        }
        while (!string.IsNullOrWhiteSpace(cursor));
        return newest;
    }

    private async Task<string?> EmitAttachmentsAsync(
        string collection,
        string contentId,
        string? boundary,
        Func<IRemoteFile, Task> onChange,
        CancellationToken cancellationToken)
    {
        string? cursor = null;
        string? newest = boundary;
        do
        {
            var path = $"wiki/api/v2/{collection}/{Uri.EscapeDataString(contentId)}/attachments?status=current&limit=100&sort={NewestFirstSort}";
            if (!string.IsNullOrWhiteSpace(cursor)) path += "&cursor=" + Uri.EscapeDataString(cursor);
            using var document = await _api.GetJsonAsync(path, cancellationToken);
            foreach (var attachment in document.RootElement.GetProperty("results").EnumerateArray())
            {
                var id = JiraConnector.GetScalarString(attachment, "id") ?? string.Empty;
                if (string.IsNullOrWhiteSpace(id)) continue;
                var updated = GetNestedString(attachment, "version", "createdAt")
                    ?? JiraConnector.GetScalarString(attachment, "createdAt");
                newest = MaxTimestamp(newest, updated);
                var name = JiraConnector.GetScalarString(attachment, "title") ?? id;
                if (string.IsNullOrWhiteSpace(boundary) || IsAfter(updated, boundary))
                {
                    var size = attachment.TryGetProperty("fileSize", out var sizeElement) && sizeElement.TryGetInt64(out var parsedSize)
                        ? parsedSize
                        : (long?)null;
                    var downloadUri = new Uri(
                        _api.BaseUri,
                        $"wiki/rest/api/content/{Uri.EscapeDataString(contentId)}/child/attachment/{Uri.EscapeDataString(id)}/download");
                    await onChange(new SimpleRemoteFile(
                        id,
                        name,
                        $"atlassian://{_siteUri.Host}/confluence/{_spaceKey}/{collection}/{contentId}/attachments/{name}",
                        GetWebUrl(attachment, $"wiki/spaces/{Uri.EscapeDataString(_spaceKey)}"),
                        size,
                        JiraConnector.GetScalarString(attachment, "mediaType"),
                        _api.HttpClient,
                        downloadUri));
                }

                var commentsEndpoint = $"wiki/api/v2/attachments/{Uri.EscapeDataString(id)}/footer-comments";
                var attachmentPath = $"{collection}/{contentId}/attachments/{id}";
                newest = MaxTimestamp(newest, await EmitCommentPageAsync(
                    commentsEndpoint,
                    attachmentPath,
                    "footer",
                    boundary,
                    onChange,
                    new HashSet<string>(StringComparer.Ordinal),
                    cancellationToken));
            }

            cursor = GetNextCursor(document.RootElement);
        }
        while (!string.IsNullOrWhiteSpace(cursor));
        return newest;
    }

    internal static string? GetNextCursor(JsonElement root)
    {
        if (!root.TryGetProperty("_links", out var links)
            || !links.TryGetProperty("next", out var nextElement)
            || nextElement.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(nextElement.GetString()))
        {
            return null;
        }

        var next = nextElement.GetString()!;
        var queryIndex = next.IndexOf('?');
        if (queryIndex < 0) return null;
        foreach (var pair in next[(queryIndex + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 && parts[0].Equals("cursor", StringComparison.OrdinalIgnoreCase))
            {
                return Uri.UnescapeDataString(parts[1]);
            }
        }

        return null;
    }

    internal static string GetBodyText(JsonElement element)
    {
        if (!element.TryGetProperty("body", out var body) || body.ValueKind != JsonValueKind.Object) return string.Empty;
        JsonElement value = body;
        if (body.TryGetProperty("atlas_doc_format", out var atlas)) value = atlas;
        if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty("value", out var nestedValue)) value = nestedValue;
        if (value.ValueKind == JsonValueKind.String)
        {
            var raw = value.GetString() ?? string.Empty;
            try
            {
                using var document = JsonDocument.Parse(
                    raw,
                    new JsonDocumentOptions { MaxDepth = JiraApiClient.MaximumJsonDepth });
                return JiraDrive.GetFlexibleValueText(document.RootElement);
            }
            catch (JsonException)
            {
                return raw;
            }
        }

        return JiraDrive.GetFlexibleValueText(value);
    }

    private string GetWebUrl(JsonElement element, string fallback)
    {
        var link = element.TryGetProperty("_links", out var links)
            ? JiraConnector.GetScalarString(links, "webui")
            : null;
        if (Uri.TryCreate(link, UriKind.Absolute, out var absolute)) return absolute.AbsoluteUri;
        var path = string.IsNullOrWhiteSpace(link) ? fallback : link.TrimStart('/');
        if (!path.StartsWith("wiki/", StringComparison.OrdinalIgnoreCase)) path = "wiki/" + path;
        return new Uri(_siteUri, path).AbsoluteUri;
    }

    private static string? GetNestedString(JsonElement element, string property, string nestedProperty)
        => element.TryGetProperty(property, out var nested) && nested.ValueKind == JsonValueKind.Object
            ? JiraConnector.GetScalarString(nested, nestedProperty)
            : null;

    private static string? ParseDelta(string? token)
        => DateTimeOffset.TryParse(token, out var parsed) ? parsed.ToUniversalTime().ToString("O") : null;

    private static bool IsAfter(string? candidate, string? boundary)
        => DateTimeOffset.TryParse(candidate, out var candidateValue)
           && (!DateTimeOffset.TryParse(boundary, out var boundaryValue) || candidateValue > boundaryValue);

    private static string? MaxTimestamp(string? left, string? right)
        => !DateTimeOffset.TryParse(right, out var rightValue)
            ? left
            : !DateTimeOffset.TryParse(left, out var leftValue) || rightValue > leftValue
                ? rightValue.ToUniversalTime().ToString("O")
                : left;

    private static void Append(StringBuilder builder, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) builder.Append(label).Append(": ").AppendLine(value);
    }

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        var name = string.Concat(value.Select(ch => invalid.Contains(ch) || ch is '/' or '\\' ? '-' : ch)).Trim();
        if (name.Length > 120) name = name[..120];
        return string.IsNullOrWhiteSpace(name) ? "page" : name;
    }
}
