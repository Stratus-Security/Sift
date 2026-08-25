using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.Atlassian;

internal sealed class JiraDrive : IRemoteDrive
{
    private static readonly string[] StandardSearchFields =
    [
        "summary", "description", "environment", "attachment", "labels", "status", "reporter", "assignee", "created", "updated"
    ];

    private static readonly HashSet<string> IgnoredCustomMetadataProperties = new(StringComparer.OrdinalIgnoreCase)
    {
        "self", "id", "key", "accountId", "iconUrl", "avatarUrls", "type"
    };

    private readonly AtlassianApiClient _api;
    private readonly Uri _siteUri;
    private readonly string _projectKey;
    private readonly string _checkpointScope;
    private readonly string? _additionalJql;
    private readonly string _filterHash;
    private readonly IReadOnlyDictionary<string, string> _customFields;
    private readonly string[] _searchFields;

    internal JiraDrive(
        AtlassianApiClient api,
        Uri siteUri,
        string projectId,
        string projectKey,
        string projectName,
        string? additionalJql,
        IReadOnlyDictionary<string, string> customFields,
        string checkpointScope)
    {
        _api = api;
        _siteUri = siteUri;
        Id = projectId;
        _projectKey = projectKey;
        _checkpointScope = checkpointScope;
        Name = $"{projectKey} - {projectName}";
        _additionalJql = string.IsNullOrWhiteSpace(additionalJql) ? null : additionalJql.Trim();
        _filterHash = ComputeFilterHash(_additionalJql);
        _customFields = customFields;
        _searchFields = StandardSearchFields
            .Concat(customFields.Keys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public string Id { get; }
    public string Name { get; }
    public string ConnectionId => $"atlassian-v2://{_siteUri.Host}/{_checkpointScope}/jira/{Uri.EscapeDataString(_projectKey)}";
    public string WebUrl => new Uri(_siteUri, $"browse/{Uri.EscapeDataString(_projectKey)}").AbsoluteUri;
    public DatastoreType DriveType => DatastoreType.Jira;
    public long? TotalSize => null;
    public long? UsedSize => null;

    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(
        string? deltaToken,
        CancellationToken cancellationToken = default)
    {
        var changes = new List<IRemoteFile>();
        var token = await ProcessChangesAsync(deltaToken, file =>
        {
            changes.Add(file);
            return Task.CompletedTask;
        }, null, cancellationToken);
        return (changes, token);
    }

    public async Task<string> ProcessChangesAsync(
        string? deltaToken,
        Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint = null,
        CancellationToken cancellationToken = default)
    {
        var resume = GetResumeState(deltaToken);
        var scanStartedAt = resume.ScanStartedAt ?? DateTimeOffset.UtcNow;
        var previousUpdated = resume.Boundary;
        var nextPageToken = resume.NextPageToken;
        var newestUpdated = resume.NewestUpdated ?? previousUpdated;

        do
        {
            var request = new System.Text.Json.Nodes.JsonObject
            {
                ["jql"] = BuildJql(previousUpdated),
                ["fields"] = new System.Text.Json.Nodes.JsonArray(_searchFields.Select(item => (System.Text.Json.Nodes.JsonNode?)System.Text.Json.Nodes.JsonValue.Create(item)).ToArray()),
                ["maxResults"] = 100
            };
            if (!string.IsNullOrWhiteSpace(nextPageToken))
            {
                request["nextPageToken"] = nextPageToken;
            }

            using var document = await _api.PostJsonAsync("rest/api/3/search/jql", request, cancellationToken);
            var root = document.RootElement;
            foreach (var issue in root.GetProperty("issues").EnumerateArray())
            {
                newestUpdated = MaxIsoTimestamp(newestUpdated, GetString(issue.GetProperty("fields"), "updated"));
                await EmitIssueAsync(issue, onChange, cancellationToken);
            }

            nextPageToken = root.TryGetProperty("nextPageToken", out var nextPage) ? nextPage.GetString() : null;
            if (!string.IsNullOrWhiteSpace(nextPageToken) && onCheckpoint != null)
            {
                await onCheckpoint(CreatePageCheckpoint(
                    previousUpdated,
                    nextPageToken,
                    newestUpdated,
                    scanStartedAt));
            }
        }
        while (!string.IsNullOrWhiteSpace(nextPageToken));

        newestUpdated = MaxIsoTimestamp(newestUpdated, scanStartedAt.ToString("O"));
        return CreateDeltaToken(newestUpdated!);
    }

    private async Task EmitIssueAsync(
        JsonElement issue,
        Func<IRemoteFile, Task> onChange,
        CancellationToken cancellationToken)
    {
        var issueId = AtlassianConnector.GetScalarString(issue, "id") ?? Guid.NewGuid().ToString("N");
        var key = AtlassianConnector.GetScalarString(issue, "key") ?? issueId;
        var fields = issue.GetProperty("fields");
        var issueUrl = new Uri(_siteUri, $"browse/{Uri.EscapeDataString(key)}").AbsoluteUri;
        var builder = new StringBuilder();
        AppendLine(builder, "Key", key);
        AppendLine(builder, "Summary", GetString(fields, "summary"));
        AppendLine(builder, "Status", GetNestedString(fields, "status", "name"));
        AppendLine(builder, "Reporter", GetNestedString(fields, "reporter", "displayName"));
        AppendLine(builder, "Assignee", GetNestedString(fields, "assignee", "displayName"));
        AppendLine(builder, "Created", GetString(fields, "created"));
        AppendLine(builder, "Updated", GetString(fields, "updated"));
        AppendLine(builder, "Labels", GetStringArray(fields, "labels"));
        AppendSection(builder, "Description", GetDocumentText(fields, "description"));
        AppendSection(builder, "Environment", GetDocumentText(fields, "environment"));

        foreach (var customField in _customFields)
        {
            if (fields.TryGetProperty(customField.Key, out var value))
            {
                AppendSection(builder, $"{customField.Value} ({customField.Key})", GetFlexibleValueText(value));
            }
        }

        await AppendCommentsAsync(builder, key, cancellationToken);

        await onChange(new SimpleRemoteFile(
            issueId,
            $"{key}.txt",
            $"atlassian://{_siteUri.Host}/jira/{_projectKey}/{key}.txt",
            issueUrl,
            builder.ToString()));

        if (!fields.TryGetProperty("attachment", out var attachments) || attachments.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var attachment in attachments.EnumerateArray())
        {
            var id = AtlassianConnector.GetScalarString(attachment, "id");
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            var name = AtlassianConnector.GetScalarString(attachment, "filename") ?? id;
            var downloadUri = new Uri(_api.BaseUri, $"rest/api/3/attachment/content/{Uri.EscapeDataString(id)}");
            var size = attachment.TryGetProperty("size", out var sizeElement) && sizeElement.TryGetInt64(out var parsedSize)
                ? (long?)parsedSize
                : null;
            await onChange(new SimpleRemoteFile(
                id,
                name,
                $"atlassian://{_siteUri.Host}/jira/{_projectKey}/{key}/attachments/{name}",
                issueUrl,
                size,
                AtlassianConnector.GetScalarString(attachment, "mimeType"),
                _api.HttpClient,
                downloadUri));
        }
    }

    private async Task AppendCommentsAsync(StringBuilder builder, string issueKey, CancellationToken cancellationToken)
    {
        var startAt = 0;
        while (true)
        {
            using var document = await _api.GetJsonAsync(
                $"rest/api/3/issue/{Uri.EscapeDataString(issueKey)}/comment?startAt={startAt}&maxResults=100",
                cancellationToken);
            var root = document.RootElement;
            if (!root.TryGetProperty("comments", out var comments) || comments.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            var returned = 0;
            foreach (var comment in comments.EnumerateArray())
            {
                returned++;
                var author = GetNestedString(comment, "author", "displayName");
                var body = GetDocumentText(comment, "body");
                AppendSection(builder, string.IsNullOrWhiteSpace(author) ? "Comment" : $"Comment by {author}", body);
            }

            var total = root.TryGetProperty("total", out var totalElement) && totalElement.TryGetInt32(out var parsedTotal)
                ? parsedTotal
                : startAt + returned;
            startAt += returned;
            if (returned == 0 || startAt >= total)
            {
                return;
            }
        }
    }

    private string BuildJql(string? updatedTimestamp)
    {
        var clauses = new List<string> { $"project = \"{_projectKey.Replace("\"", "\\\"", StringComparison.Ordinal)}\"" };
        if (!string.IsNullOrWhiteSpace(_additionalJql))
        {
            clauses.Add($"({_additionalJql})");
        }

        if (DateTimeOffset.TryParse(updatedTimestamp, out var updated))
        {
            clauses.Add($"updated >= \"{updated.UtcDateTime:yyyy-MM-dd HH:mm}\"");
        }

        return string.Join(" AND ", clauses) + " ORDER BY updated DESC";
    }

    private string? GetDeltaTimestamp(string? deltaToken)
        => GetResumeState(deltaToken).Boundary;

    private JiraResumeState GetResumeState(string? deltaToken)
    {
        if (string.IsNullOrWhiteSpace(deltaToken))
        {
            return default;
        }

        try
        {
            using var document = JsonDocument.Parse(deltaToken);
            var root = document.RootElement;
            var filter = AtlassianConnector.GetScalarString(root, "filter");
            var updated = AtlassianConnector.GetScalarString(root, "updated");
            var nextPageToken = AtlassianConnector.GetScalarString(root, "nextPageToken");
            if (!string.Equals(filter, _filterHash, StringComparison.Ordinal)
                || (string.IsNullOrWhiteSpace(nextPageToken) && !DateTimeOffset.TryParse(updated, out _)))
            {
                return default;
            }

            var newest = AtlassianConnector.GetScalarString(root, "newest");
            var started = AtlassianConnector.GetScalarString(root, "startedAt");
            return new JiraResumeState(
                updated,
                nextPageToken,
                DateTimeOffset.TryParse(newest, out _) ? newest : updated,
                DateTimeOffset.TryParse(started, out var parsedStarted) ? parsedStarted : null);
        }
        catch (JsonException)
        {
            return _additionalJql == null && DateTimeOffset.TryParse(deltaToken, out _)
                ? new JiraResumeState(deltaToken, null, deltaToken, null)
                : default;
        }
    }

    private string CreatePageCheckpoint(
        string? boundary,
        string nextPageToken,
        string? newest,
        DateTimeOffset scanStartedAt)
    {
        return new System.Text.Json.Nodes.JsonObject
        {
            ["version"] = 2,
            ["filter"] = _filterHash,
            ["updated"] = boundary,
            ["nextPageToken"] = nextPageToken,
            ["newest"] = newest,
            ["startedAt"] = scanStartedAt.ToUniversalTime().ToString("O")
        }.ToJsonString();
    }

    private string CreateDeltaToken(string updated)
    {
        return new System.Text.Json.Nodes.JsonObject
        {
            ["version"] = 1,
            ["filter"] = _filterHash,
            ["updated"] = updated
        }.ToJsonString();
    }

    internal static string GetDocumentText(JsonElement container, string propertyName)
    {
        if (!container.TryGetProperty(propertyName, out var value) || value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return string.Empty;
        }

        if (value.ValueKind == JsonValueKind.String)
        {
            return value.GetString() ?? string.Empty;
        }

        var parts = new List<string>();
        CollectDocumentText(value, parts);
        return string.Join(Environment.NewLine, parts.Where(part => !string.IsNullOrWhiteSpace(part)));
    }

    internal static string GetFlexibleValueText(JsonElement value)
    {
        var parts = new List<string>();
        CollectFlexibleText(value, parts);
        return string.Join(Environment.NewLine, parts.Where(part => !string.IsNullOrWhiteSpace(part)).Distinct(StringComparer.Ordinal));
    }

    private static void CollectDocumentText(JsonElement element, List<string> parts)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            if (element.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String)
            {
                parts.Add(text.GetString() ?? string.Empty);
            }

            foreach (var property in element.EnumerateObject())
            {
                if (!property.NameEquals("text"))
                {
                    CollectDocumentText(property.Value, parts);
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                CollectDocumentText(item, parts);
            }
        }
    }

    private static void CollectFlexibleText(JsonElement element, List<string> parts)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                parts.Add(element.GetString() ?? string.Empty);
                break;
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
                parts.Add(element.GetRawText());
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    CollectFlexibleText(item, parts);
                }
                break;
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (!IgnoredCustomMetadataProperties.Contains(property.Name))
                    {
                        CollectFlexibleText(property.Value, parts);
                    }
                }
                break;
        }
    }

    private static string? GetString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static string? GetNestedString(JsonElement element, string propertyName, string nestedPropertyName)
    {
        return element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.Object
            ? GetString(value, nestedPropertyName)
            : null;
    }

    private static string GetStringArray(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.Array
            ? string.Join(", ", value.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String).Select(item => item.GetString()))
            : string.Empty;
    }

    private static void AppendLine(StringBuilder builder, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            builder.Append(label).Append(": ").AppendLine(value);
        }
    }

    private static void AppendSection(StringBuilder builder, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            builder.AppendLine().AppendLine(label + ":").AppendLine(value);
        }
    }

    private static string? MaxIsoTimestamp(string? left, string? right)
    {
        if (!DateTimeOffset.TryParse(right, out var rightValue))
        {
            return left;
        }

        return !DateTimeOffset.TryParse(left, out var leftValue) || rightValue > leftValue
            ? rightValue.ToString("O")
            : left;
    }

    private static string ComputeFilterHash(string? jql)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(jql?.Trim() ?? string.Empty)));
    }

    private readonly record struct JiraResumeState(
        string? Boundary,
        string? NextPageToken,
        string? NewestUpdated,
        DateTimeOffset? ScanStartedAt);
}
