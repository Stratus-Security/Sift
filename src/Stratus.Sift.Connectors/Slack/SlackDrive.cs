using System.Text;
using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.Slack;

public sealed class SlackDrive : IRemoteDrive
{
    private readonly HttpClient _client;
    private readonly SlackConnector _connector;
    private readonly string _workspaceId;
    private readonly string _workspaceName;
    private readonly string _workspaceUrl;

    internal SlackDrive(
        HttpClient client,
        SlackConnector connector,
        string workspaceId,
        string workspaceName,
        string workspaceUrl,
        string channelId,
        string channelName)
    {
        _client = client;
        _connector = connector;
        _workspaceId = workspaceId;
        _workspaceName = workspaceName;
        _workspaceUrl = workspaceUrl.TrimEnd('/');
        Id = channelId;
        Name = channelName;
    }

    public string Id { get; }
    public string Name { get; }
    public string ConnectionId => $"slack://{_workspaceId}/{Id}";
    public string WebUrl => $"{_workspaceUrl}/archives/{Id}";
    public DatastoreType DriveType => DatastoreType.Slack;
    public long? TotalSize => null;
    public long? UsedSize => null;

    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? deltaToken, CancellationToken cancellationToken = default)
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
        var resume = ParseCheckpoint(deltaToken);
        var boundary = resume.Boundary;
        var cursor = resume.Cursor;
        var newestTimestamp = resume.Newest ?? boundary;
        var threadParents = resume.ThreadParents.ToList();
        var seenThreadParents = threadParents.ToHashSet(StringComparer.Ordinal);

        if (!resume.RepliesPhase)
        {
            do
            {
                using var document = await _connector.GetSlackDocumentAsync(
                    "conversations.history",
                    new Dictionary<string, string?>
                    {
                        ["channel"] = Id,
                        ["limit"] = "15",
                        ["cursor"] = cursor
                    },
                    cancellationToken);

                foreach (var message in document.RootElement.GetProperty("messages").EnumerateArray())
                {
                    var timestamp = message.GetProperty("ts").GetString() ?? string.Empty;
                    newestTimestamp = MaxSlackTimestamp(newestTimestamp, timestamp);
                    var editedTimestamp = GetNestedTimestamp(message, "edited", "ts");
                    newestTimestamp = MaxSlackTimestamp(newestTimestamp, editedTimestamp);
                    if (string.IsNullOrWhiteSpace(boundary)
                        || IsAfter(timestamp, boundary)
                        || IsAfter(editedTimestamp, boundary))
                    {
                        await EmitMessageAsync(message, onChange);
                    }

                    if (message.TryGetProperty("reply_count", out var replyCount) && replyCount.GetInt32() > 0)
                    {
                        var latestReply = message.TryGetProperty("latest_reply", out var latestReplyElement)
                            ? latestReplyElement.GetString()
                            : null;
                        if (string.IsNullOrWhiteSpace(boundary) || IsAfter(latestReply, boundary))
                        {
                            newestTimestamp = MaxSlackTimestamp(newestTimestamp, latestReply);
                            if (!string.IsNullOrWhiteSpace(timestamp) && seenThreadParents.Add(timestamp))
                            {
                                threadParents.Add(timestamp);
                            }
                        }
                    }
                }

                cursor = SlackConnector.GetNextCursor(document.RootElement);
                if (onCheckpoint != null)
                {
                    await onCheckpoint(CreateCheckpoint(
                        boundary,
                        cursor,
                        newestTimestamp,
                        repliesPhase: string.IsNullOrWhiteSpace(cursor),
                        threadParents));
                }
            }
            while (!string.IsNullOrWhiteSpace(cursor));
        }

        while (threadParents.Count > 0)
        {
            var parentTimestamp = threadParents[0];
            newestTimestamp = MaxSlackTimestamp(
                newestTimestamp,
                await EmitRepliesAsync(parentTimestamp, boundary, onChange, cancellationToken));
            threadParents.RemoveAt(0);
            if (onCheckpoint != null)
            {
                await onCheckpoint(CreateCheckpoint(boundary, null, newestTimestamp, repliesPhase: true, threadParents));
            }
        }

        return newestTimestamp ?? string.Empty;
    }

    internal static string CreateCheckpoint(
        string? boundary,
        string? cursor,
        string? newest,
        bool repliesPhase,
        IReadOnlyCollection<string> threadParents)
        => $"sift-slack-v3:{Encode(boundary)}.{Encode(cursor)}.{Encode(newest)}.{(repliesPhase ? "r" : "h")}.{string.Join(',', threadParents.Select(Encode))}";

    internal static SlackResumeState ParseCheckpoint(string? token)
    {
        const string prefix = "sift-slack-v3:";
        if (string.IsNullOrWhiteSpace(token))
        {
            return new SlackResumeState(null, null, null, false, []);
        }

        if (!token.StartsWith(prefix, StringComparison.Ordinal))
        {
            return new SlackResumeState(token, null, token, false, []);
        }

        var parts = token[prefix.Length..].Split('.', 5);
        if (parts.Length != 5)
        {
            return new SlackResumeState(null, null, null, false, []);
        }

        var parents = parts[4]
            .Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(Decode)
            .Where(value => value != null)
            .Cast<string>()
            .ToArray();
        return new SlackResumeState(
            Decode(parts[0]),
            Decode(parts[1]),
            Decode(parts[2]),
            parts[3] == "r",
            parents);
    }

    private static string Encode(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string? Decode(string value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        try
        {
            var normalized = value.Replace('-', '+').Replace('_', '/');
            normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
            return Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
        }
        catch (FormatException)
        {
            return null;
        }
    }

    internal readonly record struct SlackResumeState(
        string? Boundary,
        string? Cursor,
        string? Newest,
        bool RepliesPhase,
        IReadOnlyList<string> ThreadParents);

    private async Task<string?> EmitRepliesAsync(
        string parentTimestamp,
        string? deltaToken,
        Func<IRemoteFile, Task> onChange,
        CancellationToken cancellationToken)
    {
        string? cursor = null;
        string? newestTimestamp = deltaToken;
        do
        {
            using var document = await _connector.GetSlackDocumentAsync(
                "conversations.replies",
                new Dictionary<string, string?>
                {
                    ["channel"] = Id,
                    ["ts"] = parentTimestamp,
                    ["limit"] = "15",
                    ["oldest"] = deltaToken,
                    ["cursor"] = cursor
                },
                cancellationToken);
            foreach (var reply in document.RootElement.GetProperty("messages").EnumerateArray())
            {
                var timestamp = reply.GetProperty("ts").GetString() ?? string.Empty;
                newestTimestamp = MaxSlackTimestamp(newestTimestamp, timestamp);
                newestTimestamp = MaxSlackTimestamp(newestTimestamp, GetNestedTimestamp(reply, "edited", "ts"));
                if (!timestamp.Equals(parentTimestamp, StringComparison.Ordinal))
                {
                    await EmitMessageAsync(reply, onChange);
                }
            }

            cursor = SlackConnector.GetNextCursor(document.RootElement);
        }
        while (!string.IsNullOrWhiteSpace(cursor));

        return newestTimestamp;
    }

    private async Task EmitMessageAsync(JsonElement message, Func<IRemoteFile, Task> onChange)
    {
        var timestamp = message.GetProperty("ts").GetString() ?? Guid.NewGuid().ToString("N");
        var user = message.TryGetProperty("user", out var userElement) ? userElement.GetString() : null;
        var text = ExtractMessageText(message);
        var permalink = $"{WebUrl}/p{timestamp.Replace(".", string.Empty, StringComparison.Ordinal)}";
        var messageName = $"message-{timestamp.Replace('.', '-')}.txt";
        var content = $"Workspace: {_workspaceName}{Environment.NewLine}Channel: {Name}{Environment.NewLine}User: {user}{Environment.NewLine}Timestamp: {timestamp}{Environment.NewLine}{Environment.NewLine}{text}";
        await onChange(new SimpleRemoteFile(
            $"{Id}:{timestamp}",
            messageName,
            $"slack://{_workspaceName}/{Name}/{messageName}",
            permalink,
            content));

        if (!message.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var file in files.EnumerateArray())
        {
            var fileId = file.TryGetProperty("id", out var idElement) ? idElement.GetString() ?? Guid.NewGuid().ToString("N") : Guid.NewGuid().ToString("N");
            var fileName = file.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? fileId : fileId;
            var downloadUrl = file.TryGetProperty("url_private_download", out var downloadElement) ? downloadElement.GetString() : null;
            if (string.IsNullOrWhiteSpace(downloadUrl) || !Uri.TryCreate(downloadUrl, UriKind.Absolute, out var downloadUri))
            {
                continue;
            }

            if (downloadUri.Scheme != Uri.UriSchemeHttps
                || !(downloadUri.Host.Equals("slack.com", StringComparison.OrdinalIgnoreCase)
                     || downloadUri.Host.EndsWith(".slack.com", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var size = file.TryGetProperty("size", out var sizeElement) && sizeElement.TryGetInt64(out var parsedSize) ? (long?)parsedSize : null;
            var contentType = file.TryGetProperty("mimetype", out var mimeElement) ? mimeElement.GetString() : null;
            var fileUrl = file.TryGetProperty("permalink", out var permalinkElement) ? permalinkElement.GetString() ?? permalink : permalink;
            await onChange(new SimpleRemoteFile(
                fileId,
                fileName,
                $"slack://{_workspaceName}/{Name}/attachments/{fileName}",
                fileUrl,
                size,
                contentType,
                _client,
                downloadUri));
        }
    }

    private static string? MaxSlackTimestamp(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(right))
        {
            return left;
        }

        if (string.IsNullOrWhiteSpace(left))
        {
            return right;
        }

        return decimal.TryParse(left, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var leftValue)
            && decimal.TryParse(right, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var rightValue)
            && rightValue > leftValue
                ? right
                : left;
    }

    private static bool IsAfter(string? candidate, string? boundary)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(boundary))
        {
            return true;
        }

        return decimal.TryParse(candidate, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var candidateValue)
            && decimal.TryParse(boundary, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var boundaryValue)
            && candidateValue > boundaryValue;
    }

    private static string? GetNestedTimestamp(JsonElement element, string propertyName, string nestedPropertyName)
    {
        return element.TryGetProperty(propertyName, out var nested)
            && nested.ValueKind == JsonValueKind.Object
            && nested.TryGetProperty(nestedPropertyName, out var value)
            && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
    }

    public static string ExtractMessageText(JsonElement message)
    {
        var values = new List<string>();
        if (message.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String)
        {
            values.Add(text.GetString() ?? string.Empty);
        }

        if (message.TryGetProperty("blocks", out var blocks))
        {
            CollectText(blocks, values);
        }

        if (message.TryGetProperty("attachments", out var attachments) && attachments.ValueKind == JsonValueKind.Array)
        {
            foreach (var attachment in attachments.EnumerateArray())
            {
                CollectAttachmentText(attachment, values);
            }
        }

        return string.Join(Environment.NewLine, values.Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.Ordinal));
    }

    private static void CollectAttachmentText(JsonElement attachment, List<string> values)
    {
        if (attachment.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var propertyName in new[] { "pretext", "title", "text", "fallback", "author_name", "footer" })
        {
            if (attachment.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String)
            {
                values.Add(value.GetString() ?? string.Empty);
            }
        }

        if (attachment.TryGetProperty("fields", out var fields) && fields.ValueKind == JsonValueKind.Array)
        {
            foreach (var field in fields.EnumerateArray())
            {
                foreach (var propertyName in new[] { "title", "value" })
                {
                    if (field.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String)
                    {
                        values.Add(value.GetString() ?? string.Empty);
                    }
                }
            }
        }
    }

    private static void CollectText(JsonElement element, List<string> values)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("text") && property.Value.ValueKind == JsonValueKind.String)
                {
                    values.Add(property.Value.GetString() ?? string.Empty);
                }
                else
                {
                    CollectText(property.Value, values);
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                CollectText(item, values);
            }
        }
    }
}
