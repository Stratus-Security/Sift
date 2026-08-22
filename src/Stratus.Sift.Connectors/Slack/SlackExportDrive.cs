using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.Slack;

internal sealed class SlackExportDrive : IRemoteDrive
{
    private readonly SlackExportSource? _source;
    private readonly string[] _entries;
    private readonly string? _filesRoot;
    private readonly SlackExportDriveKind _kind;
    private readonly string _exportName;

    private SlackExportDrive(SlackExportSource? source, string exportName, string id, string name, SlackExportDriveKind kind, string[] entries, string? filesRoot)
    {
        _source = source;
        _exportName = exportName;
        Id = id;
        Name = name;
        _kind = kind;
        _entries = entries;
        _filesRoot = filesRoot;
    }

    public string Id { get; }
    public string Name { get; }
    public string ConnectionId => $"slack-export://{Uri.EscapeDataString(_exportName)}/{Uri.EscapeDataString(Id)}";
    public string WebUrl => string.Empty;
    public DatastoreType DriveType => DatastoreType.Slack;
    public long? TotalSize => null;
    public long? UsedSize => null;

    internal static SlackExportDrive ForMetadata(SlackExportSource source, string[] entries)
        => new(source, source.DisplayName, "metadata", "Workspace metadata", SlackExportDriveKind.Metadata, entries, null);

    internal static SlackExportDrive ForConversation(SlackExportSource source, string conversation, string[] entries)
        => new(source, source.DisplayName, conversation, conversation, SlackExportDriveKind.Conversation, entries, null);

    internal static SlackExportDrive ForFiles(string exportName, string filesRoot)
        => new(null, exportName, "downloaded-files", "Downloaded Slack files", SlackExportDriveKind.Files, [], filesRoot);

    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? deltaToken, CancellationToken cancellationToken = default)
    {
        var changes = new List<IRemoteFile>();
        await ProcessChangesAsync(deltaToken, item => { changes.Add(item); return Task.CompletedTask; }, null, cancellationToken);
        return (changes, string.Empty);
    }

    public async Task<string> ProcessChangesAsync(string? deltaToken, Func<IRemoteFile, Task> onChange, Func<string, Task>? onCheckpoint = null, CancellationToken cancellationToken = default)
    {
        if (_kind == SlackExportDriveKind.Files)
        {
            await EmitLocalFilesAsync(onChange, cancellationToken);
            return string.Empty;
        }

        foreach (var entry in _entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_kind == SlackExportDriveKind.Metadata)
            {
                var content = await _source!.ReadTextAsync(entry, cancellationToken);
                await onChange(new SimpleRemoteFile(StableId(entry), Path.GetFileName(entry), BuildPath(entry), string.Empty, content, "application/json"));
                continue;
            }

            JsonDocument document;
            try
            {
                document = await _source!.ReadJsonAsync(entry, cancellationToken);
            }
            catch (JsonException)
            {
                var content = await _source!.ReadTextAsync(entry, cancellationToken);
                await onChange(new SimpleRemoteFile(StableId(entry), Path.GetFileName(entry), BuildPath(entry), string.Empty, content, "application/json"));
                continue;
            }

            using (document)
            {
                if (document.RootElement.ValueKind != JsonValueKind.Array)
                {
                    await onChange(new SimpleRemoteFile(StableId(entry), Path.GetFileName(entry), BuildPath(entry), string.Empty, document.RootElement.GetRawText(), "application/json"));
                    continue;
                }

                var index = 0;
                foreach (var message in document.RootElement.EnumerateArray())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (message.ValueKind != JsonValueKind.Object) continue;
                    var timestamp = GetString(message, "ts") ?? index.ToString(System.Globalization.CultureInfo.InvariantCulture);
                    var name = $"message-{SanitizeSegment(timestamp)}.txt";
                    var path = BuildPath($"{Path.GetFileNameWithoutExtension(entry)}/{name}");
                    await onChange(new SimpleRemoteFile(
                        StableId(entry + "|" + index + "|" + timestamp),
                        name,
                        path,
                        GetString(message, "permalink") ?? string.Empty,
                        BuildMessageContent(message),
                        "text/plain"));
                    index++;
                }
            }
        }

        return string.Empty;
    }

    private async Task EmitLocalFilesAsync(Func<IRemoteFile, Task> onChange, CancellationToken cancellationToken)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true };
        foreach (var filePath in Directory.EnumerateFiles(_filesRoot!, "*", options))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relative = Path.GetRelativePath(_filesRoot!, filePath);
            await onChange(new SimpleRemoteFile(
                StableId(relative),
                Path.GetFileName(filePath),
                BuildPath("files/" + relative.Replace('\\', '/')),
                string.Empty,
                new FileInfo(filePath)));
        }
    }

    private string BuildPath(string relative) => $"slack-export://{_exportName}/{Id}/{relative.Replace('\\', '/')}";

    private static string BuildMessageContent(JsonElement message)
    {
        var builder = new StringBuilder();
        Append(builder, "User", GetString(message, "user") ?? GetString(message, "username"));
        Append(builder, "Timestamp", GetString(message, "ts"));
        Append(builder, "Thread", GetString(message, "thread_ts"));
        Append(builder, "Type", GetString(message, "type"));
        Append(builder, "Subtype", GetString(message, "subtype"));
        var text = SlackDrive.ExtractMessageText(message);
        if (!string.IsNullOrWhiteSpace(text)) builder.AppendLine().AppendLine(text);

        if (message.TryGetProperty("files", out var files) && files.ValueKind == JsonValueKind.Array)
        {
            foreach (var file in files.EnumerateArray())
            {
                builder.AppendLine().AppendLine("File:");
                Append(builder, "  Name", GetString(file, "name") ?? GetString(file, "title"));
                Append(builder, "  Type", GetString(file, "mimetype") ?? GetString(file, "filetype"));
                Append(builder, "  URL", GetString(file, "url_private_download") ?? GetString(file, "url_private"));
            }
        }

        return builder.ToString();
    }

    private static void Append(StringBuilder builder, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) builder.Append(label).Append(": ").AppendLine(value);
    }

    private static string? GetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string StableId(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..32];

    private static string SanitizeSegment(string value)
    {
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        return string.Concat(value.Select(ch => invalid.Contains(ch) || ch is '/' or '\\' ? '-' : ch));
    }

    private enum SlackExportDriveKind { Metadata, Conversation, Files }
}
