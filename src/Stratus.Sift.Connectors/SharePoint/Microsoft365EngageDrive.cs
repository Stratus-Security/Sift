using System.Globalization;
using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class Microsoft365EngageDrive(Microsoft365ServiceReader api, string tenant, int maxItems)
    : Microsoft365WorkloadDrive(tenant, "engage", DatastoreType.VivaEngage, maxItems), IDisposable
{
    public void Dispose() => api.Dispose();
    public override string WebUrl => "https://www.yammer.com/";
    protected override async Task ReadAsync(Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        var groups = new HashSet<string>(StringComparer.Ordinal);
        for (var page = 1; page <= Microsoft365CoverageOptions.MaxPages; page++)
        {
            using var json = await api.Get("groups.json?page=" + page, ct);
            if (json.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Engage group response has no array.");
            if (json.RootElement.GetArrayLength() == 0) return;
            foreach (var group in json.RootElement.EnumerateArray())
            {
                var id = Id(group);
                if (!groups.Add(id)) throw new InvalidDataException("Engage group paging repeated a community.");
                if (groups.Count > MaxItems) throw new InvalidDataException("Engage community inventory exceeded MaxWorkloadItems.");
                await Emit(Microsoft365ContentFile.Text("engage:community:" + id, id + ".community.json", Link(WebUrl, id), SearchableText(group)), emit, ct);
                await Attempt("Engage community " + id, () => Messages(id, emit, ct), ct);
            }
        }
        throw new InvalidDataException("Engage community inventory exceeded its page limit.");
    }
    private async Task Messages(string group, Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        ulong? cursor = null;
        var visited = new HashSet<string>(StringComparer.Ordinal);
        for (var page = 0; page < Microsoft365CoverageOptions.MaxPages; page++)
        {
            var path = "messages/in_group/" + Segment(group) + ".json?threaded=false"
                + (cursor.HasValue ? "&older_than=" + cursor.Value.ToString(CultureInfo.InvariantCulture) : "");
            using var json = await api.Get(path, ct);
            if (!json.RootElement.TryGetProperty("messages", out var messages) || messages.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Engage feed has no messages array.");
            if (messages.GetArrayLength() == 0) return;
            ulong oldest = ulong.MaxValue;
            foreach (var message in messages.EnumerateArray())
            {
                var id = Id(message);
                if (!ulong.TryParse(id, CultureInfo.InvariantCulture, out var numeric) || !visited.Add(id))
                    throw new InvalidDataException("Engage feed returned an invalid or repeated message ID.");
                oldest = Math.Min(oldest, numeric);
                await Emit(Microsoft365ContentFile.Text("engage:message:" + id, id + ".message.json",
                    String(message, "web_url") ?? Link(WebUrl, id), SearchableText(message)), emit, ct);
                if (message.TryGetProperty("attachments", out var attachments) && attachments.ValueKind == JsonValueKind.Array)
                    foreach (var attachment in attachments.EnumerateArray())
                    {
                        var key = id + ":" + Id(attachment);
                        var name = String(attachment, "name") ?? "attachment.bin";
                        if (String(attachment, "download_url") is not { } download || !Uri.TryCreate(download, UriKind.Absolute, out var uri)
                            || !Microsoft365GraphWorkloadDrive.SameOrigin(uri, api.Root))
                        {
                            await Emit(Microsoft365ContentFile.Text("engage:attachment:" + key, name + ".attachment.json",
                                Link(WebUrl, key), SearchableText(attachment), complete: false), emit, ct);
                            Record(Link(WebUrl, key), new InvalidDataException("Engage attachment requires a separate storage download; its metadata was retained."));
                        }
                        else
                        {
                            long? size = attachment.TryGetProperty("size", out var bytes) && bytes.TryGetInt64(out var n) ? n : null;
                            await Emit(new Microsoft365ContentFile("engage:attachment:" + key, name, String(attachment, "web_url") ?? Link(WebUrl, key),
                                String(attachment, "last_modified_at"), size, async (_, token) => await api.Open(uri, token)), emit, ct);
                        }
                    }
            }
            if (cursor.HasValue && oldest >= cursor.Value) throw new InvalidDataException("Engage feed did not advance its older_than cursor.");
            cursor = oldest;
            if (json.RootElement.TryGetProperty("meta", out var meta) && meta.TryGetProperty("older_available", out var older) && older.ValueKind == JsonValueKind.False) return;
        }
        throw new InvalidDataException("Engage message collection exceeded its page limit.");
    }
}
