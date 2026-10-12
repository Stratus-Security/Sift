using Microsoft.Graph;
using Microsoft.Graph.Models;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

// Search supplements direct enumeration; it must never be treated as an authoritative inventory.
internal sealed class Microsoft365SharedSearchDrive(GraphServiceClient client, string tenant,
    Microsoft365CoverageOptions coverage) : IRemoteDrive
{
    public string Id => "accessible-file-search";
    public string Name => "Accessible and shared files (search index)";
    public string ConnectionId => $"sharepoint-search://{tenant}/accessible-files";
    public string WebUrl => "";
    public DatastoreType DriveType => DatastoreType.OneDrive;
    public long? TotalSize => null;
    public long? UsedSize => null;
    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken cancellationToken = default)
    {
        var files = new List<IRemoteFile>();
        await ProcessChangesAsync(token, item => { files.Add(item); return Task.CompletedTask; }, cancellationToken: cancellationToken);
        return (files, string.Empty);
    }
    public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint = null, CancellationToken cancellationToken = default)
    {
        var reader = new Microsoft365GraphReader(client);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var failures = 0;
        const int pageSize = 500;
        for (var page = 0; page < Microsoft365CoverageOptions.MaxPages; page++)
        {
            using var document = await reader.PostAsync("search/query",
                "{\"requests\":[{\"entityTypes\":[\"driveItem\"],\"query\":{\"queryString\":\"*\"},\"from\":"
                + (page * pageSize) + ",\"size\":" + pageSize + "}]}", cancellationToken);
            if (!document.RootElement.TryGetProperty("value", out var values)) throw new InvalidDataException("Search response has no results.");
            var more = false;
            var added = 0;
            foreach (var response in values.EnumerateArray())
            {
                if (!response.TryGetProperty("hitsContainers", out var containers)) throw new InvalidDataException("Search response has no hit containers.");
                foreach (var container in containers.EnumerateArray())
                {
                    more |= container.TryGetProperty("moreResultsAvailable", out var hasMore) && hasMore.ValueKind == System.Text.Json.JsonValueKind.True;
                    if (!container.TryGetProperty("hits", out var hits)) continue;
                    foreach (var hit in hits.EnumerateArray())
                    {
                        if (seen.Count >= 1_000_000) throw new InvalidDataException("Accessible-file search exceeded its item limit.");
                        try
                        {
                            if (!hit.TryGetProperty("resource", out var resource) || !resource.TryGetProperty("parentReference", out var parent))
                                throw new InvalidDataException("Search result cannot be resolved to a drive item.");
                            var drive = String(parent, "driveId") ?? throw new InvalidDataException("Search result has no drive ID.");
                            var id = Microsoft365GraphReader.Id(resource);
                            if (!seen.Add(drive + ":" + id)) continue;
                            added++;
                            if (seen.Count > 1_000_000) throw new InvalidDataException("Accessible-file search exceeded its item limit.");
                            // Fetch authoritative metadata, not the index's stale size or eTag.
                            var item = await client.Drives[drive].Items[id].GetAsync(cancellationToken: cancellationToken)
                                ?? throw new InvalidDataException("Search result item could not be read.");
                            await onChange(new SharePointFile(client, drive, item, tenant, false, coverage));
                        }
                        catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested)) { failures++; }
                    }
                }
            }
            if (!more)
            {
                if (failures > 0) throw new InvalidDataException($"{failures} indexed files could not be resolved.");
                return string.Empty;
            }
            if (added == 0) throw new InvalidDataException("Accessible-file search repeated a page without making progress.");
        }
        throw new InvalidDataException("Accessible-file search exceeded its page limit.");
    }
}
