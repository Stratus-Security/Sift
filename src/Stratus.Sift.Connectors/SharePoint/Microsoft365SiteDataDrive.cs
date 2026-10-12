using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class Microsoft365SiteDataDrive(Microsoft365GraphReader? graph, SharePointRestClient? rest,
    string tenant, string siteId, Uri siteUrl, Microsoft365CoverageOptions options) : IRemoteDrive
{
    public string Id => "site-data:" + siteId;
    public string Name => siteUrl.AbsolutePath + " (lists, pages and recycle bin)";
    public string ConnectionId => $"sharepoint-data://{tenant}/{Uri.EscapeDataString(siteId)}";
    public string WebUrl => siteUrl.AbsoluteUri;
    public DatastoreType DriveType => DatastoreType.SharePoint;
    public long? TotalSize => null;
    public long? UsedSize => null;

    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken cancellationToken = default)
    {
        var files = new List<IRemoteFile>();
        await ProcessChangesAsync(token, file => { files.Add(file); return Task.CompletedTask; }, cancellationToken: cancellationToken);
        return (files, string.Empty);
    }

    public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint = null, CancellationToken cancellationToken = default)
    {
        var failures = new List<Exception>();
        async Task Attempt(Func<Task> action)
        {
            try { await action(); }
            catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
            { if (failures.Count < 1000) failures.Add(ex); }
        }
        if (options.ScanListsAndPages)
        {
            if (graph != null)
            {
                await Attempt(async () =>
                {
                    await foreach (var list in graph.EnumerateAsync($"sites/{Segment(siteId)}/lists?$select=id,displayName,webUrl,list&$top=200", cancellationToken))
                    {
                        var listId = Microsoft365GraphReader.Id(list);
                        var url = String(list, "webUrl") ?? siteUrl.AbsoluteUri;
                        // File libraries supply their fields through their drive items.
                        if (list.TryGetProperty("list", out var facet) && String(facet, "template") is "documentLibrary" or "pictureLibrary") continue;
                        await Attempt(async () =>
                        {
                            await foreach (var item in graph.EnumerateAsync($"sites/{Segment(siteId)}/lists/{Segment(listId)}/items?$expand=fields&$top=200", cancellationToken))
                            {
                                var itemId = Microsoft365GraphReader.Id(item);
                                if (!item.TryGetProperty("fields", out var fields)) throw new InvalidDataException("List item had no fields.");
                                await onChange(Microsoft365ContentFile.Text($"{siteId}:list:{listId}:{itemId}", $"list-{listId}-item-{itemId}.json",
                                    String(item, "webUrl") ?? url + "?ID=" + Uri.EscapeDataString(itemId), SearchableText(fields))
                                    .WithInspection(Inspection($"web/lists('{SharePointRestClient.ResourcePath(listId)}')/items({Microsoft365NativeAccessReader.ValidatedNumber(itemId)})")));
                                if (fields.TryGetProperty("Attachments", out var hasAttachments) && hasAttachments.ValueKind == JsonValueKind.True)
                                {
                                    if (rest == null) throw new InvalidDataException("List attachments require SharePoint-native access.");
                                    await Attempt(() => ReadAttachmentsAsync(rest, listId, itemId, onChange, cancellationToken));
                                }
                            }
                        });
                    }
                });
                await Attempt(async () =>
                {
                    await foreach (var page in graph.EnumerateAsync($"sites/{Segment(siteId)}/pages/microsoft.graph.sitePage?$select=id,name,webUrl&$top=200", cancellationToken))
                        await Attempt(async () =>
                        {
                            var id = Microsoft365GraphReader.Id(page);
                            using var content = await graph.GetAsync($"sites/{Segment(siteId)}/pages/{Segment(id)}/microsoft.graph.sitePage?$expand=canvasLayout", cancellationToken);
                            if (!content.RootElement.TryGetProperty("canvasLayout", out _)) throw new InvalidDataException("Modern page had no canvas content.");
                            var pageUrl = new Uri(String(page, "webUrl") ?? throw new InvalidDataException("Page had no URL."));
                            await onChange(Microsoft365ContentFile.Text($"{siteId}:page:{id}", (String(page, "name") ?? id) + ".page.json",
                                pageUrl.AbsoluteUri + "#sift-page-content", SearchableText(content.RootElement))
                                .WithInspection(Inspection($"web/GetFileByServerRelativePath(decodedurl='{SharePointRestClient.ResourcePath(Uri.UnescapeDataString(pageUrl.AbsolutePath))}')/ListItemAllFields")));
                        });
                });
            }
            else if (rest != null) await Attempt(() => ReadNativeListsAsync(rest, onChange, ex => { if (failures.Count < 1000) failures.Add(ex); }, cancellationToken));
        }
        if (options.ScanRecycleBin)
        {
            if (rest == null) failures.Add(new InvalidDataException("Recycle-bin inventory requires SharePoint-native access."));
            else await Attempt(async () =>
            {
                await foreach (var recycled in rest.EnumerateJsonAsync(SharePointRestClient.Api(siteUrl, "site/RecycleBin?$top=200"), cancellationToken))
                {
                    var id = String(recycled, "Id") ?? throw new InvalidDataException("Recycled item had no ID.");
                    var dir = String(recycled, "DirName") ?? string.Empty;
                    // A subsite target must not widen its scope to unrelated recycled content.
                    var scope = siteUrl.AbsolutePath.TrimEnd('/');
                    if (scope.Length > 0 && !("/" + dir.TrimStart('/')).StartsWith(scope + "/", StringComparison.OrdinalIgnoreCase)) continue;
                    var name = String(recycled, "LeafName") ?? id;
                    await onChange(Microsoft365ContentFile.Text($"{siteId}:recycled:{id}", name + ".recycled.json",
                        siteUrl.AbsoluteUri.TrimEnd('/') + "/_layouts/15/RecycleBin.aspx#sift-item=" + Uri.EscapeDataString(id),
                        SearchableText(recycled), complete: false));
                }
            });
        }
        if (failures.Count > 0) throw new AggregateException("Some SharePoint site content could not be enumerated.", failures);
        return string.Empty;
    }

    private async Task ReadAttachmentsAsync(SharePointRestClient client, string listId, string itemId,
        Func<IRemoteFile, Task> onChange, CancellationToken cancellationToken)
    {
        if (!long.TryParse(itemId, out var numericId) || numericId <= 0) throw new InvalidDataException("List item attachment ID is invalid.");
        var path = $"web/lists('{SharePointRestClient.ResourcePath(listId)}')/items({numericId})/AttachmentFiles?$top=200";
        await foreach (var attachment in client.EnumerateJsonAsync(SharePointRestClient.Api(siteUrl, path), cancellationToken))
        {
            var name = String(attachment, "FileName") ?? throw new InvalidDataException("Attachment had no filename.");
            var relative = String(attachment, "ServerRelativeUrl") ?? throw new InvalidDataException("Attachment had no path.");
            var url = SharePointRestClient.BuildWebUrl(siteUrl, relative).AbsoluteUri;
            await onChange(new Microsoft365ContentFile($"{siteId}:{listId}:{itemId}:attachment:{relative}", name, url, null, null,
                (range, ct) => client.OpenFileContentAsync(siteUrl, relative, range, ct))
                .WithInspection(Inspection($"web/lists('{SharePointRestClient.ResourcePath(listId)}')/items({numericId})")));
        }
    }

    private async Task ReadNativeListsAsync(SharePointRestClient client, Func<IRemoteFile, Task> onChange, Action<Exception> onFailure, CancellationToken cancellationToken)
    {
        await foreach (var list in client.EnumerateJsonAsync(SharePointRestClient.Api(siteUrl, "web/lists?$select=Id,Title,BaseType&$top=200"), cancellationToken))
        {
            try
            {
                // Libraries supply their fields and attachments through their
                // file-backed drives, matching the Graph site's list reader.
                if (String(list, "BaseType") == "1") continue;
                var listId = String(list, "Id") ?? throw new InvalidDataException("List had no ID.");
                var path = $"web/lists('{SharePointRestClient.ResourcePath(listId)}')/items?$top=200";
                await foreach (var item in client.EnumerateJsonAsync(SharePointRestClient.Api(siteUrl, path), cancellationToken))
                {
                    var id = String(item, "Id") ?? throw new InvalidDataException("List item had no ID.");
                    await onChange(Microsoft365ContentFile.Text($"{siteId}:list:{listId}:{id}", $"list-{listId}-item-{id}.json",
                        siteUrl.AbsoluteUri.TrimEnd('/') + $"/_layouts/15/listform.aspx?PageType=4&ListId={Uri.EscapeDataString(listId)}&ID={Uri.EscapeDataString(id)}", SearchableText(item))
                        .WithInspection(Inspection($"web/lists('{SharePointRestClient.ResourcePath(listId)}')/items({Microsoft365NativeAccessReader.ValidatedNumber(id)})")));
                    if (item.TryGetProperty("Attachments", out var attachments) && attachments.ValueKind == JsonValueKind.True)
                        await ReadAttachmentsAsync(client, listId, id, onChange, cancellationToken);
                }
            }
            catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested)) { onFailure(ex); }
        }
    }

    private Func<CancellationToken, Task<Microsoft365Access>>? Inspection(string resource)
        => !options.ReadSharing ? null : rest == null
            ? _ => Task.FromException<Microsoft365Access>(new InvalidDataException("SharePoint item permissions require native access."))
            : ct => Microsoft365NativeAccessReader.ReadAsync(rest, siteUrl, resource, options, ct);
}
