using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class Microsoft365PowerBIDrive(Microsoft365ServiceReader api, string tenant, int maxItems)
    : Microsoft365WorkloadDrive(tenant, "powerbi", DatastoreType.PowerBI, maxItems), IDisposable
{
    public void Dispose() => api.Dispose();
    public override string WebUrl => "https://app.powerbi.com/";
    protected override async Task ReadAsync(Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        // Workspaces use offset paging, not OData nextLink. Other inventory
        // endpoints return full value arrays or an explicit continuation.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var offset = 0; offset < MaxItems; offset += 1000)
        {
            using var page = await api.Get("groups?$top=1000&$skip=" + offset, ct);
            if (!page.RootElement.TryGetProperty("value", out var groups) || groups.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Power BI workspace response has no value array.");
            foreach (var group in groups.EnumerateArray())
            {
                var id = Id(group);
                if (!seen.Add(id)) throw new InvalidDataException("Power BI workspace paging repeated a workspace.");
                await Json("workspace:" + id, group, emit, ct);
                await Attempt("Power BI workspace " + id, () => Workspace(id, emit, ct), ct);
            }
            if (groups.GetArrayLength() < 1000) return;
        }
        throw new InvalidDataException("Power BI workspace inventory exceeded MaxWorkloadItems.");
    }
    private async Task Workspace(string group, Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        var root = "groups/" + Segment(group) + "/";
        foreach (var collection in new[] { "reports", "dashboards", "datasets", "dataflows" })
            await Attempt(root + collection, async () =>
            {
                await foreach (var item in api.Enumerate(root + collection, ct))
                {
                    var id = collection == "dataflows" ? String(item, "objectId") ?? Id(item) : Id(item);
                    await Json(group + ":" + collection + ":" + id, item, emit, ct);
                    if (collection == "datasets")
                        foreach (var child in new[] { "parameters", "datasources" })
                            await Attempt(root + collection + "/" + id + "/" + child, async () =>
                            {
                                using var details = await api.Get(root + "datasets/" + Segment(id) + "/" + child, ct);
                                await Json(group + ":dataset:" + id + ":" + child, details.RootElement, emit, ct);
                            }, ct);
                    if (collection == "dataflows")
                        await Attempt(root + collection + "/" + id, async () =>
                        {
                            using var definition = await api.Get(root + "dataflows/" + Segment(id), ct);
                            await Json(group + ":dataflow-definition:" + id, definition.RootElement, emit, ct);
                        }, ct);
                    if (collection == "dashboards")
                        await Attempt(root + collection + "/" + id + "/tiles", async () =>
                        {
                            using var tiles = await api.Get(root + "dashboards/" + Segment(id) + "/tiles", ct);
                            await Json(group + ":dashboard:" + id + ":tiles", tiles.RootElement, emit, ct);
                        }, ct);
                }
            }, ct);
    }
    private Task Json(string key, JsonElement value, Func<IRemoteFile, Task> emit, CancellationToken ct)
        => Emit(Microsoft365ContentFile.Text("powerbi:" + key, key.Replace(':', '-') + ".json",
            String(value, "webUrl") ?? Link(WebUrl, key), SearchableText(value)), emit, ct);
}
