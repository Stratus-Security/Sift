using Microsoft.Graph;
using Microsoft.Graph.Models;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class Microsoft365EmbeddedDrive(GraphServiceClient client, string tenant, Microsoft365WorkloadOptions options, Microsoft365CoverageOptions coverage)
    : Microsoft365WorkloadDrive(tenant, "embedded", DatastoreType.SharePoint, options.MaxItems)
{
    public override string WebUrl => "https://graph.microsoft.com/v1.0/storage/fileStorage/containers";
    protected override async Task ReadAsync(Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        var graph = new Microsoft365GraphReader(client);
        var ids = new HashSet<string>(options.ContainerIds, StringComparer.Ordinal);
        foreach (var type in options.ContainerTypes)
            await Attempt("Embedded container type " + type, async () =>
            {
                await foreach (var container in graph.EnumerateAsync("storage/fileStorage/containers?$filter=containerTypeId eq " + type, ct))
                {
                    if (ids.Add(Id(container)) && ids.Count > options.MaxItems)
                        throw new InvalidDataException("Embedded container inventory exceeded MaxWorkloadItems.");
                    await Emit(Microsoft365ContentFile.Text("embedded:container:" + Id(container), Id(container) + ".container.json",
                        Link(WebUrl, Id(container)), SearchableText(container)), emit, ct);
                }
            }, ct);
        if (options.ContainerTypes.Count == 0 && ids.Count == 0)
            throw new InvalidDataException("Embedded scanning needs EmbeddedContainerTypeId or EmbeddedContainerId and permission grants for those containers.");
        foreach (var id in ids)
            await Attempt("Embedded container " + id, async () =>
            {
                using var value = await graph.GetAsync("storage/fileStorage/containers/" + Segment(id) + "/drive", ct);
                var model = value.RootElement;
                var drive = new SharePointDrive(client, new Drive { Id = Id(model), Name = String(model, "name"), WebUrl = String(model, "webUrl") },
                    Tenant, DatastoreType.SharePoint, coverage with { ScanLibraryFields = false, NativeClient = null });
                await drive.ProcessChangesAsync(null, file => Emit(file, emit, ct), cancellationToken: ct);
            }, ct);
    }
}
