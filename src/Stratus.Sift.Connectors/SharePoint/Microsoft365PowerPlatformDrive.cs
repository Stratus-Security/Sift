using Azure.Core;
using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class Microsoft365PowerPlatformDrive(TokenCredential credential, string tenant, Microsoft365WorkloadOptions options,
    Func<Uri, string[], Microsoft365ServiceReader>? createReader = null)
    : Microsoft365WorkloadDrive(tenant, "powerplatform", DatastoreType.Dynamics, options.MaxItems)
{
    private Microsoft365ServiceReader Api(Uri root, string[] scopes) => createReader?.Invoke(root, scopes) ?? new(credential, root, scopes);
    public override string WebUrl => "https://make.powerapps.com/";
    protected override async Task ReadAsync(Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        var urls = options.DataverseUrls.ToList();
        if (urls.Count == 0)
        {
            using var discovery = Api(new("https://globaldisco.crm.dynamics.com/api/discovery/v2.0/"),
                ["https://globaldisco.crm.dynamics.com/.default"]);
            await foreach (var instance in discovery.Enumerate("Instances", ct))
            {
                var value = String(instance, "Url") ?? String(instance, "ApiUrl") ?? throw new InvalidDataException("Dataverse instance has no URL.");
                var candidate = new Uri(value);
                var parsed = Microsoft365WorkloadOptions.Parse(new Dictionary<string, string> { ["DataverseUrl"] = candidate.GetLeftPart(UriPartial.Authority) });
                urls.Add(parsed.DataverseUrls.Single());
                if (urls.Count > MaxItems) throw new InvalidDataException("Dataverse environment inventory exceeded MaxWorkloadItems.");
            }
        }
        foreach (var url in urls.DistinctBy(uri => uri.Host, StringComparer.OrdinalIgnoreCase))
            await Attempt(url.AbsoluteUri, async () =>
            {
                using var api = Api(new(url, "/api/data/v9.2/"), [url.GetLeftPart(UriPartial.Authority) + "/.default"]);
                foreach (var collection in new[]
                {
                    "workflows?$select=workflowid,name,description,clientdata,category&$filter=category eq 5",
                    "canvasapps?$select=canvasappid,name,displayname,description,modifiedon,document,document_name",
                    "appmodules?$select=appmoduleid,name,description",
                    "environmentvariabledefinitions?$select=environmentvariabledefinitionid,schemaname,displayname,defaultvalue,description",
                    "environmentvariablevalues?$select=environmentvariablevalueid,value"
                })
                    await Attempt(url.AbsoluteUri + collection, async () =>
                    {
                        await foreach (var item in api.Enumerate(collection, ct))
                        {
                            var kind = collection.Split('?')[0];
                            var field = kind switch { "workflows" => "workflowid", "canvasapps" => "canvasappid", "appmodules" => "appmoduleid",
                                "environmentvariabledefinitions" => "environmentvariabledefinitionid", _ => "environmentvariablevalueid" };
                            var id = String(item, field) ?? throw new InvalidDataException("Dataverse item has no ID.");
                            var key = url.Host + ":" + kind + ":" + id;
                            var text = SearchableText(item);
                            if (String(item, "clientdata") is { Length: > 0 } data)
                            {
                                using var definition = JsonDocument.Parse(data);
                                text += "\n" + SearchableText(definition.RootElement);
                            }
                            await Emit(Microsoft365ContentFile.Text("powerplatform:" + key, id + "." + kind + ".json", Link(url.AbsoluteUri, id), text), emit, ct);
                            if (kind == "canvasapps" && (!item.TryGetProperty("document", out var fileColumn) || fileColumn.ValueKind != JsonValueKind.Null))
                                await Attempt(url.AbsoluteUri + "/canvasapps/" + id, async () =>
                                {
                                    if (!Guid.TryParse(id, out var appId)) throw new InvalidDataException("Canvas app record ID was not a GUID.");
                                    // Document is a File column. Download lazily into the scanner's
                                    // bounded archive pipeline, using a client owned by that stream.
                                    var apiRoot = api.Root;
                                    var scopes = new[] { url.GetLeftPart(UriPartial.Authority) + "/.default" };
                                    await Emit(new Microsoft365ContentFile("powerplatform:package:" + key, id + ".msapp", Link(url.AbsoluteUri, id),
                                        String(item, "@odata.etag") ?? String(item, "modifiedon"), null,
                                        async (_, token) => await Api(apiRoot, scopes).OpenOwned(new(apiRoot, "canvasapps(" + appId + ")/document/$value"), token)), emit, ct);
                                }, ct);
                        }
                    }, ct);
            }, ct);
    }
}
