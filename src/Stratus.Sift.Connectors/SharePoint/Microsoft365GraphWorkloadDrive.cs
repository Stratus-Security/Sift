using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed partial class Microsoft365GraphWorkloadDrive(Microsoft365GraphReader graph, string tenant, string workload,
    Microsoft365WorkloadOptions options, bool appOnly)
    : Microsoft365WorkloadDrive(tenant, workload, workload switch
    {
        "sharedmail" => DatastoreType.Exchange, "planner" => DatastoreType.Planner,
        "todo" => DatastoreType.ToDo, "onenote" => DatastoreType.OneNote, _ => DatastoreType.Teams
    }, options.MaxItems)
{
    public override string WebUrl => Workload switch
    {
        "sharedmail" => "https://outlook.office.com/mail/", "onenote" => "https://www.onenote.com/",
        "planner" => "https://planner.cloud.microsoft/", "todo" => "https://to-do.office.com/", _ => "https://teams.microsoft.com/"
    };
    private readonly HashSet<string> _roots = new(StringComparer.Ordinal);
    protected override async Task ReadAsync(Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        _roots.Clear();
        _referenceLibraries.Clear();
        switch (Workload)
        {
            case "teams": await ReadTeams(emit, ct); break;
            case "planner": await ReadPlanner(emit, ct); break;
            case "todo": await ReadToDo(emit, ct); break;
            case "onenote": await ReadOneNote(emit, ct); break;
            case "sharedmail": await ReadSharedMail(emit, ct); break;
            default: throw new InvalidDataException("Unsupported Graph workload.");
        }
    }
    private Task Json(string key, string name, JsonElement value, Func<IRemoteFile, Task> emit, CancellationToken ct, string? url = null, bool complete = true)
        => Emit(Microsoft365ContentFile.Text(Workload + ":" + key, name + ".json", url ?? Link(WebUrl, key),
            SearchableText(value), complete), emit, ct);

    private async Task Users(Func<string, Task> read, CancellationToken ct)
    {
        if (options.UserIds.Count > 0)
        {
            if (options.UserIds.Count > MaxItems) throw new InvalidDataException("Workload user inventory exceeded MaxWorkloadItems.");
            foreach (var id in options.UserIds) await Attempt("users/" + id, () => read("users/" + Segment(id)), ct);
        }
        else if (!appOnly) await Attempt("me", () => read("me"), ct);
        else
        {
            var users = 0;
            await foreach (var user in graph.EnumerateAsync("users?$select=id&$top=999", ct))
            {
                if (++users > MaxItems) throw new InvalidDataException("Workload user inventory exceeded MaxWorkloadItems.");
                await Attempt("users/" + Id(user), () => read("users/" + Segment(Id(user))), ct);
            }
        }
    }
    private async Task Groups(Func<string, Task> read, CancellationToken ct)
    {
        if (options.GroupIds.Count > 0)
        {
            foreach (var id in options.GroupIds) await Attempt("groups/" + id, () => read(id), ct);
            return;
        }
        var path = appOnly ? "groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id&$top=999"
            : "me/memberOf/microsoft.graph.group?$select=id,groupTypes&$top=999";
        var count = 0;
        await foreach (var group in graph.EnumerateAsync(path, ct))
        {
            if (++count > MaxItems) throw new InvalidDataException("Workload group inventory exceeded MaxWorkloadItems.");
            if (!appOnly && (!group.TryGetProperty("groupTypes", out var types) || !types.EnumerateArray().Any(type => type.GetString() == "Unified"))) continue;
            await Attempt("groups/" + Id(group), () => read(Id(group)), ct);
        }
    }
    private async Task ReadTeams(Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        var teams = options.TeamIds.ToList();
        if (teams.Count == 0)
            await Attempt("Teams discovery", async () =>
            {
                var path = appOnly ? "teams?$select=id,displayName&$top=100" : "me/joinedTeams?$select=id,displayName";
                await foreach (var team in graph.EnumerateAsync(path, ct))
                {
                    if (teams.Count >= MaxItems) throw new InvalidDataException("Teams inventory exceeded MaxWorkloadItems.");
                    teams.Add(Id(team));
                }
            }, ct);
        foreach (var team in teams.Distinct(StringComparer.Ordinal))
            await Attempt("teams/" + team, async () =>
            {
                await foreach (var channel in graph.EnumerateAsync($"teams/{Segment(team)}/allChannels?$select=id,displayName,membershipType,tenantId", ct))
                {
                    var channelId = Id(channel);
                    await Attempt($"teams/{team}/{channelId}", async () =>
                    {
                        var reference = String(channel, "@odata.id");
                        var root = $"teams/{Segment(team)}/channels/{Segment(channelId)}/messages";
                        if (reference != null)
                        {
                            if (!Uri.TryCreate(reference, UriKind.Absolute, out var canonical) || !SameOrigin(canonical, graph.Root))
                                throw new InvalidDataException("Teams channel reference changed service origin.");
                            // Microsoft's documented shared-channel workaround removes
                            // the tenant segment, retaining the owning team and channel.
                            var path = CollectionPath(canonical);
                            var prefix = graph.Root.AbsolutePath.TrimEnd('/') + "/";
                            if (!path.StartsWith(prefix, StringComparison.Ordinal))
                                throw new InvalidDataException("Teams channel reference changed API version.");
                            path = path[prefix.Length..];
                            var parts = path.Split('/');
                            if (parts.Length == 6 && parts[0] == "tenants") path = string.Join("/", parts.Skip(2));
                            parts = path.Split('/');
                            if (parts.Length != 4 || parts[0] != "teams" || parts[2] != "channels")
                                throw new InvalidDataException("Teams channel reference is not a channel URL.");
                            root = graph.Url(path).AbsoluteUri + "/messages";
                        }
                        if (!_roots.Add("channel:" + CollectionPath(graph.Url(root)))) return;
                        await foreach (var message in graph.EnumerateAsync(root + "?$top=50", ct))
                        {
                            var id = Id(message);
                            await Message($"channel:{team}:{channelId}:{id}", root + "/" + Segment(id), message, emit, ct);
                            // Replies have their own pages; the root-message collection is insufficient.
                            await Attempt(root + "/" + id + "/replies", async () =>
                            {
                                await foreach (var reply in graph.EnumerateAsync(root + "/" + Segment(id) + "/replies?$top=50", ct))
                                    await Message($"channel:{team}:{channelId}:{Id(reply)}", root + "/" + Segment(id) + "/replies/" + Segment(Id(reply)), reply, emit, ct);
                            }, ct);
                        }
                    }, ct);
                }
            }, ct);

        async Task Chat(string id)
        {
            if (!_roots.Add("chat:" + id)) return;
            await foreach (var message in graph.EnumerateAsync($"chats/{Segment(id)}/messages?$top=50", ct))
                await Message($"chat:{id}:{Id(message)}", $"chats/{Segment(id)}/messages/{Segment(Id(message))}", message, emit, ct);
        }
        if (options.ChatIds.Count > 0)
            foreach (var id in options.ChatIds) await Attempt("chats/" + id, () => Chat(id), ct);
        else await Users(async user =>
        {
            await foreach (var chat in graph.EnumerateAsync(user + "/chats?$top=50", ct))
                await Attempt("chats/" + Id(chat), () => Chat(Id(chat)), ct);
        }, ct);
    }
    private async Task Message(string key, string path, JsonElement message, Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        await Json(key, Id(message) + ".message", message, emit, ct, String(message, "webUrl"));
        if (message.TryGetProperty("attachments", out var attachments) && attachments.ValueKind == JsonValueKind.Array)
            foreach (var attachment in attachments.EnumerateArray())
                if (String(attachment, "contentType") == "reference" && String(attachment, "contentUrl") is { } url)
                    await Attempt(url, () => ReferenceAttachment(key, attachment, url, emit, ct), ct);
        if (message.TryGetProperty("body", out var body) && (String(body, "content") ?? "").Contains("hostedContents", StringComparison.OrdinalIgnoreCase))
            await Attempt(path + "/hostedContents", async () =>
            {
                await foreach (var resource in graph.EnumerateAsync(path + "/hostedContents", ct))
                {
                    var resourceId = Id(resource);
                    var contentPath = path + "/hostedContents/" + Segment(resourceId);
                    using var metadata = await graph.GetAsync(contentPath, ct);
                    var mime = String(metadata.RootElement, "contentType");
                    await Emit(new Microsoft365ContentFile("teams:hosted:" + key + ":" + resourceId, resourceId + Extension(mime),
                        String(message, "webUrl") ?? Link(WebUrl, key), String(message, "lastModifiedDateTime"), null,
                        async (_, token) => await graph.OpenAsync(graph.Url(contentPath + "/$value"), token)), emit, ct);
                }
            }, ct);
    }
    private async Task ReferenceAttachment(string parent, JsonElement attachment, string url, Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        // Resolve a file reference once. Do not follow arbitrary web links, redirects or a folder tree.
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "https" || !Microsoft365Cloud.IsSharePointHost(uri.Host))
            throw new InvalidDataException("Attachment reference is not a SharePoint/OneDrive file URL.");
        var sharingId = "u!" + Convert.ToBase64String(Encoding.UTF8.GetBytes(url)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        using var document = await ResolveReference(uri, sharingId, ct);
        var item = document.RootElement;
        if (item.TryGetProperty("folder", out _) || item.TryGetProperty("remoteItem", out _))
            throw new InvalidDataException("Attachment references a folder or unresolved shortcut; its backing storage must be scanned separately.");
        var drive = item.TryGetProperty("parentReference", out var reference) ? String(reference, "driveId") : null;
        if (drive == null) throw new InvalidDataException("Attachment has no backing drive.");
        var id = Id(item);
        var name = String(item, "name") ?? String(attachment, "name") ?? "attachment.bin";
        long? size = item.TryGetProperty("size", out var bytes) && bytes.TryGetInt64(out var n) ? n : null;
        var converted = Microsoft365ContentProjection.Supports(name);
        var version = String(item, "eTag") ?? String(item, "cTag");
        await Emit(new Microsoft365ContentFile($"{Workload}:attachment:{drive}:{id}", name, String(item, "webUrl") ?? url,
            version == null ? null : version + (converted ? Microsoft365ContentProjection.VersionSuffix : ""), converted ? null : size,
            async (range, token) => converted ? await graph.ProjectContentAsync(drive, id, token)
                : await graph.OpenAsync(graph.Url($"drives/{Segment(drive)}/items/{Segment(id)}/content"), token, range))
            { ContentName = converted ? name + ".html" : name }, emit, ct);
    }
    private async Task ReadPlanner(Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        async Task Plan(string id)
        {
            if (!_roots.Add("plan:" + id)) return;
            using var metadata = await graph.GetAsync("planner/plans/" + Segment(id), ct);
            await Json("plan:" + id, id + ".plan", metadata.RootElement, emit, ct);
            await Attempt("planner plan details " + id, async () =>
            {
                using var details = await graph.GetAsync($"planner/plans/{Segment(id)}/details", ct);
                await Json("plan-details:" + id, id + ".plan-details", details.RootElement, emit, ct);
            }, ct);
            await foreach (var task in graph.EnumerateAsync($"planner/plans/{Segment(id)}/tasks", ct))
            {
                var taskId = Id(task);
                await Json("task:" + taskId, taskId + ".task", task, emit, ct);
                await Attempt("planner task details " + taskId, async () =>
                {
                    using var details = await graph.GetAsync($"planner/tasks/{Segment(taskId)}/details", ct);
                    await Json("task-details:" + taskId, taskId + ".task-details", details.RootElement, emit, ct);
                    if (details.RootElement.TryGetProperty("references", out var refs))
                        foreach (var property in refs.EnumerateObject())
                        {
                            var url = DecodePlannerReference(property.Name);
                            if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && Microsoft365Cloud.IsSharePointHost(uri.Host))
                                await Attempt(url, () => ReferenceAttachment("task:" + taskId, property.Value, url, emit, ct), ct);
                        }
                }, ct);
            }
        }
        if (options.PlanIds.Count > 0)
            foreach (var id in options.PlanIds) await Attempt("planner/plans/" + id, () => Plan(id), ct);
        else await Groups(async group =>
        {
            await foreach (var plan in graph.EnumerateAsync($"groups/{Segment(group)}/planner/plans", ct))
                await Attempt("planner/plans/" + Id(plan), () => Plan(Id(plan)), ct);
        }, ct);
    }
    internal static string DecodePlannerReference(string value)
        => Uri.UnescapeDataString(value);

    private async Task ReadToDo(Func<IRemoteFile, Task> emit, CancellationToken ct)
        => await Users(async user =>
        {
            await foreach (var list in graph.EnumerateAsync(user + "/todo/lists?$top=100", ct))
            {
                if (!options.IncludePersonalTasks)
                {
                    if (!list.TryGetProperty("isShared", out var shared) || shared.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    {
                        Record(user + "/todo/lists", new InvalidDataException("To Do list sharing state was unavailable; it was not assumed to be a personal list."));
                        continue;
                    }
                    if (shared.ValueKind == JsonValueKind.False) continue;
                }
                var listId = Id(list);
                var prefix = user + "/todo/lists/" + Segment(listId);
                await Json(user + ":list:" + listId, listId + ".task-list", list, emit, ct);
                await Attempt(prefix, async () =>
                {
                    await foreach (var task in graph.EnumerateAsync(prefix + "/tasks?$top=100", ct))
                    {
                        var taskId = Id(task);
                        var key = user + ":" + listId + ":" + taskId;
                        await Json(key, taskId + ".task", task, emit, ct);
                        await Attempt(prefix + "/tasks/" + taskId + "/attachments", () => Attachments(prefix + "/tasks/" + Segment(taskId), key, false, emit, ct), ct);
                        await Attempt(prefix + "/tasks/" + taskId + "/linkedResources", async () =>
                        {
                            await foreach (var link in graph.EnumerateAsync(prefix + "/tasks/" + Segment(taskId) + "/linkedResources", ct))
                                await Json(key + ":link:" + Id(link), taskId + ".linked-resource", link, emit, ct);
                        }, ct);
                    }
                }, ct);
            }
        }, ct);
}
