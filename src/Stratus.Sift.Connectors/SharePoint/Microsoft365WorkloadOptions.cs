namespace Stratus.Sift.Connectors.SharePoint;

internal sealed record Microsoft365WorkloadOptions
{
    internal IReadOnlySet<string> Enabled { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    internal IReadOnlyList<string> SharedMailboxes { get; init; } = [];
    internal IReadOnlyList<string> UserIds { get; init; } = [];
    internal IReadOnlyList<string> GroupIds { get; init; } = [];
    internal IReadOnlyList<string> TeamIds { get; init; } = [];
    internal IReadOnlyList<string> ChatIds { get; init; } = [];
    internal IReadOnlyList<string> PlanIds { get; init; } = [];
    internal IReadOnlyList<string> OneNoteSites { get; init; } = [];
    internal IReadOnlyList<string> ContainerTypes { get; init; } = [];
    internal IReadOnlyList<string> ContainerIds { get; init; } = [];
    internal IReadOnlyList<Uri> DataverseUrls { get; init; } = [];
    internal bool IncludePersonalTasks { get; init; }
    internal bool ScanStorage { get; init; } = true;
    internal bool RequestAdditionalPermissions { get; init; }
    internal int MaxItems { get; init; } = 1_000_000;
    internal bool Has(string workload) => Enabled.Contains(workload);
    internal static readonly string[] Names = ["teams", "planner", "todo", "onenote", "sharedmail", "embedded", "engage", "powerbi", "powerplatform"];

    internal static Microsoft365WorkloadOptions Parse(IReadOnlyDictionary<string, string> config)
    {
        string? Get(string key) => config.FirstOrDefault(pair => pair.Key.Equals(key, StringComparison.OrdinalIgnoreCase)).Value;
        string[] Values(string key) => (Get(key) ?? "").Split([',', ';', '\r', '\n'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var enabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(Get("Workloads"))) enabled.UnionWith(Names);
        foreach (var name in Values("Workloads"))
        {
            if (name.Equals("all", StringComparison.OrdinalIgnoreCase)) enabled.UnionWith(Names);
            else if (name.Equals("storage", StringComparison.OrdinalIgnoreCase)) { }
            else if (Names.Contains(name, StringComparer.OrdinalIgnoreCase)) enabled.Add(name.ToLowerInvariant());
            else throw new ArgumentException($"Unknown M365 workload '{name}'. Use storage, all, or {string.Join(", ", Names)}.");
        }
        var max = 1_000_000;
        foreach (var name in Values("ExcludeWorkloads"))
        {
            if (!Names.Contains(name, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException($"Unknown excluded M365 workload '{name}'.");
            enabled.Remove(name);
        }
        var consent = false;
        if (Get("RequestAdditionalPermissions") is { } permissionValue && !bool.TryParse(permissionValue, out consent))
            throw new ArgumentException("RequestAdditionalPermissions must be true or false.");
        if (Get("MaxWorkloadItems") is { } raw && (!int.TryParse(raw, out max) || max < 1 || max > 10_000_000))
            throw new ArgumentException("MaxWorkloadItems must be between 1 and 10000000.");
        var personal = true;
        if (Get("IncludePersonalTasks") is { } tasks && !bool.TryParse(tasks, out personal))
            throw new ArgumentException("IncludePersonalTasks must be true or false.");
        var storage = true;
        if (Get("ScanStorage") is { } storageValue && !bool.TryParse(storageValue, out storage))
            throw new ArgumentException("ScanStorage must be true or false.");
        if (!storage && enabled.Count == 0) throw new ArgumentException("ScanStorage=false requires at least one selected Workloads source.");
        var types = Values("EmbeddedContainerTypeId");
        if (types.Any(value => !Guid.TryParse(value, out _))) throw new ArgumentException("EmbeddedContainerTypeId must contain GUIDs.");
        var environments = Values("DataverseUrl").Select(value =>
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || !uri.IsDefaultPort
                || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.AbsolutePath.Trim('/') != ""
                || !new[] { ".dynamics.com", ".dynamics.cn", ".microsoftdynamics.us", ".crm.appsplatform.us" }
                    .Any(suffix => uri.Host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException("DataverseUrl must be an HTTPS Dynamics environment origin, without a path or credentials.");
            return uri;
        }).ToArray();
        return new()
        {
            Enabled = enabled, RequestAdditionalPermissions = consent, SharedMailboxes = Values("SharedMailbox"), UserIds = Values("WorkloadUserId"),
            GroupIds = Values("WorkloadGroupId"), TeamIds = Values("WorkloadTeamId"), ChatIds = Values("WorkloadChatId"),
            PlanIds = Values("PlannerPlanId"), OneNoteSites = Values("OneNoteSiteId"), ContainerTypes = types,
            ContainerIds = Values("EmbeddedContainerId"), DataverseUrls = environments, IncludePersonalTasks = personal, ScanStorage = storage, MaxItems = max
        };
    }

    internal IEnumerable<string> DelegatedScopes()
    {
        if (Has("teams") || Has("planner")) { yield return "Files.Read.All"; yield return "Sites.Read.All"; }
        if (Has("teams")) { yield return "Chat.Read"; yield return "ChannelMessage.Read.All"; yield return "Team.ReadBasic.All"; yield return "Channel.ReadBasic.All"; yield return "Group.Read.All"; }
        if (Has("planner")) { yield return "Tasks.Read"; yield return "Group.Read.All"; }
        if (Has("todo")) yield return "Tasks.Read";
        if (Has("onenote")) { yield return "Notes.Read.All"; yield return "Group.Read.All"; }
        if (Has("sharedmail") && SharedMailboxes.Count > 0) { yield return "Mail.Read.Shared"; yield return "User.Read.All"; }
        if (Has("embedded")) yield return "FileStorageContainer.Selected";
    }
}
