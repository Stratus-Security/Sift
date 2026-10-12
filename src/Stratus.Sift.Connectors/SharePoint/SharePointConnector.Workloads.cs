using Azure.Core;
using Stratus.Sift.Connectors.Interfaces;

namespace Stratus.Sift.Connectors.SharePoint;

public partial class SharePointConnector
{
    private Microsoft365WorkloadOptions _workloads = new();
    private TokenCredential? _workloadCredential;
    private bool _workloadAppOnly;
    private string[] _workloadAuthenticationScopes = [];
    private readonly Dictionary<string, List<string>> _unavailableWorkloads = new(StringComparer.Ordinal);
    private void WorkloadUnavailable(string workload, string reason)
    {
        if (!_unavailableWorkloads.TryGetValue(reason, out var names)) _unavailableWorkloads[reason] = names = [];
        names.Add(workload);
        _discoveryComplete = false;
        AddDiscoveryCount("unavailable workloads", 1);
    }

    private async Task AuthenticateWorkloadDiscovery(CancellationToken ct)
    {
        // Storage discovery normally acquires a token before the CLI creates its
        // resume journal. Workload-only discovery must establish the same principal
        // and tenant identity, even though it does not enumerate any storage yet.
        if (_workloadAppOnly || _workloadCredential == null) return;
        var scopes = _workloadAuthenticationScopes;
        if (_graphClient == null)
        {
            scopes = _workloads.Has("powerbi") ? ["https://analysis.windows.net/powerbi/api/.default"]
                : _workloads.Has("engage") ? ["https://www.yammer.com/.default"]
                : _workloads.Has("powerplatform") ? [(_workloads.DataverseUrls.FirstOrDefault()?.GetLeftPart(UriPartial.Authority)
                    ?? "https://globaldisco.crm.dynamics.com") + "/.default"] : [];
        }
        if (scopes.Length > 0)
        {
            var token = await _workloadCredential.GetTokenAsync(new TokenRequestContext(scopes), ct);
            UpdateDelegatedCheckpointScope(token.Token);
        }
    }

    private void AddWorkloadDrives(List<IRemoteDrive> drives)
    {
        _unavailableWorkloads.Clear();
        foreach (var name in _workloads.Enabled)
        {
            if (name is "teams" or "planner" or "todo" or "onenote" or "sharedmail" or "embedded")
            {
                if (_graphClient == null) { WorkloadUnavailable(name, "Graph access is unavailable with this sign-in"); continue; }
                if (name == "sharedmail" && _workloads.SharedMailboxes.Count == 0)
                { WorkloadUnavailable(name, "SharedMailbox targets are needed"); continue; }
                if (name == "onenote" && _workloadAppOnly)
                { WorkloadUnavailable(name, "delegated access is needed"); continue; }
                if (name == "embedded" && _workloads.ContainerIds.Count == 0 && _workloads.ContainerTypes.Count == 0)
                { WorkloadUnavailable(name, "container targets/access grants are needed"); continue; }
                drives.Add(name == "embedded" ? new Microsoft365EmbeddedDrive(_graphClient, _tenantId, _workloads, _coverage)
                    : new Microsoft365GraphWorkloadDrive(new(_graphClient), _tenantId, name, _workloads, _workloadAppOnly));
            }
            else
            {
                if (_workloadCredential == null || _cloud.GraphRoot.Host != "graph.microsoft.com")
                { WorkloadUnavailable(name, "an available Worldwide credential is needed"); continue; }
                if (name == "powerbi")
                    drives.Add(new Microsoft365PowerBIDrive(new(_workloadCredential, new("https://api.powerbi.com/v1.0/myorg/"),
                        ["https://analysis.windows.net/powerbi/api/.default"]), _tenantId, _workloads.MaxItems));
                if (name == "powerplatform") drives.Add(new Microsoft365PowerPlatformDrive(_workloadCredential, _tenantId, _workloads));
                if (name == "engage")
                    drives.Add(new Microsoft365EngageDrive(new(_workloadCredential, new("https://www.yammer.com/api/v1/"),
                        ["https://www.yammer.com/.default"]), _tenantId, _workloads.MaxItems));
            }
        }
        if (_workloads.Enabled.Count > 0)
        {
            AddDiscoveryCount("workload sources", drives.Count(drive => drive is Microsoft365WorkloadDrive));
        }
    }
}
