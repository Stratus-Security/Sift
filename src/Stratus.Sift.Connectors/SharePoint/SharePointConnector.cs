using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Abstractions;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using System.Text.Json;

namespace Stratus.Sift.Connectors.SharePoint;

public class SharePointConnector : IConnector, IConnectorDiscoveryReportProvider, IConnectorCheckpointScopeProvider
{
    private const int MaxConcurrentSiteRequests = 6;
    private const string DefaultInteractiveRedirectUri = "http://localhost";
    private const string ProductPrefix = "StratusSiftConnector.SharePoint";
    private static readonly string[] DefaultDelegatedScopes = ["Sites.Read.All", "Team.ReadBasic.All", "Channel.ReadBasic.All"];

    private static readonly HashSet<string> SystemLibraries = new(StringComparer.OrdinalIgnoreCase)
    {
        "Style Library",
        "Form Templates",
        "Site Assets",
        "Preservation Hold Library",
        "MicroFeed",
        "Pages",
        "Site Pages",
        "TaxonomyHiddenList",
        "Taxonomy Hidden List",
        "Master Page Gallery",
        "PersonalCacheLibrary"
    };

    private static readonly string[] SiteSelectFields = ["id", "name", "webUrl", "displayName"];
    private static readonly string[] DriveSelectFields = ["id", "name", "webUrl"];

    private GraphServiceClient? _graphClient;
    private SharePointRestClient? _sharePointRestClient;
    private Uri? _sharePointRestRootUrl;
    private string _tenantId = string.Empty;
    private string _checkpointScope = string.Empty;
    private readonly ILogger<SharePointConnector>? _logger;
    private readonly ThrottleNotificationHub? _throttleNotifications;
    private readonly List<Uri> _configuredSiteTargets = [];
    private readonly List<string> _configuredDriveIds = [];
    private bool _useConfiguredTargets;
    private bool _discoverTeamsChannels;
    private bool _discoverFollowedLocations;
    private readonly Dictionary<string, int> _discoverySourceCounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _discoveryWarnings = [];

    public ConnectorDiscoveryReport DiscoveryReport { get; private set; } = ConnectorDiscoveryReport.Empty;

    public SharePointConnector(ILogger<SharePointConnector>? logger = null, ThrottleNotificationHub? throttleNotifications = null)
    {
        _logger = logger;
        _throttleNotifications = throttleNotifications;
    }

    internal SharePointConnector(
        GraphServiceClient graphClient,
        string tenantId,
        ILogger<SharePointConnector>? logger = null,
        ThrottleNotificationHub? throttleNotifications = null,
        bool useConfiguredTargets = false,
        IEnumerable<Uri>? configuredSiteTargets = null,
        IEnumerable<string>? configuredDriveIds = null,
        bool discoverTeamsChannels = false,
        bool discoverFollowedLocations = false)
    {
        _graphClient = graphClient;
        _tenantId = tenantId;
        _logger = logger;
        _throttleNotifications = throttleNotifications;
        _useConfiguredTargets = useConfiguredTargets;
        _discoverTeamsChannels = discoverTeamsChannels;
        _discoverFollowedLocations = discoverFollowedLocations;

        if (configuredSiteTargets != null)
        {
            _configuredSiteTargets.AddRange(ExpandSharePointTargets(configuredSiteTargets));
        }

        if (configuredDriveIds != null)
        {
            _configuredDriveIds.AddRange(configuredDriveIds.Where(id => !string.IsNullOrWhiteSpace(id)).Distinct(StringComparer.OrdinalIgnoreCase));
        }
    }

    internal SharePointConnector(
        SharePointRestClient sharePointRestClient,
        string tenantId,
        Uri? sharePointRestRootUrl,
        ILogger<SharePointConnector>? logger = null,
        ThrottleNotificationHub? throttleNotifications = null,
        bool useConfiguredTargets = false,
        IEnumerable<Uri>? configuredSiteTargets = null,
        IEnumerable<string>? configuredDriveIds = null,
        bool discoverFollowedLocations = false)
    {
        _sharePointRestClient = sharePointRestClient;
        _sharePointRestRootUrl = sharePointRestRootUrl is null ? null : SharePointRestClient.NormalizeRootUrl(sharePointRestRootUrl);
        _tenantId = tenantId;
        _logger = logger;
        _throttleNotifications = throttleNotifications;
        _useConfiguredTargets = useConfiguredTargets;
        _discoverFollowedLocations = discoverFollowedLocations;

        if (configuredSiteTargets != null)
        {
            _configuredSiteTargets.AddRange(ExpandSharePointTargets(configuredSiteTargets));
        }

        if (configuredDriveIds != null)
        {
            _configuredDriveIds.AddRange(configuredDriveIds.Where(id => !string.IsNullOrWhiteSpace(id)).Distinct(StringComparer.OrdinalIgnoreCase));
        }
    }

    public string ProviderName => CommonConstants.ConnectorProviders.Microsoft365;
    public string CheckpointScope => !string.IsNullOrWhiteSpace(_checkpointScope)
        ? _checkpointScope
        : throw new InvalidOperationException("The Microsoft 365 connector has not been initialized.");

    public async Task InitializeAsync(Dictionary<string, string> config, CancellationToken cancellationToken = default)
    {
        _graphClient = null;
        _sharePointRestClient = null;
        _sharePointRestRootUrl = null;
        _checkpointScope = string.Empty;
        _tenantId = config.GetValueOrDefault("TenantId") ?? string.Empty;
        var clientId = config.GetValueOrDefault("ClientId") ?? string.Empty;
        var clientSecret = config.GetValueOrDefault("ClientSecret") ?? string.Empty;
        var authMode = ResolveAuthenticationMode(config, clientSecret);
        var delegatedScopes = GetDelegatedScopes(config);
        _discoverTeamsChannels = GetBooleanSetting(config, "DiscoverTeamsChannels", defaultValue: true);
        _discoverFollowedLocations = GetBooleanSetting(config, "DiscoverFollowedLocations", defaultValue: true);

        ConfigureTargets(config, authMode);

        TokenCredential credential;
        var authorityHost = AzureAuthorityHosts.AzurePublicCloud;

        switch (authMode)
        {
            case SharePointAuthenticationMode.AppOnly:
                if (string.IsNullOrWhiteSpace(_tenantId)
                    || string.Equals(_tenantId, "common", StringComparison.OrdinalIgnoreCase)
                    || string.IsNullOrWhiteSpace(clientId)
                    || string.IsNullOrWhiteSpace(clientSecret))
                {
                    throw new ArgumentException("App-only Microsoft 365 scans require TenantId, ClientId, and ClientSecret.");
                }

                credential = new ClientSecretCredential(_tenantId, clientId, clientSecret, new ClientSecretCredentialOptions
                {
                    AuthorityHost = authorityHost
                });

                _graphClient = MicrosoftGraphClientBuilder.Create(
                    credential,
                    ProductPrefix,
                    timeout: null,
                    finalHandler: null,
                    retryOptions: null,
                    throttleNotifications: _throttleNotifications);
                _checkpointScope = ConnectorCheckpointIdentity.Create(
                    "m365-app",
                    _tenantId,
                    clientId,
                    clientSecret);
                break;

            case SharePointAuthenticationMode.DeviceCode:
            case SharePointAuthenticationMode.InteractiveBrowser:
                if (!string.IsNullOrWhiteSpace(clientId))
                {
                    if (string.IsNullOrWhiteSpace(_tenantId))
                    {
                        _tenantId = "common";
                    }

                    credential = authMode == SharePointAuthenticationMode.DeviceCode
                        ? CreateDeviceCodeCredential(clientId, authorityHost)
                        : CreateInteractiveBrowserCredential(clientId, authorityHost, config.GetValueOrDefault("RedirectUri"));
                    credential = ObserveDelegatedCredential(credential);

                    _graphClient = MicrosoftGraphClientBuilder.Create(
                        credential,
                        ProductPrefix,
                        delegatedScopes,
                        timeout: null,
                        finalHandler: null,
                        retryOptions: null,
                        throttleNotifications: _throttleNotifications);
                    break;
                }

                if (_configuredDriveIds.Count > 0)
                {
                    throw new ArgumentException("DriveId targeting requires Microsoft Graph delegated auth. For SharePoint-native delegated auth, provide --site-url targets or --sharepoint-url for tenant-wide discovery.");
                }

                _sharePointRestRootUrl = ResolveSharePointRestRootUrl(config, _configuredSiteTargets);
                if (_configuredSiteTargets.Count == 0 && _sharePointRestRootUrl == null)
                {
                    throw new ArgumentException("Delegated SharePoint-native scans require SharePointUrl or SiteUrl when ClientId is omitted. Example: --sharepoint-url https://contoso.sharepoint.com");
                }

                if (string.IsNullOrWhiteSpace(_tenantId))
                {
                    _tenantId = "common";
                }

                var sharePointClientId = SharePointRestClient.SharePointOnlineManagementShellClientId;
                credential = authMode == SharePointAuthenticationMode.DeviceCode
                    ? CreateDeviceCodeCredential(sharePointClientId, authorityHost)
                    : CreateInteractiveBrowserCredential(sharePointClientId, authorityHost, config.GetValueOrDefault("RedirectUri"));
                credential = ObserveDelegatedCredential(credential);

                _sharePointRestClient = SharePointRestClient.Create(
                    credential,
                    ProductPrefix,
                    _logger,
                    _throttleNotifications);
                break;

            default:
                throw new InvalidOperationException($"Unsupported SharePoint auth mode '{authMode}'.");
        }

        if (string.IsNullOrWhiteSpace(_checkpointScope))
        {
            _checkpointScope = ConnectorCheckpointIdentity.Create(
                "m365-fallback",
                _tenantId,
                clientId,
                authMode.ToString(),
                Environment.UserDomainName,
                Environment.UserName);
        }

        await Task.CompletedTask;
    }

    public async Task<IEnumerable<IRemoteDrive>> GetDrivesAsync(CancellationToken cancellationToken = default)
    {
        ResetDiscoveryReport();
        if (_graphClient == null && _sharePointRestClient == null)
        {
            throw new InvalidOperationException("Connector not initialized.");
        }

        if (_sharePointRestClient != null)
        {
            if (_discoverTeamsChannels && _configuredSiteTargets.Count == 0)
            {
                const string warning = "Teams channel filesFolder discovery requires Microsoft Graph authentication; private or shared channel storage may require a ClientId with Graph permissions.";
                AddDiscoveryWarning(warning);
                _logger?.LogInformation("{DiscoveryWarning}", warning);
            }

            var restDrives = (await GetSharePointRestDrivesAsync(cancellationToken))
                .DistinctBy(drive => drive.ConnectionId, StringComparer.OrdinalIgnoreCase)
                .ToList();
            return CompleteDiscoveryReport(
                _configuredSiteTargets.Count > 0 ? "explicit-target" : "delegated/sharepoint-native best-effort",
                restDrives);
        }

        List<IRemoteDrive> drives;
        if (_useConfiguredTargets)
        {
            drives = (await GetConfiguredDrivesAsync(cancellationToken)).ToList();
        }
        else
        {
            var sites = await GetSitesAsync(cancellationToken);
            AddDiscoveryCount("app sites", sites.Count);
            drives = (await GetDistinctDrivesForSitesAsync(sites, cancellationToken)).ToList();
        }

        if (!_discoverTeamsChannels || _configuredSiteTargets.Count > 0 || _configuredDriveIds.Count > 0)
        {
            var coverage = _configuredSiteTargets.Count > 0 || _configuredDriveIds.Count > 0
                ? "explicit-target"
                : _useConfiguredTargets
                    ? "delegated/multi-source best-effort"
                    : "app-only tenant inventory";
            return CompleteDiscoveryReport(coverage, drives);
        }

        var teamsDrives = await GetTeamsChannelDrivesAsync(cancellationToken);
        var merged = MergeGraphDriveDiscoveries(drives, teamsDrives);
        return CompleteDiscoveryReport(
            _useConfiguredTargets ? "delegated/multi-source best-effort" : "app-only tenant inventory",
            merged);
    }

    public bool TryCreateCachedDrive(Stratus.Sift.Core.Models.FileShare share, out IRemoteDrive? drive)
    {
        drive = null;
        if (_graphClient == null || string.IsNullOrWhiteSpace(share.Path))
        {
            return false;
        }

        if (!TryParseConnectionId(share.Path, out var driveId, out var rootItemId))
        {
            return false;
        }

        var cachedDrive = new Drive
        {
            Id = driveId,
            Name = string.IsNullOrWhiteSpace(share.Name) ? driveId : share.Name,
            WebUrl = share.WebUrl ?? string.Empty,
            Quota = new Quota
            {
                Used = share.TotalSizeBytes
            }
        };

        drive = new SharePointDrive(
            _graphClient,
            cachedDrive,
            _tenantId,
            NormalizeDriveType(share.Type),
            rootItemId,
            share.Name,
            share.WebUrl);
        return true;
    }

    private async Task<IEnumerable<IRemoteDrive>> GetConfiguredDrivesAsync(CancellationToken cancellationToken)
    {
        if (_graphClient == null)
        {
            return [];
        }

        if (_configuredSiteTargets.Count == 0 && _configuredDriveIds.Count == 0)
        {
            return await GetDelegatedAccessibleDrivesAsync(cancellationToken);
        }

        AddDiscoveryCount("URL seeds", _configuredSiteTargets.Count);
        AddDiscoveryCount("drive seeds", _configuredDriveIds.Count);

        var drives = new List<IRemoteDrive>();
        var seenDriveIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var driveId in _configuredDriveIds)
        {
            var drive = await GetDriveByIdAsync(driveId, cancellationToken);
            if (drive != null && seenDriveIds.Add(drive.Id))
            {
                drives.Add(drive);
            }
        }

        foreach (var siteTarget in _configuredSiteTargets)
        {
            var resolvedTarget = await ResolveSiteTargetAsync(siteTarget, cancellationToken);
            if (resolvedTarget == null)
            {
                _logger?.LogWarning("Unable to resolve SharePoint site target {SiteUrl}.", siteTarget);
                continue;
            }

            var siteDrives = (await GetDrivesForSiteAsync(
                    resolvedTarget.Site,
                    cancellationToken,
                    DetermineDriveType(resolvedTarget.Site.WebUrl ?? siteTarget.AbsoluteUri)))
                .ToList();

            if (resolvedTarget.RestrictToRequestedPath)
            {
                siteDrives = siteDrives
                    .Where(drive => DriveMatchesRequestedTarget(drive, siteTarget))
                    .ToList();
            }

            foreach (var drive in siteDrives)
            {
                if (seenDriveIds.Add(drive.Id))
                {
                    drives.Add(drive);
                }
            }
        }

        return drives;
    }

    private async Task<IEnumerable<IRemoteDrive>> GetSharePointRestDrivesAsync(CancellationToken cancellationToken)
    {
        if (_sharePointRestClient == null)
        {
            return [];
        }

        return await GetConfiguredSharePointRestDrivesAsync(cancellationToken);
    }

    private async Task<IEnumerable<IRemoteDrive>> GetConfiguredSharePointRestDrivesAsync(CancellationToken cancellationToken)
    {
        if (_sharePointRestClient == null)
        {
            return [];
        }

        if (_configuredSiteTargets.Count == 0)
        {
            return await GetDelegatedAccessibleSharePointRestDrivesAsync(cancellationToken);
        }

        AddDiscoveryCount("URL seeds", _configuredSiteTargets.Count);

        var drives = new List<IRemoteDrive>();
        var seenDriveIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var siteTarget in _configuredSiteTargets)
        {
            var resolvedTarget = await ResolveSharePointRestSiteTargetAsync(siteTarget, cancellationToken);
            if (resolvedTarget == null)
            {
                _logger?.LogWarning("Unable to resolve SharePoint site target {SiteUrl}.", siteTarget);
                continue;
            }

            var siteDrives = (await GetSharePointRestDrivesForSiteAsync(resolvedTarget.Site, cancellationToken)).ToList();
            if (resolvedTarget.RestrictToRequestedPath)
            {
                siteDrives = siteDrives
                    .Where(drive => DriveMatchesRequestedTarget(drive, siteTarget))
                    .ToList();
            }

            foreach (var drive in siteDrives)
            {
                if (seenDriveIds.Add(drive.Id))
                {
                    drives.Add(drive);
                }
            }
        }

        return drives;
    }

    private async Task<IEnumerable<IRemoteDrive>> GetDelegatedAccessibleSharePointRestDrivesAsync(CancellationToken cancellationToken)
    {
        if (_sharePointRestClient == null || _sharePointRestRootUrl == null)
        {
            return [];
        }

        _logger?.LogInformation("No explicit SharePoint targets configured for delegated SharePoint-native auth. Discovering accessible sites via SharePoint Search.");
        var sites = (await _sharePointRestClient.SearchAccessibleSitesAsync(_sharePointRestRootUrl, cancellationToken)).ToList();
        AddDiscoveryCount("SharePoint search sites", sites.Count);

        if (_discoverFollowedLocations)
        {
            try
            {
                var followedLocations = await _sharePointRestClient.GetFollowedLocationUrlsAsync(_sharePointRestRootUrl, cancellationToken);
                AddDiscoveryCount("followed locations", followedLocations.Count);
                var followedSites = new System.Collections.Concurrent.ConcurrentBag<SharePointRestClient.RestSite>();
                await Parallel.ForEachAsync(followedLocations, new ParallelOptions
                {
                    MaxDegreeOfParallelism = Math.Min(MaxConcurrentSiteRequests, Math.Max(followedLocations.Count, 1)),
                    CancellationToken = cancellationToken
                }, async (location, ct) =>
                {
                    var site = await _sharePointRestClient.TryResolveSiteAsync(location, ct);
                    if (site != null)
                    {
                        followedSites.Add(site);
                    }
                });

                sites.AddRange(followedSites);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                const string warning = "Followed SharePoint sites and documents could not be enumerated.";
                AddDiscoveryWarning(warning);
                _logger?.LogDebug(ex, "{DiscoveryWarning}", warning);
            }
        }

        var distinctSites = sites
            .DistinctBy(site => site.Url.AbsoluteUri, StringComparer.OrdinalIgnoreCase)
            .ToList();
        AddDiscoveryCount("distinct sites", distinctSites.Count);
        return await GetDistinctSharePointRestDrivesForSitesAsync(distinctSites, cancellationToken);
    }

    private async Task<IEnumerable<IRemoteDrive>> GetDistinctSharePointRestDrivesForSitesAsync(
        IReadOnlyCollection<SharePointRestClient.RestSite> sites,
        CancellationToken cancellationToken)
    {
        if (_sharePointRestClient == null || sites.Count == 0)
        {
            return [];
        }

        var allDrives = new System.Collections.Concurrent.ConcurrentBag<IRemoteDrive>();
        await Parallel.ForEachAsync(sites, new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Min(MaxConcurrentSiteRequests, Math.Max(sites.Count, 1)),
            CancellationToken = cancellationToken
        }, async (site, ct) =>
        {
            var drives = await GetSharePointRestDrivesForSiteAsync(site, ct);
            foreach (var drive in drives)
            {
                allDrives.Add(drive);
            }
        });

        return allDrives.DistinctBy(drive => drive.Id).ToList();
    }

    private async Task<IEnumerable<IRemoteDrive>> GetSharePointRestDrivesForSiteAsync(
        SharePointRestClient.RestSite site,
        CancellationToken cancellationToken)
    {
        if (_sharePointRestClient == null)
        {
            return [];
        }

        try
        {
            var libraries = await _sharePointRestClient.GetLibrariesAsync(site, cancellationToken);
            var drives = new List<IRemoteDrive>();
            foreach (var library in libraries)
            {
                if (SystemLibraries.Contains(library.Title))
                {
                    continue;
                }

                if (library.ItemCount.HasValue && library.ItemCount.Value <= 0)
                {
                    continue;
                }

                if (library.WebUrl.AbsolutePath.Contains("/_catalogs/masterpage", StringComparison.OrdinalIgnoreCase)
                    || library.WebUrl.AbsolutePath.Contains("/lists/taxonomyhiddenlist", StringComparison.OrdinalIgnoreCase)
                    || library.WebUrl.AbsolutePath.Contains("/sitepages/", StringComparison.OrdinalIgnoreCase)
                    || library.WebUrl.AbsolutePath.Contains("/siteassets/", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                drives.Add(new SharePointRestDrive(
                    _sharePointRestClient,
                    library,
                    _tenantId,
                    BuildSharePointRestDriveName(site, library)));
            }

            return drives;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error listing SharePoint libraries for site {SiteUrl}", site.Url);
            return [];
        }
    }

    private async Task<ResolvedRestSiteTarget?> ResolveSharePointRestSiteTargetAsync(Uri targetUri, CancellationToken cancellationToken)
    {
        if (_sharePointRestClient == null)
        {
            return null;
        }

        var site = await _sharePointRestClient.TryResolveSiteAsync(targetUri, cancellationToken);
        if (site == null)
        {
            return null;
        }

        return new ResolvedRestSiteTarget(site, ShouldRestrictToRequestedPath(targetUri, site.Url.AbsoluteUri));
    }

    private async Task<IEnumerable<IRemoteDrive>> GetDelegatedAccessibleDrivesAsync(CancellationToken cancellationToken)
    {
        if (_graphClient == null)
        {
            return [];
        }

        _logger?.LogInformation("No explicit SharePoint targets configured for delegated auth. Discovering accessible sites via Microsoft Graph search.");
        var sites = await SearchSitesAsync("*", cancellationToken);
        AddDiscoveryCount("Graph search sites", sites.Count);

        if (_discoverFollowedLocations)
        {
            var followedSites = await GetFollowedSitesAsync(cancellationToken);
            AddDiscoveryCount("followed sites", followedSites.Count);
            sites.AddRange(followedSites);
        }

        var distinctSites = sites
            .Where(site => !string.IsNullOrWhiteSpace(site.Id))
            .DistinctBy(site => site.Id!, StringComparer.OrdinalIgnoreCase)
            .ToList();
        AddDiscoveryCount("distinct sites", distinctSites.Count);
        return await GetDistinctDrivesForSitesAsync(distinctSites, cancellationToken);
    }

    private async Task<IReadOnlyList<IRemoteDrive>> GetTeamsChannelDrivesAsync(CancellationToken cancellationToken)
    {
        if (_graphClient == null)
        {
            return [];
        }

        List<TeamReference> teams;
        try
        {
            teams = await GetTeamsAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(
                ex,
                "Teams channel discovery is unavailable. Continuing with SharePoint site discovery. Grant Team.ReadBasic.All and Channel.ReadBasic.All to discover channel file locations.");
            return [];
        }

        if (teams.Count == 0)
        {
            return [];
        }

        AddDiscoveryCount("Teams", teams.Count);

        _logger?.LogInformation("Discovering Teams channel file locations for {TeamCount} teams.", teams.Count);

        var channels = new System.Collections.Concurrent.ConcurrentBag<ChannelReference>();
        var teamFailures = 0;
        await Parallel.ForEachAsync(teams, new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Min(MaxConcurrentSiteRequests, teams.Count),
            CancellationToken = cancellationToken
        }, async (team, ct) =>
        {
            try
            {
                foreach (var channel in await GetTeamChannelsAsync(team, ct))
                {
                    channels.Add(channel);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref teamFailures);
                _logger?.LogDebug(ex, "Unable to list Teams channels for {TeamName} ({TeamId}).", team.DisplayName, team.Id);
            }
        });

        var channelList = channels.ToArray();
        AddDiscoveryCount("Teams channels", channelList.Length);
        var channelDrives = new System.Collections.Concurrent.ConcurrentBag<TeamsChannelDriveReference>();
        var channelFailures = 0;
        await Parallel.ForEachAsync(channelList, new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Min(MaxConcurrentSiteRequests, Math.Max(channelList.Length, 1)),
            CancellationToken = cancellationToken
        }, async (channel, ct) =>
        {
            try
            {
                var drive = await GetChannelFilesFolderAsync(channel, ct);
                if (drive != null)
                {
                    channelDrives.Add(drive);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref channelFailures);
                _logger?.LogDebug(
                    ex,
                    "Unable to resolve Teams filesFolder for {TeamName} / {ChannelName}.",
                    channel.TeamDisplayName,
                    channel.DisplayName);
            }
        });

        if (teamFailures > 0 || channelFailures > 0)
        {
            AddDiscoveryCount("discovery failures", teamFailures + channelFailures);
            AddDiscoveryWarning($"Teams discovery had {teamFailures:N0} team failure(s) and {channelFailures:N0} channel failure(s).");
            _logger?.LogWarning(
                "Teams channel discovery completed with {TeamFailureCount} team failures and {ChannelFailureCount} channel failures. The scan will continue with every accessible drive discovered.",
                teamFailures,
                channelFailures);
        }

        var drives = channelDrives
            .DistinctBy(
                reference => $"{reference.DriveId}\n{reference.RootItemId}",
                StringComparer.OrdinalIgnoreCase)
            .Select(reference =>
            {
                var name = string.IsNullOrWhiteSpace(reference.ChannelDisplayName)
                    ? $"{reference.TeamDisplayName} (Teams)"
                    : $"{reference.TeamDisplayName} / {reference.ChannelDisplayName}";
                var drive = new Drive
                {
                    Id = reference.DriveId,
                    Name = name,
                    WebUrl = reference.WebUrl
                };

                return (IRemoteDrive)new SharePointDrive(
                    _graphClient,
                    drive,
                    _tenantId,
                    DatastoreType.Teams,
                    reference.RootItemId,
                    name,
                    reference.WebUrl);
            })
            .ToList();

        AddDiscoveryCount("Teams roots", drives.Count);

        _logger?.LogInformation(
            "Resolved {ChannelCount} Teams channels to {DriveCount} distinct drives.",
            channelDrives.Count,
            drives.Count);
        return drives;
    }

    private async Task<List<TeamReference>> GetTeamsAsync(CancellationToken cancellationToken)
    {
        var teams = new List<TeamReference>();
        await ForEachGraphCollectionItemAsync(
            new Uri("https://graph.microsoft.com/v1.0/teams?$select=id,displayName&$top=999"),
            element =>
            {
                var id = GetJsonString(element, "id");
                if (!string.IsNullOrWhiteSpace(id))
                {
                    teams.Add(new TeamReference(id, GetJsonString(element, "displayName") ?? id));
                }
            },
            cancellationToken);
        return teams.DistinctBy(team => team.Id, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<List<ChannelReference>> GetTeamChannelsAsync(TeamReference team, CancellationToken cancellationToken)
    {
        var channels = new List<ChannelReference>();
        await ForEachGraphCollectionItemAsync(
            new Uri($"https://graph.microsoft.com/v1.0/teams/{Uri.EscapeDataString(team.Id)}/allChannels?$select=id,displayName,membershipType"),
            element =>
            {
                var id = GetJsonString(element, "id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    return;
                }

                channels.Add(new ChannelReference(
                    team.DisplayName,
                    GetJsonString(element, "displayName") ?? id,
                    BuildChannelFilesFolderUrl(team.Id, id, GetJsonString(element, "@odata.id"))));
            },
            cancellationToken);
        return channels.DistinctBy(channel => channel.FilesFolderUrl.AbsoluteUri, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<TeamsChannelDriveReference?> GetChannelFilesFolderAsync(ChannelReference channel, CancellationToken cancellationToken)
    {
        if (_graphClient == null)
        {
            return null;
        }

        var requestInfo = new RequestInformation
        {
            HttpMethod = Method.GET,
            URI = channel.FilesFolderUrl
        };
        using var stream = await _graphClient.RequestAdapter.SendPrimitiveAsync<Stream>(
            requestInfo,
            errorMapping: null,
            cancellationToken: cancellationToken);
        if (stream == null)
        {
            return null;
        }

        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var root = document.RootElement;
        if (!root.TryGetProperty("parentReference", out var parentReference)
            || parentReference.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var driveId = GetJsonString(parentReference, "driveId");
        if (string.IsNullOrWhiteSpace(driveId))
        {
            return null;
        }

        return new TeamsChannelDriveReference(
            driveId,
            channel.TeamDisplayName,
            channel.DisplayName,
            GetJsonString(root, "id"),
            GetJsonString(root, "webUrl") ?? string.Empty);
    }

    private async Task ForEachGraphCollectionItemAsync(
        Uri initialUri,
        Action<JsonElement> processItem,
        CancellationToken cancellationToken)
    {
        if (_graphClient == null)
        {
            return;
        }

        Uri? nextUri = initialUri;
        while (nextUri != null)
        {
            var requestInfo = new RequestInformation
            {
                HttpMethod = Method.GET,
                URI = nextUri
            };
            using var stream = await _graphClient.RequestAdapter.SendPrimitiveAsync<Stream>(
                requestInfo,
                errorMapping: null,
                cancellationToken: cancellationToken);
            if (stream == null)
            {
                return;
            }

            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            if (document.RootElement.TryGetProperty("value", out var value)
                && value.ValueKind == JsonValueKind.Array)
            {
                foreach (var element in value.EnumerateArray())
                {
                    processItem(element);
                }
            }

            var nextLink = GetJsonString(document.RootElement, "@odata.nextLink");
            nextUri = Uri.TryCreate(nextLink, UriKind.Absolute, out var parsedNextUri) ? parsedNextUri : null;
        }
    }

    private static Uri BuildChannelFilesFolderUrl(string teamId, string channelId, string? odataId)
    {
        if (Uri.TryCreate(odataId, UriKind.Absolute, out var odataUri))
        {
            var path = odataUri.AbsolutePath;
            if (path.StartsWith("/v1.0/tenants/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/beta/tenants/", StringComparison.OrdinalIgnoreCase))
            {
                var teamsIndex = path.IndexOf("/teams/", StringComparison.OrdinalIgnoreCase);
                if (teamsIndex >= 0)
                {
                    path = "/v1.0" + path[teamsIndex..];
                }
            }

            if (!path.EndsWith("/filesFolder", StringComparison.OrdinalIgnoreCase))
            {
                path += "/filesFolder";
            }

            return new Uri($"https://graph.microsoft.com{path}");
        }

        return new Uri(
            $"https://graph.microsoft.com/v1.0/teams/{Uri.EscapeDataString(teamId)}/channels/{Uri.EscapeDataString(channelId)}/filesFolder");
    }

    private static string? GetJsonString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.String
                ? property.GetString()
                : null;
    }

    private async Task<IEnumerable<IRemoteDrive>> GetDistinctDrivesForSitesAsync(IReadOnlyCollection<Site> sites, CancellationToken cancellationToken)
    {
        if (_graphClient == null || sites.Count == 0)
        {
            return [];
        }

        var allDrives = new System.Collections.Concurrent.ConcurrentBag<IRemoteDrive>();

        await Parallel.ForEachAsync(sites, new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Min(MaxConcurrentSiteRequests, Math.Max(sites.Count, 1)),
            CancellationToken = cancellationToken
        }, async (site, ct) =>
        {
            if (string.IsNullOrEmpty(site.Id) || string.IsNullOrEmpty(site.WebUrl))
            {
                return;
            }

            var drives = await GetDrivesForSiteAsync(site, ct, DetermineDriveType(site.WebUrl));
            foreach (var drive in drives)
            {
                allDrives.Add(drive);
            }
        });

        return allDrives.DistinctBy(d => d.Id).ToList();
    }

    private async Task<IRemoteDrive?> GetDriveByIdAsync(string driveId, CancellationToken cancellationToken)
    {
        if (_graphClient == null || string.IsNullOrWhiteSpace(driveId))
        {
            return null;
        }

        try
        {
            var drive = await _graphClient.Drives[driveId].GetAsync(requestConfiguration =>
            {
                requestConfiguration.QueryParameters.Select = DriveSelectFields;
            }, cancellationToken: cancellationToken);

            if (drive?.Id == null)
            {
                return null;
            }

            return new SharePointDrive(_graphClient, drive, _tenantId, DetermineDriveType(drive.WebUrl ?? string.Empty));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error resolving configured SharePoint drive {DriveId}", driveId);
            return null;
        }
    }

    private async Task<ResolvedSiteTarget?> ResolveSiteTargetAsync(Uri targetUri, CancellationToken cancellationToken)
    {
        foreach (var candidatePath in EnumerateCandidateSitePaths(targetUri.AbsolutePath))
        {
            var site = await TryGetSiteByPathAsync(targetUri.Host, candidatePath, cancellationToken);
            if (site?.Id == null || string.IsNullOrWhiteSpace(site.WebUrl))
            {
                continue;
            }

            return new ResolvedSiteTarget(site, ShouldRestrictToRequestedPath(targetUri, site.WebUrl));
        }

        return null;
    }

    private async Task<Site?> TryGetSiteByPathAsync(string host, string candidatePath, CancellationToken cancellationToken)
    {
        if (_graphClient == null)
        {
            return null;
        }

        var requestInfo = new RequestInformation
        {
            HttpMethod = Method.GET,
            URI = new Uri($"https://graph.microsoft.com/v1.0/sites/{host}:{candidatePath}?$select={string.Join(',', SiteSelectFields)}")
        };

        try
        {
            return await _graphClient.RequestAdapter.SendAsync<Site>(
                requestInfo,
                Site.CreateFromDiscriminatorValue,
                cancellationToken: cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Site-by-path lookup failed for host {Host} and path {Path}", host, candidatePath);
            return null;
        }
    }

    private async Task<List<Site>> SearchSitesAsync(string searchQuery, CancellationToken cancellationToken)
    {
        if (_graphClient == null)
        {
            return [];
        }

        var sites = new List<Site>();
        var processedSiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var encodedSearchQuery = Uri.EscapeDataString(string.IsNullOrWhiteSpace(searchQuery) ? "*" : searchQuery);
        var requestInfo = new RequestInformation
        {
            HttpMethod = Method.GET,
            URI = new Uri($"https://graph.microsoft.com/v1.0/sites?search={encodedSearchQuery}&$select={string.Join(',', SiteSelectFields)}&$top=999")
        };
        requestInfo.Headers.Add("ConsistencyLevel", "eventual");

        while (requestInfo != null)
        {
            try
            {
                using var stream = await _graphClient.RequestAdapter.SendPrimitiveAsync<Stream>(
                    requestInfo,
                    errorMapping: null,
                    cancellationToken: cancellationToken);

                if (stream == null)
                {
                    break;
                }

                using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
                if (document.RootElement.TryGetProperty("value", out var valueElement) && valueElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var element in valueElement.EnumerateArray())
                    {
                        var siteId = element.TryGetProperty("id", out var idProperty) ? idProperty.GetString() : null;
                        if (string.IsNullOrWhiteSpace(siteId) || !processedSiteIds.Add(siteId))
                        {
                            continue;
                        }

                        var site = new Site
                        {
                            Id = siteId,
                            Name = element.TryGetProperty("name", out var nameProperty) ? nameProperty.GetString() : null,
                            WebUrl = element.TryGetProperty("webUrl", out var webUrlProperty) ? webUrlProperty.GetString() : null,
                            DisplayName = element.TryGetProperty("displayName", out var displayNameProperty) ? displayNameProperty.GetString() : null
                        };

                        if (element.TryGetProperty("createdDateTime", out var createdProperty)
                            && createdProperty.ValueKind == JsonValueKind.String
                            && DateTimeOffset.TryParse(createdProperty.GetString(), out var createdDateTime))
                        {
                            site.CreatedDateTime = createdDateTime;
                        }

                        sites.Add(site);
                    }
                }

                if (!document.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkProperty)
                    || string.IsNullOrWhiteSpace(nextLinkProperty.GetString()))
                {
                    break;
                }

                requestInfo = new RequestInformation
                {
                    HttpMethod = Method.GET,
                    URI = new Uri(nextLinkProperty.GetString()!)
                };
                requestInfo.Headers.Add("ConsistencyLevel", "eventual");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(
                    ex,
                    "Error searching SharePoint sites for delegated discovery. Returning {Count} sites discovered so far.",
                    sites.Count);
                break;
            }
        }

        return sites;
    }

    private async Task<List<Site>> GetFollowedSitesAsync(CancellationToken cancellationToken)
    {
        var sites = new List<Site>();
        try
        {
            await ForEachGraphCollectionItemAsync(
                new Uri($"https://graph.microsoft.com/v1.0/me/followedSites?$select={string.Join(',', SiteSelectFields)}"),
                element =>
                {
                    var id = GetJsonString(element, "id");
                    if (string.IsNullOrWhiteSpace(id))
                    {
                        return;
                    }

                    sites.Add(new Site
                    {
                        Id = id,
                        Name = GetJsonString(element, "name"),
                        DisplayName = GetJsonString(element, "displayName"),
                        WebUrl = GetJsonString(element, "webUrl")
                    });
                },
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            const string warning = "Followed Microsoft 365 sites could not be enumerated.";
            AddDiscoveryWarning(warning);
            _logger?.LogDebug(ex, "{DiscoveryWarning}", warning);
        }

        return sites
            .DistinctBy(site => site.Id, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private async Task<List<Site>> GetSitesAsync(CancellationToken cancellationToken)
    {
        if (_graphClient == null)
        {
            return [];
        }

        var sites = new List<Site>();
        var processedSiteIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var requestInfo = new RequestInformation
        {
            HttpMethod = Method.GET,
            URI = new Uri($"https://graph.microsoft.com/v1.0/sites/getAllSites?$select={string.Join(',', SiteSelectFields)}")
        };

        while (requestInfo != null)
        {
            try
            {
                using var stream = await _graphClient.RequestAdapter.SendPrimitiveAsync<Stream>(
                    requestInfo,
                    errorMapping: null,
                    cancellationToken: cancellationToken);

                if (stream == null)
                {
                    break;
                }

                using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
                if (document.RootElement.TryGetProperty("value", out var valueElement) && valueElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var element in valueElement.EnumerateArray())
                    {
                        var siteId = element.TryGetProperty("id", out var idProperty) ? idProperty.GetString() : null;
                        if (string.IsNullOrWhiteSpace(siteId) || !processedSiteIds.Add(siteId))
                        {
                            continue;
                        }

                        var site = new Site
                        {
                            Id = siteId,
                            Name = element.TryGetProperty("name", out var nameProperty) ? nameProperty.GetString() : null,
                            WebUrl = element.TryGetProperty("webUrl", out var webUrlProperty) ? webUrlProperty.GetString() : null,
                            DisplayName = element.TryGetProperty("displayName", out var displayNameProperty) ? displayNameProperty.GetString() : null
                        };

                        if (element.TryGetProperty("createdDateTime", out var createdProperty)
                            && createdProperty.ValueKind == JsonValueKind.String
                            && DateTimeOffset.TryParse(createdProperty.GetString(), out var createdDateTime))
                        {
                            site.CreatedDateTime = createdDateTime;
                        }

                        sites.Add(site);
                    }
                }

                if (!document.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkProperty)
                    || string.IsNullOrWhiteSpace(nextLinkProperty.GetString()))
                {
                    break;
                }

                requestInfo = new RequestInformation
                {
                    HttpMethod = Method.GET,
                    URI = new Uri(nextLinkProperty.GetString()!)
                };
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(
                    ex,
                    "Error listing SharePoint sites for tenant {TenantId}. Returning {Count} sites discovered so far.",
                    _tenantId,
                    sites.Count);
                break;
            }
        }

        return sites;
    }

    private async Task<IEnumerable<IRemoteDrive>> GetDrivesForSiteAsync(Site site, CancellationToken cancellationToken, DatastoreType type = DatastoreType.SharePoint)
    {
        if (_graphClient == null)
        {
            return Enumerable.Empty<IRemoteDrive>();
        }

        var drives = new List<IRemoteDrive>();

        try
        {
            var response = await _graphClient.Sites[site.Id].Drives.GetAsync(requestConfiguration =>
            {
                requestConfiguration.QueryParameters.Select = DriveSelectFields;
                requestConfiguration.QueryParameters.Top = 999;
            }, cancellationToken: cancellationToken);

            void ProcessResponse(DriveCollectionResponse? currentResponse)
            {
                if (currentResponse?.Value == null)
                {
                    return;
                }

                foreach (var drive in currentResponse.Value)
                {
                    if (string.IsNullOrEmpty(drive.Name))
                    {
                        continue;
                    }

                    if (SystemLibraries.Contains(drive.Name))
                    {
                        continue;
                    }

                    if (!string.IsNullOrEmpty(drive.WebUrl))
                    {
                        if (drive.WebUrl.Contains("/_catalogs/masterpage", StringComparison.OrdinalIgnoreCase)
                            || drive.WebUrl.Contains("/lists/taxonomyhiddenlist", StringComparison.OrdinalIgnoreCase)
                            || drive.WebUrl.Contains("/sitepages/", StringComparison.OrdinalIgnoreCase)
                            || drive.WebUrl.Contains("/siteassets/", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }
                    }

                    if (type == DatastoreType.OneDrive)
                    {
                        if (drive.Name.Equals("Documents", StringComparison.OrdinalIgnoreCase)
                            || drive.Name.Equals("OneDrive", StringComparison.OrdinalIgnoreCase))
                        {
                            drive.Name = $"{site.DisplayName}'s OneDrive";
                        }
                        else
                        {
                            drive.Name = $"{site.DisplayName} - {drive.Name}";
                        }
                    }
                    else if (!string.IsNullOrEmpty(site.DisplayName))
                    {
                        drive.Name = drive.Name.Equals("Documents", StringComparison.OrdinalIgnoreCase)
                            ? site.DisplayName
                            : $"{site.DisplayName} - {drive.Name}";
                    }

                    drives.Add(new SharePointDrive(_graphClient, drive, _tenantId, type));
                }
            }

            ProcessResponse(response);

            while (response?.OdataNextLink != null)
            {
                var requestInfo = _graphClient.Sites[site.Id].Drives.ToGetRequestInformation();
                requestInfo.URI = new Uri(response.OdataNextLink);
                response = await _graphClient.RequestAdapter.SendAsync<DriveCollectionResponse>(
                    requestInfo,
                    DriveCollectionResponse.CreateFromDiscriminatorValue,
                    cancellationToken: cancellationToken);
                ProcessResponse(response);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error listing drives for site {SiteId} ({SiteName})", site.Id, site.DisplayName);
        }

        return drives;
    }

    private void ConfigureTargets(IReadOnlyDictionary<string, string> config, SharePointAuthenticationMode authMode)
    {
        _configuredSiteTargets.Clear();
        _configuredDriveIds.Clear();
        var configuredTargets = ParseUriTargets(config, "SiteUrl", "SiteUrls")
            .Concat(ParseUriTargets(config, "SeedUrl", "SeedUrls"));
        _configuredSiteTargets.AddRange(ExpandSharePointTargets(configuredTargets));
        _configuredDriveIds.AddRange(ParseStringTargets(config, "DriveId", "DriveIds"));

        _useConfiguredTargets = authMode != SharePointAuthenticationMode.AppOnly
            || _configuredSiteTargets.Count > 0
            || _configuredDriveIds.Count > 0;
    }

    private static SharePointAuthenticationMode ResolveAuthenticationMode(IReadOnlyDictionary<string, string> config, string clientSecret)
    {
        var rawMode = config.GetValueOrDefault("AuthMode");
        if (string.IsNullOrWhiteSpace(rawMode))
        {
            return string.IsNullOrWhiteSpace(clientSecret)
                ? SharePointAuthenticationMode.InteractiveBrowser
                : SharePointAuthenticationMode.AppOnly;
        }

        return rawMode.Trim().ToLowerInvariant() switch
        {
            "app" or "app-only" or "clientsecret" or "client-secret" => SharePointAuthenticationMode.AppOnly,
            "device" or "devicecode" or "device-code" => SharePointAuthenticationMode.DeviceCode,
            "interactive" or "browser" or "interactivebrowser" or "interactive-browser" => SharePointAuthenticationMode.InteractiveBrowser,
            _ => throw new ArgumentException($"Unsupported SharePoint AuthMode '{rawMode}'.")
        };
    }

    internal static bool TryGetTenantIdFromAccessToken(string accessToken, out string? tenantId)
    {
        tenantId = null;
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return false;
        }

        var tokenParts = accessToken.Split('.');
        if (tokenParts.Length < 2)
        {
            return false;
        }

        try
        {
            var payload = tokenParts[1]
                .Replace('-', '+')
                .Replace('_', '/');

            payload = payload.PadRight(payload.Length + ((4 - payload.Length % 4) % 4), '=');
            var payloadBytes = Convert.FromBase64String(payload);
            using var document = JsonDocument.Parse(payloadBytes);

            if (!document.RootElement.TryGetProperty("tid", out var tidProperty)
                || tidProperty.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(tidProperty.GetString()))
            {
                return false;
            }

            tenantId = tidProperty.GetString();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private TokenCredential ObserveDelegatedCredential(TokenCredential credential)
        => new ObservingTokenCredential(credential, UpdateDelegatedCheckpointScope);

    private void UpdateDelegatedCheckpointScope(string accessToken)
    {
        _checkpointScope = CreateDelegatedCheckpointScope(accessToken);
        if (TryGetTenantIdFromAccessToken(accessToken, out var tenantId)
            && !string.IsNullOrWhiteSpace(tenantId))
        {
            _tenantId = tenantId;
        }
    }

    private static string CreateDelegatedCheckpointScope(string accessToken)
    {
        try
        {
            var parts = accessToken.Split('.');
            if (parts.Length < 2)
            {
                return ConnectorCheckpointIdentity.Create("m365-delegated-token", accessToken);
            }

            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + ((4 - payload.Length % 4) % 4), '=');
            using var document = JsonDocument.Parse(Convert.FromBase64String(payload));
            var root = document.RootElement;
            var tenant = GetClaim(root, "tid");
            var principal = GetClaim(root, "oid") ?? GetClaim(root, "sub");
            var client = GetClaim(root, "azp") ?? GetClaim(root, "appid");
            return !string.IsNullOrWhiteSpace(principal)
                ? ConnectorCheckpointIdentity.Create("m365-delegated", tenant, principal, client)
                : ConnectorCheckpointIdentity.Create("m365-delegated-token", accessToken);
        }
        catch
        {
            return ConnectorCheckpointIdentity.Create("m365-delegated-token", accessToken);
        }

        static string? GetClaim(JsonElement root, string name)
            => root.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
                ? property.GetString()
                : null;
    }

    private sealed class ObservingTokenCredential(
        TokenCredential inner,
        Action<string> onTokenReceived) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            var token = inner.GetToken(requestContext, cancellationToken);
            onTokenReceived(token.Token);
            return token;
        }

        public override async ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            var token = await inner.GetTokenAsync(requestContext, cancellationToken);
            onTokenReceived(token.Token);
            return token;
        }
    }

    private InteractiveBrowserCredential CreateInteractiveBrowserCredential(string clientId, Uri authorityHost, string? redirectUri)
    {
        var options = new InteractiveBrowserCredentialOptions
        {
            TenantId = _tenantId,
            ClientId = clientId,
            AuthorityHost = authorityHost,
            RedirectUri = new Uri(string.IsNullOrWhiteSpace(redirectUri) ? DefaultInteractiveRedirectUri : redirectUri),
            TokenCachePersistenceOptions = CreateTokenCacheOptions()
        };

        return new InteractiveBrowserCredential(options);
    }

    private DeviceCodeCredential CreateDeviceCodeCredential(string clientId, Uri authorityHost)
    {
        var options = new DeviceCodeCredentialOptions
        {
            TenantId = _tenantId,
            ClientId = clientId,
            AuthorityHost = authorityHost,
            TokenCachePersistenceOptions = CreateTokenCacheOptions(),
            DeviceCodeCallback = (deviceCodeInfo, _) =>
            {
                Console.Error.WriteLine(deviceCodeInfo.Message);
                return Task.CompletedTask;
            }
        };

        return new DeviceCodeCredential(options);
    }

    private static TokenCachePersistenceOptions CreateTokenCacheOptions()
    {
        return new TokenCachePersistenceOptions
        {
            Name = "Stratus.Sift.Cli.Microsoft365"
        };
    }

    private static IEnumerable<string> GetDelegatedScopes(IReadOnlyDictionary<string, string> config)
    {
        var customScopes = ParseValues(config.GetValueOrDefault("DelegatedScopes") ?? config.GetValueOrDefault("Scopes"), allowCommaSeparator: true);
        return customScopes.Count == 0 ? DefaultDelegatedScopes : customScopes;
    }

    private static bool GetBooleanSetting(IReadOnlyDictionary<string, string> config, string key, bool defaultValue)
    {
        return !config.TryGetValue(key, out var rawValue) || string.IsNullOrWhiteSpace(rawValue)
            ? defaultValue
            : bool.TryParse(rawValue, out var parsed)
                ? parsed
                : throw new ArgumentException($"{key} must be 'true' or 'false'.");
    }

    private static Uri? ResolveSharePointRestRootUrl(IReadOnlyDictionary<string, string> config, IReadOnlyList<Uri> configuredSiteTargets)
    {
        var configuredRootUrl = config.GetValueOrDefault("SharePointUrl")
            ?? config.GetValueOrDefault("SharePointRootUrl")
            ?? config.GetValueOrDefault("RootSiteUrl");

        if (!string.IsNullOrWhiteSpace(configuredRootUrl))
        {
            if (!TryCreateSharePointUri(configuredRootUrl, out var parsedRootUrl))
            {
                throw new ArgumentException($"Invalid SharePoint root URL '{configuredRootUrl}'.");
            }

            return SharePointRestClient.NormalizeRootUrl(parsedRootUrl);
        }

        if (configuredSiteTargets.Count > 0)
        {
            return SharePointRestClient.NormalizeRootUrl(configuredSiteTargets[0]);
        }

        return null;
    }

    private static string BuildSharePointRestDriveName(SharePointRestClient.RestSite site, SharePointRestClient.RestLibrary library)
    {
        if (library.DriveType == DatastoreType.OneDrive)
        {
            if (library.Title.Equals("Documents", StringComparison.OrdinalIgnoreCase)
                || library.Title.Equals("OneDrive", StringComparison.OrdinalIgnoreCase))
            {
                return $"{site.Title}'s OneDrive";
            }

            return $"{site.Title} - {library.Title}";
        }

        return library.Title.Equals("Documents", StringComparison.OrdinalIgnoreCase)
            ? site.Title
            : $"{site.Title} - {library.Title}";
    }

    private static List<Uri> ParseUriTargets(IReadOnlyDictionary<string, string> config, params string[] keys)
    {
        var uris = new List<Uri>();

        foreach (var key in keys)
        {
            if (!config.TryGetValue(key, out var rawValue))
            {
                continue;
            }

            foreach (var value in ParseValues(rawValue))
            {
                if (!TryCreateSharePointUri(value, out var uri))
                {
                    throw new ArgumentException($"Invalid SharePoint site target '{value}'.");
                }

                uris.Add(uri);
            }
        }

        return uris.DistinctBy(uri => uri.AbsoluteUri, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<string> ParseStringTargets(IReadOnlyDictionary<string, string> config, params string[] keys)
    {
        var values = new List<string>();
        foreach (var key in keys)
        {
            if (!config.TryGetValue(key, out var rawValue))
            {
                continue;
            }

            values.AddRange(ParseValues(rawValue));
        }

        return values
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool TryCreateSharePointUri(string rawValue, out Uri uri)
    {
        uri = null!;
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return false;
        }

        var candidate = rawValue.Trim().Replace('\\', '/');
        if (Uri.TryCreate(candidate, UriKind.Absolute, out var absoluteUri) && absoluteUri.Host.Contains('.', StringComparison.Ordinal))
        {
            uri = absoluteUri;
            return true;
        }

        if (candidate.StartsWith("//", StringComparison.Ordinal))
        {
            candidate = "https:" + candidate;
        }
        else if (!candidate.Contains("://", StringComparison.Ordinal))
        {
            candidate = "https://" + candidate.TrimStart('/');
        }

        if (!Uri.TryCreate(candidate, UriKind.Absolute, out absoluteUri) || !absoluteUri.Host.Contains('.', StringComparison.Ordinal))
        {
            return false;
        }

        uri = absoluteUri;
        return true;
    }

    private static List<string> ParseValues(string? rawValue, bool allowCommaSeparator = false)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return [];
        }

        var separators = allowCommaSeparator
            ? new[] { '\r', '\n', ';', ',' }
            : new[] { '\r', '\n', ';' };

        return rawValue
            .Split(separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToList();
    }

    private static IEnumerable<string> EnumerateCandidateSitePaths(string absolutePath)
    {
        var trimmedPath = absolutePath.Trim('/');
        if (string.IsNullOrWhiteSpace(trimmedPath))
        {
            yield return "/";
            yield break;
        }

        var segments = trimmedPath.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (var length = segments.Length; length >= 1; length--)
        {
            yield return "/" + string.Join('/', segments.Take(length));
        }
    }

    private static bool ShouldRestrictToRequestedPath(Uri requestedUri, string siteWebUrl)
    {
        if (!Uri.TryCreate(siteWebUrl, UriKind.Absolute, out var siteUri))
        {
            return false;
        }

        return requestedUri.AbsolutePath.TrimEnd('/').Length > siteUri.AbsolutePath.TrimEnd('/').Length;
    }

    private static bool DriveMatchesRequestedTarget(IRemoteDrive drive, Uri requestedUri)
    {
        if (string.IsNullOrWhiteSpace(drive.WebUrl))
        {
            return true;
        }

        var requested = requestedUri.AbsoluteUri.TrimEnd('/');
        var driveUrl = drive.WebUrl.TrimEnd('/');
        return requested.Equals(driveUrl, StringComparison.OrdinalIgnoreCase)
            || requested.StartsWith(driveUrl + "/", StringComparison.OrdinalIgnoreCase);
    }

    private List<IRemoteDrive> MergeGraphDriveDiscoveries(
        IReadOnlyCollection<IRemoteDrive> discoveredDrives,
        IReadOnlyCollection<IRemoteDrive> teamsDrives)
    {
        var merged = new List<IRemoteDrive>();
        var teamsByDriveId = teamsDrives
            .GroupBy(drive => drive.Id, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToList(), StringComparer.OrdinalIgnoreCase);
        var discoveredDriveIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var drive in discoveredDrives)
        {
            discoveredDriveIds.Add(drive.Id);
            if (drive is SharePointDrive sharePointDrive
                && teamsByDriveId.TryGetValue(drive.Id, out var matchingTeamsRoots))
            {
                var teamNames = matchingTeamsRoots
                    .Select(root => root.Name.Split(" / ", 2, StringSplitOptions.TrimEntries)[0])
                    .Where(name => !string.IsNullOrWhiteSpace(name))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var name = teamNames.Length == 1 ? $"{teamNames[0]} (Teams)" : sharePointDrive.Name;
                merged.Add(sharePointDrive.WithDriveType(DatastoreType.Teams, name));
                continue;
            }

            merged.Add(drive);
        }

        foreach (var group in teamsByDriveId.Where(entry => !discoveredDriveIds.Contains(entry.Key)))
        {
            var unscoped = group.Value.OfType<SharePointDrive>().FirstOrDefault(drive => !drive.IsScoped);
            if (unscoped != null)
            {
                merged.Add(unscoped);
                continue;
            }

            merged.AddRange(group.Value.DistinctBy(drive => drive.ConnectionId, StringComparer.OrdinalIgnoreCase));
        }

        return merged
            .DistinctBy(drive => drive.ConnectionId, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void ResetDiscoveryReport()
    {
        _discoverySourceCounts.Clear();
        _discoveryWarnings.Clear();
        DiscoveryReport = ConnectorDiscoveryReport.Empty;
    }

    private void AddDiscoveryCount(string source, int count)
    {
        if (count <= 0)
        {
            return;
        }

        _discoverySourceCounts[source] = _discoverySourceCounts.GetValueOrDefault(source) + count;
    }

    private void AddDiscoveryWarning(string warning)
    {
        if (!string.IsNullOrWhiteSpace(warning)
            && !_discoveryWarnings.Contains(warning, StringComparer.OrdinalIgnoreCase))
        {
            _discoveryWarnings.Add(warning);
        }
    }

    private IReadOnlyList<IRemoteDrive> CompleteDiscoveryReport(string coverage, IReadOnlyList<IRemoteDrive> drives)
    {
        _discoverySourceCounts["drives"] = drives.Count;
        DiscoveryReport = new ConnectorDiscoveryReport(
            coverage,
            new Dictionary<string, int>(_discoverySourceCounts, StringComparer.OrdinalIgnoreCase),
            _discoveryWarnings.ToArray());
        _logger?.LogInformation(
            "Microsoft 365 discovery completed with coverage {Coverage}, {DriveCount} drives, and {WarningCount} warnings. Sources: {Sources}",
            coverage,
            drives.Count,
            _discoveryWarnings.Count,
            string.Join(", ", _discoverySourceCounts.Select(entry => $"{entry.Key}={entry.Value}")));
        return drives;
    }

    internal static IReadOnlyList<Uri> ExpandSharePointTargets(IEnumerable<Uri> targets)
    {
        var expanded = new List<Uri>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var target in targets)
        {
            Add(target);
            foreach (var value in ParseQueryValues(target.Query))
            {
                if (Uri.TryCreate(value, UriKind.Absolute, out var absoluteValue)
                    && absoluteValue.Host.EndsWith(".sharepoint.com", StringComparison.OrdinalIgnoreCase))
                {
                    Add(absoluteValue);
                    continue;
                }

                if (value.StartsWith("/", StringComparison.Ordinal))
                {
                    Add(new Uri(target.GetLeftPart(UriPartial.Authority).TrimEnd('/') + value));
                }
            }

            var path = Uri.UnescapeDataString(target.AbsolutePath);
            var sharingMarker = path.IndexOf("/:f:/r/", StringComparison.OrdinalIgnoreCase);
            if (sharingMarker >= 0)
            {
                Add(new Uri(target.GetLeftPart(UriPartial.Authority).TrimEnd('/') + path[(sharingMarker + 6)..]));
            }
        }

        return expanded;

        void Add(Uri value)
        {
            if (value.Scheme == Uri.UriSchemeHttps && seen.Add(value.AbsoluteUri))
            {
                expanded.Add(value);
            }
        }
    }

    private static IEnumerable<string> ParseQueryValues(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            yield break;
        }

        foreach (var part in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=');
            if (separator < 0 || separator == part.Length - 1)
            {
                continue;
            }

            var key = Uri.UnescapeDataString(part[..separator].Replace('+', ' '));
            if (!key.Equals("id", StringComparison.OrdinalIgnoreCase)
                && !key.Equals("RootFolder", StringComparison.OrdinalIgnoreCase)
                && !key.Equals("objectUrl", StringComparison.OrdinalIgnoreCase)
                && !key.Equals("webUrl", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            yield return Uri.UnescapeDataString(part[(separator + 1)..].Replace('+', ' '));
        }
    }

    private static DatastoreType DetermineDriveType(string webUrl)
    {
        if (webUrl.Contains("-my.sharepoint.com", StringComparison.OrdinalIgnoreCase)
            || webUrl.Contains("/personal/", StringComparison.OrdinalIgnoreCase))
        {
            return DatastoreType.OneDrive;
        }

        if (webUrl.Contains("/teams/", StringComparison.OrdinalIgnoreCase))
        {
            return DatastoreType.Teams;
        }

        return DatastoreType.SharePoint;
    }

    private static DatastoreType NormalizeDriveType(DatastoreType type)
    {
        return type switch
        {
            DatastoreType.OneDrive => DatastoreType.OneDrive,
            DatastoreType.Teams => DatastoreType.Teams,
            _ => DatastoreType.SharePoint
        };
    }

    private static bool TryParseConnectionId(string connectionId, out string driveId, out string? rootItemId)
    {
        driveId = string.Empty;
        rootItemId = null;
        if (!Uri.TryCreate(connectionId, UriKind.Absolute, out var uri)
            || !uri.Scheme.Equals("sharepoint", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length == 0)
        {
            return false;
        }

        driveId = Uri.UnescapeDataString(segments[0]);
        if (segments.Length >= 3 && segments[1].Equals("items", StringComparison.OrdinalIgnoreCase))
        {
            rootItemId = Uri.UnescapeDataString(segments[2]);
        }

        return !string.IsNullOrWhiteSpace(driveId);
    }

    private enum SharePointAuthenticationMode
    {
        AppOnly,
        InteractiveBrowser,
        DeviceCode
    }

    private sealed record ResolvedSiteTarget(Site Site, bool RestrictToRequestedPath);
    private sealed record ResolvedRestSiteTarget(SharePointRestClient.RestSite Site, bool RestrictToRequestedPath);
    private sealed record TeamReference(string Id, string DisplayName);
    private sealed record ChannelReference(string TeamDisplayName, string DisplayName, Uri FilesFolderUrl);
    private sealed record TeamsChannelDriveReference(
        string DriveId,
        string TeamDisplayName,
        string ChannelDisplayName,
        string? RootItemId,
        string WebUrl);
}

