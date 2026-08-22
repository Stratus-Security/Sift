using System.Net;
using System.Text;
using Azure;
using Azure.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Http.HttpClientLibrary.Middleware.Options;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.Tests;

public class SharePointDelegatedAuthTests
{
    [Fact]
    public void ExpandSharePointTargets_ExtractsFolderFromAllItemsLink()
    {
        var target = new Uri(
            "https://contoso.sharepoint.com/teams/team-product/Shared%20Documents/Forms/AllItems.aspx" +
            "?id=%2Fteams%2Fteam-product%2FShared%20Documents%2FGeneral%2FProduct%20Management");

        var expanded = SharePointConnector.ExpandSharePointTargets([target]);

        Assert.Contains(
            expanded,
            uri => uri.AbsoluteUri.Equals(
                "https://contoso.sharepoint.com/teams/team-product/Shared%20Documents/General/Product%20Management",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task GetDrivesAsync_UsesConfiguredSiteTargets_WhenExplicitTargetsEnabled()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "site-by-path",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/contoso.sharepoint.com:/sites/Finance?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "id": "site-1",
                      "name": "Finance",
                      "displayName": "Finance",
                      "webUrl": "https://contoso.sharepoint.com/sites/Finance"
                    }
                    """)),
            SequenceRoute.Create(
                "drives",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/site-1/drives", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": [
                        {
                          "id": "drive-1",
                          "name": "Documents",
                          "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents",
                          "quota": {
                            "total": 1000,
                            "used": 120
                          }
                        }
                      ]
                    }
                    """)));

        var graphClient = CreateGraphClient(handler);
        var connector = new SharePointConnector(
            graphClient,
            "common",
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true,
            configuredSiteTargets: [new Uri("https://contoso.sharepoint.com/sites/Finance")]);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Single(drives);
        Assert.Equal("Finance", drives[0].Name);
        Assert.Equal(1, handler.GetAttemptCount("site-by-path"));
        Assert.Equal(1, handler.GetAttemptCount("drives"));
    }

    [Fact]
    public async Task GetDrivesAsync_FiltersToConfiguredLibraryTarget_WhenUrlPointsBelowSiteRoot()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "site-by-path-library",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/contoso.sharepoint.com:/sites/Finance/Shared%20Documents/2026?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.NotFound, "{}")),
            SequenceRoute.Create(
                "site-by-path-library-root",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/contoso.sharepoint.com:/sites/Finance/Shared%20Documents?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.NotFound, "{}")),
            SequenceRoute.Create(
                "site-by-path-site",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/contoso.sharepoint.com:/sites/Finance?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "id": "site-1",
                      "name": "Finance",
                      "displayName": "Finance",
                      "webUrl": "https://contoso.sharepoint.com/sites/Finance"
                    }
                    """)),
            SequenceRoute.Create(
                "drives",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/site-1/drives", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": [
                        {
                          "id": "drive-1",
                          "name": "Documents",
                          "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents",
                          "quota": {
                            "total": 1000,
                            "used": 120
                          }
                        },
                        {
                          "id": "drive-2",
                          "name": "General",
                          "webUrl": "https://contoso.sharepoint.com/sites/Finance/General",
                          "quota": {
                            "total": 1000,
                            "used": 220
                          }
                        }
                      ]
                    }
                    """)));

        var graphClient = CreateGraphClient(handler);
        var connector = new SharePointConnector(
            graphClient,
            "common",
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true,
            configuredSiteTargets: [new Uri("https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/2026")]);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Single(drives);
        Assert.Equal("drive-1", drives[0].Id);
        Assert.Equal(1, handler.GetAttemptCount("site-by-path-library"));
        Assert.Equal(1, handler.GetAttemptCount("site-by-path-library-root"));
        Assert.Equal(1, handler.GetAttemptCount("site-by-path-site"));
    }

    [Fact]
    public async Task GetDrivesAsync_UsesConfiguredDriveIds_WhenExplicitTargetsEnabled()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "drive-by-id",
                static request => request.RequestUri?.AbsoluteUri.Contains("/drives/drive-42?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "id": "drive-42",
                      "name": "Forensics",
                      "webUrl": "https://contoso.sharepoint.com/sites/IncidentResponse/Forensics",
                      "quota": {
                        "total": 1000,
                        "used": 64
                      }
                    }
                    """)));

        var graphClient = CreateGraphClient(handler);
        var connector = new SharePointConnector(
            graphClient,
            "common",
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true,
            configuredDriveIds: ["drive-42"]);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Single(drives);
        Assert.Equal("drive-42", drives[0].Id);
        Assert.Equal("Forensics", drives[0].Name);
        Assert.Equal(1, handler.GetAttemptCount("drive-by-id"));
    }

    [Fact]
    public async Task GetDrivesAsync_UsesDelegatedSearch_WhenNoExplicitTargetsConfigured()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "site-search",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites?", StringComparison.OrdinalIgnoreCase) == true
                    && request.RequestUri.AbsoluteUri.Contains("search=%2A", StringComparison.OrdinalIgnoreCase),
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": [
                        {
                          "id": "site-1",
                          "name": "Finance",
                          "displayName": "Finance",
                          "webUrl": "https://contoso.sharepoint.com/sites/Finance"
                        }
                      ]
                    }
                    """)),
            SequenceRoute.Create(
                "delegated-drives",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/site-1/drives", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": [
                        {
                          "id": "drive-1",
                          "name": "Documents",
                          "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents",
                          "quota": {
                            "total": 1000,
                            "used": 120
                          }
                        }
                      ]
                    }
                    """)));

        var graphClient = CreateGraphClient(handler);
        var connector = new SharePointConnector(
            graphClient,
            "common",
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Single(drives);
        Assert.Equal("Finance", drives[0].Name);
        Assert.Equal(1, handler.GetAttemptCount("site-search"));
        Assert.Equal(1, handler.GetAttemptCount("delegated-drives"));
    }

    [Fact]
    public async Task GetDrivesAsync_UnionsGraphSearchAndFollowedSites()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "site-search",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    {
                      "id": "site-finance",
                      "displayName": "Finance",
                      "webUrl": "https://contoso.sharepoint.com/sites/Finance"
                    }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "followed-sites",
                static request => request.RequestUri?.AbsoluteUri.Contains("/me/followedSites", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    {
                      "id": "site-team-product",
                      "displayName": "Team Product",
                      "webUrl": "https://contoso.sharepoint.com/teams/team-product"
                    }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "finance-drives",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/site-finance/drives", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    { "id": "drive-finance", "name": "Documents", "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents" }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "team-product-drives",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/site-team-product/drives", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    { "id": "drive-team-product", "name": "Documents", "webUrl": "https://contoso.sharepoint.com/teams/team-product/Shared%20Documents" }
                  ]
                }
                """)));

        var connector = new SharePointConnector(
            CreateGraphClient(handler),
            "tenant-1",
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true,
            discoverFollowedLocations: true);

        var drives = (await connector.GetDrivesAsync()).OrderBy(drive => drive.Id).ToList();

        Assert.Equal(["drive-finance", "drive-team-product"], drives.Select(drive => drive.Id));
        Assert.Equal(1, connector.DiscoveryReport.SourceCounts["Graph search sites"]);
        Assert.Equal(1, connector.DiscoveryReport.SourceCounts["followed sites"]);
        Assert.Equal("delegated/multi-source best-effort", connector.DiscoveryReport.Coverage);
    }

    [Fact]
    public async Task GetDrivesAsync_DiscoversTeamsChannelDrives_AndDeduplicatesStandardChannelLibrary()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "site-search",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    {
                      "id": "site-1",
                      "displayName": "Project Team",
                      "webUrl": "https://contoso.sharepoint.com/sites/ProjectTeam"
                    }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "site-drives",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/site-1/drives", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    {
                      "id": "drive-standard",
                      "name": "Documents",
                      "webUrl": "https://contoso.sharepoint.com/sites/ProjectTeam/Shared%20Documents"
                    }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "teams",
                static request => request.RequestUri?.AbsolutePath.EndsWith("/teams", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    { "id": "team-1", "displayName": "Project Team" }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "channels",
                static request => request.RequestUri?.AbsoluteUri.Contains("/teams/team-1/allChannels", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    { "id": "channel-standard", "displayName": "General", "membershipType": "standard" },
                    {
                      "id": "channel-private",
                      "displayName": "Security",
                      "membershipType": "private",
                      "@odata.id": "https://graph.microsoft.com/v1.0/tenants/tenant-1/teams/team-1/channels/channel-private"
                    }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "standard-files-folder",
                static request => request.RequestUri?.AbsoluteUri.Contains("/channels/channel-standard/filesFolder", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "id": "root-standard",
                  "name": "General",
                  "webUrl": "https://contoso.sharepoint.com/sites/ProjectTeam/Shared%20Documents/General",
                  "parentReference": { "driveId": "drive-standard" }
                }
                """)),
            SequenceRoute.Create(
                "private-files-folder",
                static request => request.RequestUri?.AbsoluteUri.Contains("/channels/channel-private/filesFolder", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "id": "root-private",
                  "name": "root",
                  "webUrl": "https://contoso.sharepoint.com/sites/ProjectTeam-Security/Shared%20Documents",
                  "parentReference": { "driveId": "drive-private" }
                }
                """)),
            SequenceRoute.Create(
                "private-drive-delta",
                static request => request.RequestUri?.AbsoluteUri.Contains("/drives/drive-private/items/root-private/delta", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    {
                      "id": "file-1",
                      "name": "deployment-secrets.yml",
                      "webUrl": "https://contoso.sharepoint.com/sites/ProjectTeam-Security/Shared%20Documents/deployment-secrets.yml",
                      "size": 128,
                      "file": { "mimeType": "application/x-yaml" }
                    }
                  ],
                  "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/drive-private/items/root/delta?token=done"
                }
                """)));

        var connector = new SharePointConnector(
            CreateGraphClient(handler),
            "tenant-1",
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true,
            discoverTeamsChannels: true);

        var drives = (await connector.GetDrivesAsync()).OrderBy(drive => drive.Id).ToList();

        Assert.Equal(2, drives.Count);
        Assert.All(drives, drive => Assert.Equal(DatastoreType.Teams, Assert.IsType<SharePointDrive>(drive).DriveType));
        Assert.Equal(["drive-private", "drive-standard"], drives.Select(drive => drive.Id));
        Assert.Equal(1, handler.GetAttemptCount("standard-files-folder"));
        Assert.Equal(1, handler.GetAttemptCount("private-files-folder"));

        var privateDrive = Assert.IsType<SharePointDrive>(drives.Single(drive => drive.Id == "drive-private"));
        Assert.Equal("sharepoint://tenant-1/drive-private/items/root-private", privateDrive.ConnectionId);
        var changes = (await privateDrive.GetChangesAsync(null)).Changes.ToList();
        Assert.Equal("deployment-secrets.yml", Assert.Single(changes).Name);
        Assert.Equal(1, handler.GetAttemptCount("private-drive-delta"));
    }

    [Fact]
    public async Task GetDrivesAsync_ContinuesWithSharePointDrives_WhenTeamsPermissionsAreMissing()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "site-search",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    {
                      "id": "site-1",
                      "displayName": "Finance",
                      "webUrl": "https://contoso.sharepoint.com/sites/Finance"
                    }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "site-drives",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/site-1/drives", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    {
                      "id": "drive-1",
                      "name": "Documents",
                      "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents"
                    }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "teams-forbidden",
                static request => request.RequestUri?.AbsolutePath.EndsWith("/teams", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.Forbidden, """
                {
                  "error": { "code": "Forbidden", "message": "Missing Team.ReadBasic.All" }
                }
                """)));

        var connector = new SharePointConnector(
            CreateGraphClient(handler),
            "tenant-1",
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true,
            discoverTeamsChannels: true);

        var drive = Assert.Single(await connector.GetDrivesAsync());

        Assert.Equal("drive-1", drive.Id);
        Assert.Equal(DatastoreType.SharePoint, Assert.IsType<SharePointDrive>(drive).DriveType);
        Assert.Equal(1, handler.GetAttemptCount("teams-forbidden"));
    }

    [Fact]
    public async Task GetDrivesAsync_FollowsTeamsAndChannelPagination()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "site-search",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """{ "value": [] }""")),
            SequenceRoute.Create(
                "teams-page-1",
                static request => request.RequestUri?.AbsolutePath.EndsWith("/teams", StringComparison.OrdinalIgnoreCase) == true
                    && !request.RequestUri.Query.Contains("skiptoken", StringComparison.OrdinalIgnoreCase),
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [{ "id": "team-1", "displayName": "Team One" }],
                  "@odata.nextLink": "https://graph.microsoft.com/v1.0/teams?$skiptoken=page2"
                }
                """)),
            SequenceRoute.Create(
                "teams-page-2",
                static request => request.RequestUri?.AbsolutePath.EndsWith("/teams", StringComparison.OrdinalIgnoreCase) == true
                    && request.RequestUri.Query.Contains("skiptoken=page2", StringComparison.OrdinalIgnoreCase),
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [{ "id": "team-2", "displayName": "Team Two" }]
                }
                """)),
            SequenceRoute.Create(
                "team-1-channels-page-1",
                static request => request.RequestUri?.AbsoluteUri.Contains("/teams/team-1/allChannels", StringComparison.OrdinalIgnoreCase) == true
                    && !request.RequestUri.Query.Contains("skiptoken", StringComparison.OrdinalIgnoreCase),
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [{ "id": "channel-1", "displayName": "General" }],
                  "@odata.nextLink": "https://graph.microsoft.com/v1.0/teams/team-1/allChannels?$skiptoken=channels2"
                }
                """)),
            SequenceRoute.Create(
                "team-1-channels-page-2",
                static request => request.RequestUri?.AbsoluteUri.Contains("/teams/team-1/allChannels", StringComparison.OrdinalIgnoreCase) == true
                    && request.RequestUri.Query.Contains("skiptoken=channels2", StringComparison.OrdinalIgnoreCase),
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [{ "id": "channel-2", "displayName": "Private" }]
                }
                """)),
            SequenceRoute.Create(
                "team-2-channels",
                static request => request.RequestUri?.AbsoluteUri.Contains("/teams/team-2/allChannels", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """{ "value": [] }""")),
            SequenceRoute.Create(
                "channel-1-folder",
                static request => request.RequestUri?.AbsoluteUri.Contains("/channels/channel-1/filesFolder", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "webUrl": "https://contoso.sharepoint.com/sites/TeamOne/Documents/General",
                  "parentReference": { "driveId": "drive-1" }
                }
                """)),
            SequenceRoute.Create(
                "channel-2-folder",
                static request => request.RequestUri?.AbsoluteUri.Contains("/channels/channel-2/filesFolder", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "webUrl": "https://contoso.sharepoint.com/sites/TeamOnePrivate/Documents",
                  "parentReference": { "driveId": "drive-2" }
                }
                """)));

        var connector = new SharePointConnector(
            CreateGraphClient(handler),
            "tenant-1",
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true,
            discoverTeamsChannels: true);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Equal(2, drives.Count);
        Assert.Equal(1, handler.GetAttemptCount("teams-page-2"));
        Assert.Equal(1, handler.GetAttemptCount("team-1-channels-page-2"));
        Assert.Equal(1, handler.GetAttemptCount("team-2-channels"));
    }

    [Fact]
    public void TryGetTenantIdFromAccessToken_ReturnsTidClaim()
    {
        var token = string.Concat(
            Base64UrlEncode("""{"alg":"none","typ":"JWT"}"""),
            ".",
            Base64UrlEncode("""{"tid":"tenant-123","aud":"https://graph.microsoft.com"}"""),
            ".signature");

        var success = SharePointConnector.TryGetTenantIdFromAccessToken(token, out var tenantId);

        Assert.True(success);
        Assert.Equal("tenant-123", tenantId);
    }

    [Fact]
    public async Task InitializeAsync_RequiresSharePointRootHint_WhenDelegatedClientIdIsMissing()
    {
        var connector = new SharePointConnector(NullLogger<SharePointConnector>.Instance);

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => connector.InitializeAsync(new Dictionary<string, string>
        {
            ["AuthMode"] = "Interactive"
        }));

        Assert.Contains("SharePointUrl or SiteUrl", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static Microsoft.Graph.GraphServiceClient CreateGraphClient(HttpMessageHandler handler, RetryHandlerOption? retryOptions = null)
    {
        return MicrosoftGraphClientBuilder.Create(
            new TestTokenCredential(),
            "StratusSnareConnector.Tests",
            timeout: TimeSpan.FromSeconds(15),
            finalHandler: handler,
            retryOptions: retryOptions);
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> JsonResponse(HttpStatusCode statusCode, string json)
    {
        return request => new HttpResponseMessage(statusCode)
        {
            RequestMessage = request,
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }

    private static string Base64UrlEncode(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private sealed class TestTokenCredential : TokenCredential
    {
        private static readonly AccessToken Token = new("test-token", DateTimeOffset.UtcNow.AddHours(1));

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return Token;
        }

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(Token);
        }
    }

    private sealed class SequenceHttpMessageHandler(params SequenceRoute[] routes) : HttpMessageHandler
    {
        private readonly IReadOnlyList<SequenceRoute> _routes = routes;

        public int GetAttemptCount(string routeName)
        {
            return _routes.First(route => route.Name == routeName).AttemptCount;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var route = _routes.FirstOrDefault(candidate => candidate.IsMatch(request))
                ?? throw new InvalidOperationException($"No route configured for {request.Method} {request.RequestUri}");

            return Task.FromResult(route.GetResponse(request));
        }
    }

    private sealed class SequenceRoute
    {
        private readonly Func<HttpRequestMessage, bool> _predicate;
        private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses;

        private SequenceRoute(string name, Func<HttpRequestMessage, bool> predicate, IEnumerable<Func<HttpRequestMessage, HttpResponseMessage>> responses)
        {
            Name = name;
            _predicate = predicate;
            _responses = new Queue<Func<HttpRequestMessage, HttpResponseMessage>>(responses);
        }

        public string Name { get; }
        public int AttemptCount { get; private set; }

        public bool IsMatch(HttpRequestMessage request)
        {
            return _predicate(request);
        }

        public HttpResponseMessage GetResponse(HttpRequestMessage request)
        {
            AttemptCount++;
            if (_responses.Count == 0)
            {
                throw new InvalidOperationException($"Route {Name} has no remaining responses.");
            }

            var responseFactory = _responses.Count > 1 ? _responses.Dequeue() : _responses.Peek();
            return responseFactory(request);
        }

        public static SequenceRoute Create(string name, Func<HttpRequestMessage, bool> predicate, params Func<HttpRequestMessage, HttpResponseMessage>[] responses)
        {
            return new SequenceRoute(name, predicate, responses);
        }
    }
}

