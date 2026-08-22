using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Azure;
using Azure.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Stratus.Sift.Connectors.SharePoint;

namespace Stratus.Sift.Connectors.Tests;

public class SharePointRestDelegatedTests
{
    [Fact]
    public async Task InitializeAsync_AllowsSharePointNativeDelegatedAuth_WhenSharePointUrlProvided()
    {
        var connector = new SharePointConnector(NullLogger<SharePointConnector>.Instance);

        await connector.InitializeAsync(new Dictionary<string, string>
        {
            ["AuthMode"] = "Interactive",
            ["TenantId"] = "tenant-123",
            ["SharePointUrl"] = "https://contoso.sharepoint.com"
        });
    }

    [Fact]
    public async Task InitializeAsync_AllowsBareSharePointHost_WhenSharePointUrlHasNoScheme()
    {
        var connector = new SharePointConnector(NullLogger<SharePointConnector>.Instance);

        await connector.InitializeAsync(new Dictionary<string, string>
        {
            ["AuthMode"] = "Interactive",
            ["TenantId"] = "tenant-123",
            ["SharePointUrl"] = "contoso.sharepoint.com"
        });
    }

    [Fact]
    public async Task InitializeAsync_AllowsBareSharePointSiteTarget_WhenSiteUrlHasNoScheme()
    {
        var connector = new SharePointConnector(NullLogger<SharePointConnector>.Instance);

        await connector.InitializeAsync(new Dictionary<string, string>
        {
            ["AuthMode"] = "Interactive",
            ["TenantId"] = "tenant-123",
            ["SiteUrl"] = "contoso.sharepoint.com/sites/Finance"
        });
    }

    [Fact]
    public async Task InitializeAsync_RequiresSharePointUrlOrSiteTarget_WhenClientIdMissing()
    {
        var connector = new SharePointConnector(NullLogger<SharePointConnector>.Instance);

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => connector.InitializeAsync(new Dictionary<string, string>
        {
            ["AuthMode"] = "Interactive",
            ["TenantId"] = "tenant-123"
        }));

        Assert.Contains("SharePointUrl or SiteUrl", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetDrivesAsync_UsesSharePointSearchAndLibraries_WhenRunningSharePointNativeMode()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "search",
                static request => request.RequestUri?.AbsoluteUri.Contains("/_api/search/query?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "PrimaryQueryResult": {
                        "RelevantResults": {
                          "Table": {
                            "Rows": [
                              {
                                "Cells": [
                                  { "Key": "Title", "Value": "Finance" },
                                  { "Key": "Path", "Value": "https://contoso.sharepoint.com/sites/Finance" }
                                ]
                              }
                            ]
                          }
                        }
                      }
                    }
                    """)),
            SequenceRoute.Create(
                "libraries",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/Finance/_api/web/lists?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": [
                        {
                          "Id": "list-1",
                          "Title": "Documents",
                          "RootFolder": {
                            "ServerRelativeUrl": "/sites/Finance/Shared Documents"
                          }
                        }
                      ]
                    }
                    """)));

        var restClient = CreateRestClient(handler);
        var connector = new SharePointConnector(
            restClient,
            "tenant-123",
            new Uri("https://contoso.sharepoint.com"),
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Single(drives);
        Assert.Equal("Finance", drives[0].Name);
        Assert.Equal("sharepoint://tenant-123/list-1", drives[0].ConnectionId);
        Assert.Equal(1, handler.GetAttemptCount("search"));
        Assert.Equal(1, handler.GetAttemptCount("libraries"));
    }

    [Fact]
    public async Task GetDrivesAsync_UnionsSharePointSearchAndFollowedDocumentLocations()
    {
        HttpRequestMessage? searchRequest = null;
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "search",
                static request => request.RequestUri?.AbsoluteUri.Contains("/_api/search/query?", StringComparison.OrdinalIgnoreCase) == true,
                request =>
                {
                    searchRequest = request;
                    return JsonResponse(HttpStatusCode.OK, """
                    {
                      "PrimaryQueryResult": {
                        "RelevantResults": {
                          "Table": {
                            "Rows": [
                              {
                                "Cells": [
                                  { "Key": "Title", "Value": "Finance" },
                                  { "Key": "Path", "Value": "https://contoso.sharepoint.com/sites/Finance" }
                                ]
                              }
                            ]
                          }
                        }
                      }
                    }
                    """)(request);
                }),
            SequenceRoute.Create(
                "followed",
                static request => request.RequestUri?.AbsoluteUri.Contains("/_api/social.following/my/followed(types=6)", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "d": {
                    "Followed": {
                      "results": [
                        {
                          "ContentUri": "https://contoso.sharepoint.com/teams/team-product/Shared%20Documents/General/Product/credentials.yml"
                        }
                      ]
                    }
                  }
                }
                """)),
            SequenceRoute.Create(
                "resolve-followed",
                static request => request.RequestUri?.AbsoluteUri.Contains("/_api/web?$select=Title,Url", StringComparison.OrdinalIgnoreCase) == true,
                request => request.RequestUri!.AbsoluteUri.Contains("/teams/team-product/_api/web?", StringComparison.OrdinalIgnoreCase)
                    ? JsonResponse(HttpStatusCode.OK, """
                    {
                      "Title": "Team Product",
                      "Url": "https://contoso.sharepoint.com/teams/team-product"
                    }
                    """)(request)
                    : new HttpResponseMessage(HttpStatusCode.NotFound) { RequestMessage = request }),
            SequenceRoute.Create(
                "finance-libraries",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/Finance/_api/web/lists?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    {
                      "Id": "list-finance",
                      "Title": "Documents",
                      "RootFolder": { "ServerRelativeUrl": "/sites/Finance/Shared Documents" }
                    }
                  ]
                }
                """)),
            SequenceRoute.Create(
                "team-product-libraries",
                static request => request.RequestUri?.AbsoluteUri.Contains("/teams/team-product/_api/web/lists?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(HttpStatusCode.OK, """
                {
                  "value": [
                    {
                      "Id": "list-team-product",
                      "Title": "Documents",
                      "RootFolder": { "ServerRelativeUrl": "/teams/team-product/Shared Documents" }
                    }
                  ]
                }
                """)));

        var connector = new SharePointConnector(
            CreateRestClient(handler),
            "tenant-123",
            new Uri("https://contoso.sharepoint.com"),
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true,
            discoverFollowedLocations: true);

        var drives = (await connector.GetDrivesAsync()).OrderBy(drive => drive.Id).ToList();

        Assert.Equal(["list-finance", "list-team-product"], drives.Select(drive => drive.Id));
        Assert.NotNull(searchRequest);
        Assert.Contains("STS_Web", Uri.UnescapeDataString(searchRequest!.RequestUri!.Query), StringComparison.Ordinal);
        Assert.Equal(1, connector.DiscoveryReport.SourceCounts["followed locations"]);
        Assert.Equal(2, connector.DiscoveryReport.SourceCounts["distinct sites"]);
    }

    [Fact]
    public async Task GetDrivesAsync_SkipsContentStorageSearchResults_WhenDiscoveringSites()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "search",
                static request => request.RequestUri?.AbsoluteUri.Contains("/_api/search/query?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "PrimaryQueryResult": {
                        "RelevantResults": {
                          "Table": {
                            "Rows": [
                              {
                                "Cells": [
                                  { "Key": "Title", "Value": "Ignored contentstorage site" },
                                  { "Key": "Path", "Value": "https://contoso.sharepoint.com/contentstorage/CSP_123" }
                                ]
                              },
                              {
                                "Cells": [
                                  { "Key": "Title", "Value": "Finance" },
                                  { "Key": "Path", "Value": "https://contoso.sharepoint.com/sites/Finance" }
                                ]
                              }
                            ]
                          }
                        }
                      }
                    }
                    """)),
            SequenceRoute.Create(
                "libraries",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/Finance/_api/web/lists?", StringComparison.OrdinalIgnoreCase) == true,
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": [
                        {
                          "Id": "list-1",
                          "Title": "Documents",
                          "RootFolder": {
                            "ServerRelativeUrl": "/sites/Finance/Shared Documents"
                          }
                        }
                      ]
                    }
                    """)));

        var restClient = CreateRestClient(handler);
        var connector = new SharePointConnector(
            restClient,
            "tenant-123",
            new Uri("https://contoso.sharepoint.com"),
            NullLogger<SharePointConnector>.Instance,
            useConfiguredTargets: true);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Single(drives);
        Assert.Equal("Finance", drives[0].Name);
        Assert.Equal(1, handler.GetAttemptCount("search"));
        Assert.Equal(1, handler.GetAttemptCount("libraries"));
    }

    [Fact]
    public async Task SharePointRestDrive_ProcessesChanges_AndDownloadsContent()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "files",
                static request => request.RequestUri?.AbsoluteUri.Contains("/GetFolderByServerRelativeUrl(", StringComparison.OrdinalIgnoreCase) == true
                                  && request.RequestUri.AbsoluteUri.Contains("/Files?", StringComparison.OrdinalIgnoreCase),
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": [
                        {
                          "UniqueId": "item-1",
                          "Name": "budget.txt",
                          "ServerRelativeUrl": "/sites/Finance/Shared Documents/budget.txt",
                          "Length": "128"
                        }
                      ]
                    }
                    """)),
            SequenceRoute.Create(
                "folders",
                static request => request.RequestUri?.AbsoluteUri.Contains("/GetFolderByServerRelativeUrl(", StringComparison.OrdinalIgnoreCase) == true
                                  && request.RequestUri.AbsoluteUri.Contains("/Folders?", StringComparison.OrdinalIgnoreCase),
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": []
                    }
                    """)),
            SequenceRoute.Create(
                "content",
                static request => request.RequestUri?.AbsoluteUri.Contains("/GetFileByServerRelativeUrl(", StringComparison.OrdinalIgnoreCase) == true,
                StreamResponse(HttpStatusCode.OK, "tenant-secret")));

        var restClient = CreateRestClient(handler);
        var site = new SharePointRestClient.RestSite("Finance", new Uri("https://contoso.sharepoint.com/sites/Finance"));
        var library = new SharePointRestClient.RestLibrary(
            "list-1",
            "Documents",
            site,
            "/sites/Finance/Shared Documents",
            new Uri("https://contoso.sharepoint.com/sites/Finance/Shared%20Documents"),
            Stratus.Sift.Core.Enums.DatastoreType.SharePoint,
            1);
        var drive = new SharePointRestDrive(restClient, library, "tenant-123", "Finance");

        var files = new List<Stratus.Sift.Connectors.Interfaces.IRemoteFile>();
        var deltaToken = await drive.ProcessChangesAsync(
            null,
            file =>
            {
                files.Add(file);
                return Task.CompletedTask;
            });

        Assert.Single(files);
        Assert.Equal("budget.txt", files[0].Name);
        Assert.Equal(string.Empty, deltaToken);

        await using var stream = await files[0].GetContentAsync();
        Assert.NotNull(stream);
        Assert.Equal("tenant-secret", await ReadStreamAsync(stream!));
        Assert.Equal(1, handler.GetAttemptCount("files"));
        Assert.Equal(1, handler.GetAttemptCount("folders"));
        Assert.Equal(1, handler.GetAttemptCount("content"));
    }

    [Fact]
    public async Task SharePointRestFile_ClassifiesSecurityScannerBlockAsNonRetryable()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "blocked-content",
                static request => request.RequestUri?.AbsoluteUri.Contains("/GetFileByServerRelativeUrl(", StringComparison.OrdinalIgnoreCase) == true,
                XmlResponse(
                    HttpStatusCode.InternalServerError,
                    """
                    <?xml version="1.0" encoding="utf-8"?>
                    <m:error xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
                      <m:code>-2147217328, Microsoft.SharePoint.SPException</m:code>
                      <m:message xml:lang="en-US">The virus scanner discovered an issue while scanning the file. Additional information: 'Phish_Url_WDSTiRanosBlocker_A#'</m:message>
                    </m:error>
                    """)));
        var file = CreateRestFile(handler);

        var exception = await Assert.ThrowsAsync<Stratus.Sift.Connectors.Services.RemoteContentUnavailableException>(() => file.GetContentAsync());

        Assert.False(exception.ShouldRetry);
        Assert.Equal(500, exception.StatusCode);
        Assert.Contains("security scanner flagged", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, handler.GetAttemptCount("blocked-content"));
    }

    [Fact]
    public async Task SharePointRestFile_ClassifiesOrdinaryServerErrorAsRetryable()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "server-error",
                static request => request.RequestUri?.AbsoluteUri.Contains("/GetFileByServerRelativeUrl(", StringComparison.OrdinalIgnoreCase) == true,
                XmlResponse(HttpStatusCode.InternalServerError, "<error>Temporary backend failure</error>")));
        var file = CreateRestFile(handler);

        var exception = await Assert.ThrowsAsync<Stratus.Sift.Connectors.Services.RemoteContentUnavailableException>(() => file.GetContentAsync());

        Assert.True(exception.ShouldRetry);
        Assert.Equal(500, exception.StatusCode);
        Assert.Equal(1, handler.GetAttemptCount("server-error"));
    }

    [Fact]
    public async Task SharePointRestDrive_SkipsMissingLibraryFolder_WhenEnumeratingInitialFiles()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "files",
                static request => request.RequestUri?.AbsoluteUri.Contains("/GetFolderByServerRelativeUrl(", StringComparison.OrdinalIgnoreCase) == true
                                  && request.RequestUri.AbsoluteUri.Contains("/Files?", StringComparison.OrdinalIgnoreCase),
                request => new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request
                }));

        var restClient = CreateRestClient(handler);
        var site = new SharePointRestClient.RestSite("Finance", new Uri("https://contoso.sharepoint.com/sites/Finance"));
        var library = new SharePointRestClient.RestLibrary(
            "list-1",
            "Documents",
            site,
            "/sites/Finance/Shared Documents",
            new Uri("https://contoso.sharepoint.com/sites/Finance/Shared%20Documents"),
            Stratus.Sift.Core.Enums.DatastoreType.SharePoint,
            1);
        var drive = new SharePointRestDrive(restClient, library, "tenant-123", "Finance");

        var files = new List<Stratus.Sift.Connectors.Interfaces.IRemoteFile>();
        var deltaToken = await drive.ProcessChangesAsync(
            null,
            file =>
            {
                files.Add(file);
                return Task.CompletedTask;
            });

        Assert.Empty(files);
        Assert.Equal(string.Empty, deltaToken);
        Assert.Equal(1, handler.GetAttemptCount("files"));
    }

    [Fact]
    public async Task SharePointRestDrive_UsesExpectedListChangesEndpointAndPayload()
    {
        HttpRequestMessage? capturedRequest = null;
        string? capturedBody = null;
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "changes",
                static request => request.RequestUri?.AbsoluteUri.Contains("/GetListItemChangesSinceToken", StringComparison.OrdinalIgnoreCase) == true,
                request =>
                {
                    capturedRequest = request;
                    capturedBody = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult();
                    return XmlResponse(
                        HttpStatusCode.OK,
                        """
                        <listitems xmlns:rs="urn:schemas-microsoft-com:rowset" xmlns:z="#RowsetSchema">
                          <Changes LastChangeToken="token-2" />
                          <rs:data ItemCount="0" />
                        </listitems>
                        """)(request);
                }));

        var restClient = CreateRestClient(handler);
        var site = new SharePointRestClient.RestSite("Finance", new Uri("https://contoso.sharepoint.com/sites/Finance"));
        var library = new SharePointRestClient.RestLibrary(
            "list-1",
            "Documents",
            site,
            "/sites/Finance/Shared Documents",
            new Uri("https://contoso.sharepoint.com/sites/Finance/Shared%20Documents"),
            Stratus.Sift.Core.Enums.DatastoreType.SharePoint,
            1);

        var changeSet = await restClient.GetListItemChangesAsync(library, null, null, CancellationToken.None);

        Assert.Equal("token-2", changeSet.LastChangeToken);
        Assert.NotNull(capturedRequest);
        Assert.Equal(
            "https://contoso.sharepoint.com/sites/Finance/_api/web/lists('list-1')/GetListItemChangesSinceToken",
            capturedRequest!.RequestUri!.AbsoluteUri);
        Assert.NotNull(capturedBody);
        Assert.Contains("\"query\"", capturedBody, StringComparison.Ordinal);
        Assert.Contains("/sites/Finance/Shared Documents", capturedBody, StringComparison.Ordinal);
        Assert.Contains("RecursiveAll", capturedBody, StringComparison.Ordinal);
        Assert.DoesNotContain("\"d\"", capturedBody, StringComparison.Ordinal);
        Assert.DoesNotContain("__metadata", capturedBody, StringComparison.Ordinal);
        Assert.Contains("\"RowLimit\":\"2000\"", capturedBody, StringComparison.Ordinal);
        Assert.Contains("\"ChangeToken\":null", capturedBody, StringComparison.Ordinal);
    }

    private static SharePointRestClient CreateRestClient(HttpMessageHandler handler)
    {
        return new SharePointRestClient(
            new TestTokenCredential(),
            "StratusSnareConnector.Tests",
            new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(15)
            });
    }

    private static SharePointRestFile CreateRestFile(HttpMessageHandler handler)
    {
        var siteUrl = new Uri("https://contoso.sharepoint.com/sites/Finance");
        return new SharePointRestFile(
            CreateRestClient(handler),
            siteUrl,
            new SharePointRestClient.RestFileItem(
                "item-1",
                "budget.xlsx",
                "/sites/Finance/Shared Documents/budget.xlsx",
                new Uri(siteUrl, "/sites/Finance/Shared%20Documents/budget.xlsx"),
                false,
                false,
                128));
    }

    private static async Task<string> ReadStreamAsync(Stream stream)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        return await reader.ReadToEndAsync();
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> JsonResponse(HttpStatusCode statusCode, string json)
    {
        return request => new HttpResponseMessage(statusCode)
        {
            RequestMessage = request,
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> XmlResponse(HttpStatusCode statusCode, string xml)
    {
        return request => new HttpResponseMessage(statusCode)
        {
            RequestMessage = request,
            Content = new StringContent(xml, Encoding.UTF8, "application/xml")
        };
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> StreamResponse(HttpStatusCode statusCode, string content)
    {
        return request =>
        {
            var response = new HttpResponseMessage(statusCode)
            {
                RequestMessage = request,
                Content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(content)))
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
            return response;
        };
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
