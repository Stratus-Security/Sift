using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Azure;
using Azure.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Http.HttpClientLibrary.Middleware.Options;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Connectors.SharePoint;

namespace Stratus.Sift.Connectors.Tests;

public class SharePointRateLimitTests
{
    [Fact]
    public async Task GetDrivesAsync_RetriesSiteEnumeration_On429_AndHonorsRetryAfter()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "sites",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/getAllSites", StringComparison.OrdinalIgnoreCase) == true,
                RateLimitedResponse(HttpStatusCode.TooManyRequests, retryAfterSeconds: 1),
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": [
                        {
                          "id": "site-1",
                          "name": "Finance",
                          "displayName": "Finance",
                          "webUrl": "https://contoso.sharepoint.com/sites/Finance",
                          "createdDateTime": "2026-03-18T00:00:00Z"
                        }
                      ]
                    }
                    """)
            ),
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
                    """)
            ));

        var graphClient = CreateGraphClient(handler);
        var connector = new SharePointConnector(graphClient, "tenant-1", NullLogger<SharePointConnector>.Instance);

        var stopwatch = Stopwatch.StartNew();
        var drives = (await connector.GetDrivesAsync()).ToList();
        stopwatch.Stop();

        Assert.Single(drives);
        Assert.Equal("Finance", drives[0].Name);
        Assert.Equal(2, handler.GetAttemptCount("sites"));
        Assert.InRange(stopwatch.ElapsedMilliseconds, 900, 15000);
    }

    [Fact]
    public async Task GetDrivesAsync_ReturnsPartialResults_WhenNextSitePageStaysRateLimited()
    {
        var retryOptions = MicrosoftGraphClientBuilder.CreateRetryOptions();
        retryOptions.MaxRetry = 1;
        retryOptions.Delay = 0;
        retryOptions.RetriesTimeLimit = TimeSpan.FromSeconds(1);

        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "sites-page-1",
                static request => request.RequestUri?.AbsoluteUri.Contains("/sites/getAllSites", StringComparison.OrdinalIgnoreCase) == true
                    && request.RequestUri?.AbsoluteUri.Contains("page=2", StringComparison.OrdinalIgnoreCase) != true,
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
                      ],
                      "@odata.nextLink": "https://graph.microsoft.com/v1.0/sites/getAllSites?page=2"
                    }
                    """)
            ),
            SequenceRoute.Create(
                "sites-page-2",
                static request => request.RequestUri?.AbsoluteUri.Contains("page=2", StringComparison.OrdinalIgnoreCase) == true,
                RateLimitedResponse(HttpStatusCode.ServiceUnavailable, retryAfterSeconds: 0),
                RateLimitedResponse(HttpStatusCode.ServiceUnavailable, retryAfterSeconds: 0)
            ),
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
                    """)
            ));

        var graphClient = CreateGraphClient(handler, retryOptions);
        var connector = new SharePointConnector(graphClient, "tenant-1", NullLogger<SharePointConnector>.Instance);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Single(drives);
        Assert.Equal("Finance", drives[0].Name);
        Assert.Equal(2, handler.GetAttemptCount("sites-page-2"));
    }

    [Fact]
    public async Task ProcessChangesAsync_RetriesDeltaEnumeration_On503_AndHonorsRetryAfter()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "delta",
                static request => request.RequestUri?.AbsoluteUri.Contains("/drives/drive-1/items/root/delta", StringComparison.OrdinalIgnoreCase) == true,
                RateLimitedResponse(HttpStatusCode.ServiceUnavailable, retryAfterSeconds: 1),
                JsonResponse(
                    HttpStatusCode.OK,
                    """
                    {
                      "value": [
                        {
                          "id": "item-1",
                          "name": "budget.txt",
                          "webUrl": "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/budget.txt",
                          "size": 128,
                          "file": {
                            "mimeType": "text/plain"
                          }
                        }
                      ],
                      "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/drive-1/items/root/delta?token=next"
                    }
                    """)
            ));

        var graphClient = CreateGraphClient(handler);
        var drive = new SharePointDrive(
            graphClient,
            new Drive
            {
                Id = "drive-1",
                Name = "Finance",
                WebUrl = "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents"
            },
            tenantId: "tenant-1");

        var files = new List<string>();
        var stopwatch = Stopwatch.StartNew();
        var deltaToken = await drive.ProcessChangesAsync(
            deltaToken: null,
            onChange: file =>
            {
                files.Add(file.Name);
                return Task.CompletedTask;
            });
        stopwatch.Stop();

        Assert.Single(files);
        Assert.Equal("budget.txt", files[0]);
        Assert.Equal("https://graph.microsoft.com/v1.0/drives/drive-1/items/root/delta?token=next", deltaToken);
        Assert.Equal(2, handler.GetAttemptCount("delta"));
        Assert.InRange(stopwatch.ElapsedMilliseconds, 900, 15000);
    }

    [Fact]
    public async Task GetContentAsync_RetriesContentDownload_On429_AndHonorsRetryAfter()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "content",
                static request => request.RequestUri?.AbsoluteUri.Contains("/drives/drive-1/items/item-1/content", StringComparison.OrdinalIgnoreCase) == true,
                RateLimitedResponse(HttpStatusCode.TooManyRequests, retryAfterSeconds: 1),
                StreamResponse(HttpStatusCode.OK, "tenant-secret")
            ));

        var graphClient = CreateGraphClient(handler);
        var file = new SharePointFile(graphClient, "drive-1", CreateDriveItem("item-1", "budget.txt"), "tenant-1");

        var stopwatch = Stopwatch.StartNew();
        await using var stream = await file.GetContentAsync();
        stopwatch.Stop();

        Assert.NotNull(stream);
        Assert.Equal("tenant-secret", await ReadStreamAsync(stream!));
        Assert.Equal(2, handler.GetAttemptCount("content"));
        Assert.InRange(stopwatch.ElapsedMilliseconds, 900, 15000);
    }

    [Fact]
    public async Task GetContentRangeAsync_RetriesRangeDownload_On503_AndPreservesRangeHeader()
    {
        string? rangeHeader = null;
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "range-content",
                request =>
                {
                    request.Headers.TryGetValues("Range", out var values);
                    rangeHeader = values?.SingleOrDefault();
                    return request.RequestUri?.AbsoluteUri.Contains("/drives/drive-1/items/item-1/content", StringComparison.OrdinalIgnoreCase) == true;
                },
                RateLimitedResponse(HttpStatusCode.ServiceUnavailable, retryAfterSeconds: 1),
                StreamResponse(HttpStatusCode.PartialContent, "partial-secret")
            ));

        var graphClient = CreateGraphClient(handler);
        var file = new SharePointFile(graphClient, "drive-1", CreateDriveItem("item-1", "budget.txt"), "tenant-1");

        var stopwatch = Stopwatch.StartNew();
        await using var stream = await file.GetContentRangeAsync(0, 15);
        stopwatch.Stop();

        Assert.NotNull(stream);
        Assert.Equal("partial-secret", await ReadStreamAsync(stream!));
        Assert.Equal("bytes=0-15", rangeHeader);
        Assert.Equal(2, handler.GetAttemptCount("range-content"));
        Assert.InRange(stopwatch.ElapsedMilliseconds, 900, 15000);
    }

    [Fact]
    public async Task GetContentAsync_ThrowsRetryableRemoteContentUnavailable_WhenRateLimitPersists()
    {
        var retryOptions = MicrosoftGraphClientBuilder.CreateRetryOptions();
        retryOptions.MaxRetry = 1;
        retryOptions.Delay = 0;
        retryOptions.RetriesTimeLimit = TimeSpan.FromSeconds(1);

        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "content-rate-limited",
                static request => request.RequestUri?.AbsoluteUri.Contains("/drives/drive-1/items/item-1/content", StringComparison.OrdinalIgnoreCase) == true,
                RateLimitedResponse(HttpStatusCode.TooManyRequests, retryAfterSeconds: 0),
                RateLimitedResponse(HttpStatusCode.TooManyRequests, retryAfterSeconds: 0)));

        var graphClient = CreateGraphClient(handler, retryOptions);
        var file = new SharePointFile(graphClient, "drive-1", CreateDriveItem("item-1", "budget.txt"), "tenant-1");

        var exception = await Assert.ThrowsAsync<RemoteContentUnavailableException>(() => file.GetContentAsync());

        Assert.True(exception.ShouldRetry);
        Assert.Equal(429, exception.StatusCode);
        Assert.Equal(2, handler.GetAttemptCount("content-rate-limited"));
    }

    [Fact]
    public async Task RequestThrottleGate_CapsGlobalPause_EvenWhenObservedDelayIsLong()
    {
        var gate = new RequestThrottleGate(TimeSpan.FromMilliseconds(150));
        gate.RegisterDelay(TimeSpan.FromSeconds(5));

        var stopwatch = Stopwatch.StartNew();
        await gate.WaitAsync(CancellationToken.None);
        stopwatch.Stop();

        Assert.InRange(stopwatch.ElapsedMilliseconds, 100, 1500);
    }

    [Fact]
    public async Task GetContentAsync_ThrowsNonRetryableRemoteContentUnavailable_On404()
    {
        var handler = new SequenceHttpMessageHandler(
            SequenceRoute.Create(
                "content-not-found",
                static request => request.RequestUri?.AbsoluteUri.Contains("/drives/drive-1/items/item-1/content", StringComparison.OrdinalIgnoreCase) == true,
                request => new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    RequestMessage = request,
                    Content = new StringContent("{}", Encoding.UTF8, "application/json")
                }));

        var graphClient = CreateGraphClient(handler);
        var file = new SharePointFile(graphClient, "drive-1", CreateDriveItem("item-1", "budget.txt"), "tenant-1");

        var exception = await Assert.ThrowsAsync<RemoteContentUnavailableException>(() => file.GetContentAsync());

        Assert.False(exception.ShouldRetry);
        Assert.Equal(404, exception.StatusCode);
    }
    private static DriveItem CreateDriveItem(string id, string name)
    {
        return new DriveItem
        {
            Id = id,
            Name = name,
            File = new Microsoft.Graph.Models.FileObject
            {
                MimeType = "text/plain"
            },
            WebUrl = $"https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/{name}"
        };
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

    private static async Task<string> ReadStreamAsync(Stream stream)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        return await reader.ReadToEndAsync();
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> JsonResponse(HttpStatusCode statusCode, string json)
    {
        return request =>
        {
            var response = new HttpResponseMessage(statusCode)
            {
                RequestMessage = request,
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };

            return response;
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

    private static Func<HttpRequestMessage, HttpResponseMessage> RateLimitedResponse(HttpStatusCode statusCode, int retryAfterSeconds)
    {
        return request =>
        {
            var response = new HttpResponseMessage(statusCode)
            {
                RequestMessage = request,
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(retryAfterSeconds));
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



