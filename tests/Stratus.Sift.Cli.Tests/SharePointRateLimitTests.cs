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
    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    public async Task GraphClient_SharedPauseObservesSdkRetryResponsesAndBlocksOtherRequests(HttpStatusCode status)
    {
        var observed = new TaskCompletionSource<ThrottleNotice>(TaskCreationOptions.RunContinuationsAsynchronously);
        var hub = new ThrottleNotificationHub();
        var notices = 0;
        hub.Updated += notice => { Interlocked.Increment(ref notices); observed.TrySetResult(notice); };
        var firstAttempts = 0;
        var secondAttempts = 0;
        var prematureRequests = 0;
        var handler = new DelegateHttpMessageHandler((request, _) =>
        {
            var first = request.RequestUri!.AbsolutePath.EndsWith("/first", StringComparison.Ordinal);
            HttpResponseMessage response;
            if (first && Interlocked.Increment(ref firstAttempts) == 1)
            {
                response = RateLimitedResponse(status, 1)(request);
            }
            else
            {
                if (!first) Interlocked.Increment(ref secondAttempts);
                if (hub.Latest?.RemainingGlobalPause > TimeSpan.Zero) Interlocked.Increment(ref prematureRequests);
                response = JsonResponse(HttpStatusCode.OK, "{}")(request);
            }
            return Task.FromResult(response);
        });
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var client = MicrosoftGraphClientBuilder.CreateHttpClient("Tests", finalHandler: handler, throttleNotifications: hub);
        var tasks = new List<Task<HttpResponseMessage>>
        {
            client.GetAsync("https://graph.microsoft.com/v1.0/first", cancellation.Token)
        };
        try
        {
            // A successful internal retry must not hide the initial throttle response.
            await Task.WhenAny(tasks[0], observed.Task).WaitAsync(cancellation.Token);
            Assert.True(observed.Task.IsCompletedSuccessfully, "The shared gate must observe throttling before the SDK retries.");
            Assert.Equal(status, (await observed.Task).StatusCode);
            tasks.Add(client.GetAsync("https://graph.microsoft.com/v1.0/second", cancellation.Token));
            await Task.WhenAll(tasks);

            Assert.Equal(2, firstAttempts);
            Assert.Equal(1, secondAttempts);
            Assert.Equal(0, prematureRequests);
            Assert.Equal(1, notices);
        }
        finally
        {
            cancellation.Cancel();
            await DrainRequestsAsync(tasks);
        }
    }

    [Fact]
    public async Task GraphClient_InFlightRetryHonorsAnotherRequestsLongerSharedPause()
    {
        var firstEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstResponse = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondResponse = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var shortPause = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var longPause = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstAttempts = 0;
        var hub = new ThrottleNotificationHub();
        hub.Updated += notice =>
        {
            if (notice.RetryDelay == TimeSpan.FromSeconds(1)) shortPause.TrySetResult();
            if (notice.RetryDelay == TimeSpan.FromSeconds(60)) longPause.TrySetResult();
        };
        var handler = new DelegateHttpMessageHandler(async (request, ct) =>
        {
            HttpResponseMessage response;
            if (request.RequestUri!.AbsolutePath.EndsWith("/first", StringComparison.Ordinal))
            {
                if (Interlocked.Increment(ref firstAttempts) == 1)
                {
                    firstEntered.TrySetResult();
                    response = await firstResponse.Task.WaitAsync(ct);
                }
                else response = JsonResponse(HttpStatusCode.OK, "{}")(request);
            }
            else
            {
                secondEntered.TrySetResult();
                response = await secondResponse.Task.WaitAsync(ct);
            }
            response.RequestMessage = request;
            return response;
        });
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var client = MicrosoftGraphClientBuilder.CreateHttpClient("Tests", finalHandler: handler, throttleNotifications: hub);
        var tasks = new List<Task<HttpResponseMessage>>();
        try
        {
            tasks.Add(client.GetAsync("https://graph.microsoft.com/v1.0/first", cancellation.Token));
            await firstEntered.Task.WaitAsync(cancellation.Token);
            tasks.Add(client.GetAsync("https://graph.microsoft.com/v1.0/second", cancellation.Token));
            await secondEntered.Task.WaitAsync(cancellation.Token);
            firstResponse.SetResult(new(HttpStatusCode.TooManyRequests)
                { Content = new StringContent("{}"), Headers = { RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(1)) } });
            await shortPause.Task.WaitAsync(cancellation.Token);
            secondResponse.SetResult(new(HttpStatusCode.TooManyRequests)
                { Content = new StringContent("{}"), Headers = { RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(60)) } });
            await longPause.Task.WaitAsync(cancellation.Token);

            await Task.Delay(TimeSpan.FromMilliseconds(1500), cancellation.Token);
            Assert.Equal(1, firstAttempts);
            Assert.True(hub.Latest!.RemainingGlobalPause > TimeSpan.FromSeconds(50));
            cancellation.Cancel();
            foreach (var task in tasks) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        }
        finally
        {
            cancellation.Cancel();
            await DrainRequestsAsync(tasks);
        }
    }

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
        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Contains("incomplete", connector.DiscoveryReport.Coverage, StringComparison.Ordinal);
        Assert.Equal(1, connector.DiscoveryReport.SourceCounts["discovery failures"]);
        Assert.Single(connector.DiscoveryReport.Warnings);
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RequestThrottleGate_HoldsAllWaitersForFullRetryAfter(bool dateHeader)
    {
        var time = new ManualTimeProvider();
        var gate = new RequestThrottleGate(time);
        using var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = dateHeader
            ? new RetryConditionHeaderValue(time.GetUtcNow().AddSeconds(120))
            : new RetryConditionHeaderValue(TimeSpan.FromSeconds(120));
        Assert.Equal(TimeSpan.FromSeconds(120), gate.Observe(response));
        // A shorter response must not shorten the existing tenant pause.
        gate.RegisterDelay(TimeSpan.FromSeconds(2));
        var waiters = Enumerable.Range(0, 4).Select(_ => gate.WaitAsync(CancellationToken.None).AsTask()).ToArray();

        time.Advance(TimeSpan.FromSeconds(15));
        Assert.All(waiters, waiter => Assert.False(waiter.IsCompleted));
        time.Advance(TimeSpan.FromSeconds(104));
        Assert.All(waiters, waiter => Assert.False(waiter.IsCompleted));
        time.Advance(TimeSpan.FromSeconds(1));
        await Task.WhenAll(waiters).WaitAsync(TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task RequestThrottleGate_LongPauseRemainsCancellable()
    {
        var gate = new RequestThrottleGate(new ManualTimeProvider());
        gate.RegisterDelay(TimeSpan.FromMinutes(2));
        using var cancellation = new CancellationTokenSource();
        var waiting = gate.WaitAsync(cancellation.Token).AsTask();

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(TimeSpan.FromSeconds(3)));
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
            "StratusSiftConnector.Tests",
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

    private static async Task DrainRequestsAsync(IEnumerable<Task<HttpResponseMessage>> tasks)
    {
        foreach (var task in tasks)
        {
            try { using var response = await task; }
            catch (OperationCanceledException) { }
        }
    }

    private sealed class DelegateHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => callback(request, ct);
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        private readonly List<ManualTimer> _timers = [];
        private readonly object _sync = new();

        public override DateTimeOffset GetUtcNow() { lock (_sync) return _now; }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(this, callback, state);
            timer.Change(dueTime, period);
            return timer;
        }

        public void Advance(TimeSpan elapsed)
        {
            List<ManualTimer> due;
            lock (_sync)
            {
                _now += elapsed;
                due = _timers.Where(timer => timer.Due <= _now).ToList();
                foreach (var timer in due) _timers.Remove(timer);
            }
            foreach (var timer in due) timer.Fire();
        }

        private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state) : ITimer
        {
            public DateTimeOffset Due { get; private set; }
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (owner._sync)
                {
                    owner._timers.Remove(this);
                    if (dueTime != Timeout.InfiniteTimeSpan)
                    {
                        Due = owner._now + dueTime;
                        owner._timers.Add(this);
                    }
                }
                return true;
            }
            public void Fire() => callback(state);
            public void Dispose() { lock (owner._sync) owner._timers.Remove(this); }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
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



