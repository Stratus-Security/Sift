using System.Net;
using Azure.Core;
using Microsoft.Graph;
using Microsoft.Kiota.Http.HttpClientLibrary;
using Microsoft.Kiota.Http.HttpClientLibrary.Middleware;
using Microsoft.Kiota.Http.HttpClientLibrary.Middleware.Options;

namespace Stratus.Sift.Connectors.Services;

public static class MicrosoftGraphClientBuilder
{
    private static readonly string[] DefaultScopes = ["https://graph.microsoft.com/.default"];

    internal const int DefaultMaxRetryCount = 10;
    internal const int DefaultRetryDelaySeconds = 5;
    internal static readonly TimeSpan DefaultRetriesTimeLimit = TimeSpan.FromMinutes(2);

    public static GraphServiceClient Create(TokenCredential credential, string productPrefix, TimeSpan? timeout = null)
    {
        return Create(credential, productPrefix, timeout, null, null, null);
    }

    public static GraphServiceClient Create(
        TokenCredential credential,
        string productPrefix,
        IEnumerable<string> scopes,
        TimeSpan? timeout = null)
    {
        return Create(credential, productPrefix, scopes, timeout, null, null, null);
    }

    internal static GraphServiceClient Create(
        TokenCredential credential,
        string productPrefix,
        TimeSpan? timeout,
        HttpMessageHandler? finalHandler,
        RetryHandlerOption? retryOptions)
    {
        return Create(credential, productPrefix, timeout, finalHandler, retryOptions, null);
    }

    internal static GraphServiceClient Create(
        TokenCredential credential,
        string productPrefix,
        TimeSpan? timeout,
        HttpMessageHandler? finalHandler,
        RetryHandlerOption? retryOptions,
        ThrottleNotificationHub? throttleNotifications)
    {
        return Create(credential, productPrefix, DefaultScopes, timeout, finalHandler, retryOptions, throttleNotifications);
    }

    internal static GraphServiceClient Create(
        TokenCredential credential,
        string productPrefix,
        IEnumerable<string> scopes,
        TimeSpan? timeout,
        HttpMessageHandler? finalHandler,
        RetryHandlerOption? retryOptions)
    {
        return Create(credential, productPrefix, scopes, timeout, finalHandler, retryOptions, null);
    }

    internal static GraphServiceClient Create(
        TokenCredential credential,
        string productPrefix,
        IEnumerable<string> scopes,
        TimeSpan? timeout,
        HttpMessageHandler? finalHandler,
        RetryHandlerOption? retryOptions,
        ThrottleNotificationHub? throttleNotifications)
    {
        var httpClient = CreateHttpClient(productPrefix, timeout, finalHandler, retryOptions, throttleNotifications);
        var requestedScopes = scopes
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new GraphServiceClient(
            httpClient,
            credential,
            requestedScopes.Length == 0 ? DefaultScopes : requestedScopes);
    }

    internal static HttpClient CreateHttpClient(
        string productPrefix,
        TimeSpan? timeout = null,
        HttpMessageHandler? finalHandler = null,
        RetryHandlerOption? retryOptions = null,
        ThrottleNotificationHub? throttleNotifications = null)
    {
        var handlers = CreateHandlers(productPrefix, retryOptions, throttleNotifications);
        var httpClient = KiotaClientFactory.Create(handlers, finalHandler ?? new HttpClientHandler());
        httpClient.Timeout = timeout ?? TimeSpan.FromMinutes(5);
        return httpClient;
    }

    internal static IList<DelegatingHandler> CreateHandlers(string productPrefix, RetryHandlerOption? retryOptions = null, ThrottleNotificationHub? throttleNotifications = null)
    {
        var throttleGate = new RequestThrottleGate();
        var handlers = GraphClientFactory.CreateDefaultHandlers(new GraphClientOptions
        {
            GraphProductPrefix = productPrefix
        });

        var retryHandler = new RetryHandler(retryOptions ?? CreateRetryOptions(throttleGate, throttleNotifications));
        var replaced = false;
        for (var i = 0; i < handlers.Count; i++)
        {
            if (handlers[i] is RetryHandler)
            {
                handlers[i] = retryHandler;
                replaced = true;
                break;
            }
        }

        if (!replaced)
        {
            handlers.Add(retryHandler);
        }

        handlers.Insert(0, new ThrottleGateHandler(throttleGate, throttleNotifications));
        return handlers;
    }

    internal static RetryHandlerOption CreateRetryOptions(RequestThrottleGate? throttleGate = null, ThrottleNotificationHub? throttleNotifications = null)
    {
        return new RetryHandlerOption
        {
            MaxRetry = DefaultMaxRetryCount,
            Delay = DefaultRetryDelaySeconds,
            RetriesTimeLimit = DefaultRetriesTimeLimit,
            ShouldRetry = (_, _, response) =>
            {
                if (response == null || response.IsSuccessStatusCode)
                {
                    return false;
                }

                var shouldRetry = response.StatusCode is HttpStatusCode.TooManyRequests
                    or HttpStatusCode.ServiceUnavailable
                    or HttpStatusCode.GatewayTimeout;

                if (shouldRetry)
                {
                    var retryDelay = response.Headers.RetryAfter?.Delta;
                    if ((!retryDelay.HasValue || retryDelay.Value <= TimeSpan.Zero) && response.Headers.RetryAfter?.Date is DateTimeOffset retryAfterDate)
                    {
                        retryDelay = retryAfterDate - DateTimeOffset.UtcNow;
                    }

                    retryDelay ??= TimeSpan.FromSeconds(DefaultRetryDelaySeconds);
                    var gateDelay = throttleGate?.Observe(response, retryDelay) ?? retryDelay.Value;
                    throttleNotifications?.Report("Microsoft Graph", response.StatusCode, retryDelay.Value, gateDelay, "graph.microsoft.com");
                }

                return shouldRetry;
            }
        };
    }

    private sealed class ThrottleGateHandler(RequestThrottleGate throttleGate, ThrottleNotificationHub? throttleNotifications) : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await throttleGate.WaitAsync(cancellationToken);

            var response = await base.SendAsync(request, cancellationToken);
            if (RequestThrottleGate.ShouldThrottle(response.StatusCode))
            {
                var retryDelay = response.Headers.RetryAfter?.Delta;
                if ((!retryDelay.HasValue || retryDelay.Value <= TimeSpan.Zero) && response.Headers.RetryAfter?.Date is DateTimeOffset retryAfterDate)
                {
                    retryDelay = retryAfterDate - DateTimeOffset.UtcNow;
                }

                retryDelay ??= TimeSpan.FromSeconds(DefaultRetryDelaySeconds);
                var gateDelay = throttleGate.Observe(response, retryDelay);
                throttleNotifications?.Report("Microsoft Graph", response.StatusCode, retryDelay.Value, gateDelay, "graph.microsoft.com");
            }

            return response;
        }
    }
}
