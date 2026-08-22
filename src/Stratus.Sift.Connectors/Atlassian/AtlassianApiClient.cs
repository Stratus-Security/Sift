using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

namespace Stratus.Sift.Connectors.Atlassian;

internal sealed class AtlassianApiClient
{
    internal const int MaximumJsonDepth = 256;

    private readonly ILogger? _logger;

    internal AtlassianApiClient(HttpClient httpClient, Uri baseUri, ILogger? logger = null)
    {
        HttpClient = httpClient;
        BaseUri = baseUri;
        _logger = logger;
    }

    internal HttpClient HttpClient { get; }
    internal Uri BaseUri { get; }

    internal Task<JsonDocument> GetJsonAsync(string relativeOrAbsoluteUri, CancellationToken cancellationToken)
    {
        return SendJsonAsync(
            () => new HttpRequestMessage(HttpMethod.Get, ResolveUri(relativeOrAbsoluteUri)),
            cancellationToken);
    }

    internal Task<JsonDocument> PostJsonAsync(string relativeOrAbsoluteUri, JsonNode value, CancellationToken cancellationToken)
    {
        return SendJsonAsync(
            () => new HttpRequestMessage(HttpMethod.Post, ResolveUri(relativeOrAbsoluteUri))
            {
                Content = new StringContent(value.ToJsonString(), System.Text.Encoding.UTF8, "application/json")
            },
            cancellationToken);
    }

    private async Task<JsonDocument> SendJsonAsync(Func<HttpRequestMessage> requestFactory, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            using var request = requestFactory();
            using var response = await HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (IsRetryable(response.StatusCode) && attempt < 3)
            {
                var delay = response.Headers.RetryAfter?.Delta
                    ?? (response.Headers.RetryAfter?.Date - DateTimeOffset.UtcNow)
                    ?? TimeSpan.FromSeconds(Math.Pow(2, attempt + 1));
                if (delay < TimeSpan.Zero)
                {
                    delay = TimeSpan.Zero;
                }

                _logger?.LogWarning(
                    "Atlassian API request to {Uri} returned {StatusCode}; retrying in {Delay}.",
                    request.RequestUri,
                    (int)response.StatusCode,
                    delay);
                await Task.Delay(delay, cancellationToken);
                continue;
            }

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                if (body.Length > 2048)
                {
                    body = body[..2048];
                }

                throw new HttpRequestException(
                    $"Atlassian API request to '{request.RequestUri}' failed with HTTP {(int)response.StatusCode} ({response.ReasonPhrase})"
                    + (string.IsNullOrWhiteSpace(body) ? "." : $": {body}"),
                    inner: null,
                    response.StatusCode);
            }

            return await JsonDocument.ParseAsync(
                await response.Content.ReadAsStreamAsync(cancellationToken),
                new JsonDocumentOptions { MaxDepth = MaximumJsonDepth },
                cancellationToken: cancellationToken);
        }

        throw new InvalidOperationException("Atlassian API retry loop exited unexpectedly.");
    }

    private Uri ResolveUri(string relativeOrAbsoluteUri)
    {
        return Uri.TryCreate(relativeOrAbsoluteUri, UriKind.Absolute, out var absolute)
            ? absolute
            : new Uri(BaseUri, relativeOrAbsoluteUri);
    }

    private static bool IsRetryable(HttpStatusCode statusCode)
    {
        return statusCode is HttpStatusCode.RequestTimeout
            or HttpStatusCode.TooManyRequests
            or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;
    }
}
