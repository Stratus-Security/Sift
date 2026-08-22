using Microsoft.Kiota.Abstractions;
using Stratus.Sift.Connectors.Services;

namespace Stratus.Sift.Connectors.SharePoint;

internal static class SharePointContentExceptionClassifier
{
    private static readonly string[] SecurityBlockMarkers =
    [
        "virus scanner discovered an issue",
        "Phish_Url_",
        "malware was detected",
        "virus-infected"
    ];

    internal static bool TryWrap(
        Exception exception,
        CancellationToken cancellationToken,
        out RemoteContentUnavailableException wrapped)
    {
        wrapped = null!;

        if (exception is OperationCanceledException && cancellationToken.IsCancellationRequested)
        {
            return false;
        }

        var statusCode = TryGetStatusCode(exception);
        var securityBlocked = ContainsSecurityBlockMarker(exception);
        var shouldRetry = !securityBlocked
            && (IsRetryableStatus(statusCode)
                || HasRetryableTransportFailure(exception)
                || HasRetryableStatusInMessage(exception));

        var message = securityBlocked
            ? "SharePoint blocked the content download because its security scanner flagged the file. Open it directly in SharePoint or contact the SharePoint administrator."
            : statusCode is null
                ? "Remote content could not be downloaded."
                : $"Remote content download failed with HTTP {statusCode}.";

        wrapped = new RemoteContentUnavailableException(
            message,
            shouldRetry,
            statusCode,
            exception);
        return true;
    }

    private static bool IsRetryableStatus(int? statusCode)
        => statusCode is 408 or 429 or 500 or 502 or 503 or 504;

    private static int? TryGetStatusCode(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            if (current is ApiException apiException)
            {
                return apiException.ResponseStatusCode;
            }

            if (current is HttpRequestException httpRequestException && httpRequestException.StatusCode.HasValue)
            {
                return (int)httpRequestException.StatusCode.Value;
            }
        }

        return null;
    }

    private static bool ContainsSecurityBlockMarker(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            if (SecurityBlockMarkers.Any(marker => current.Message.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasRetryableTransportFailure(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            if (current is HttpRequestException httpRequestException && !httpRequestException.StatusCode.HasValue)
            {
                return true;
            }

            if (current is TimeoutException or OperationCanceledException)
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasRetryableStatusInMessage(Exception exception)
    {
        for (Exception? current = exception; current != null; current = current.InnerException)
        {
            var message = current.Message;
            if (message.Contains("408", StringComparison.OrdinalIgnoreCase)
                || message.Contains("request timeout", StringComparison.OrdinalIgnoreCase)
                || message.Contains("429", StringComparison.OrdinalIgnoreCase)
                || message.Contains("too many requests", StringComparison.OrdinalIgnoreCase)
                || message.Contains("500", StringComparison.OrdinalIgnoreCase)
                || message.Contains("internal server error", StringComparison.OrdinalIgnoreCase)
                || message.Contains("502", StringComparison.OrdinalIgnoreCase)
                || message.Contains("bad gateway", StringComparison.OrdinalIgnoreCase)
                || message.Contains("503", StringComparison.OrdinalIgnoreCase)
                || message.Contains("service unavailable", StringComparison.OrdinalIgnoreCase)
                || message.Contains("504", StringComparison.OrdinalIgnoreCase)
                || message.Contains("gateway timeout", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
