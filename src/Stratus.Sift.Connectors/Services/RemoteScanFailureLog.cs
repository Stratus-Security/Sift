using Microsoft.Extensions.Logging;
using Microsoft.Kiota.Abstractions;
using Azure.Identity;

namespace Stratus.Sift.Connectors.Services;

internal static class RemoteScanExceptionClassifier
{
    // A missing file can be a normal race; a missing collection/continuation
    // endpoint may be a routing bug and must remain visible.
    internal static bool IsExpectedForEnumeration(Exception exception) => exception switch
    {
        AggregateException aggregate => aggregate.InnerExceptions.Count > 0
            && aggregate.InnerExceptions.All(IsExpectedForEnumeration),
        HttpRequestException { StatusCode: System.Net.HttpStatusCode.NotFound } => false,
        ApiException { ResponseStatusCode: 404 } => false,
        _ => IsExpected(exception)
    };

    internal static bool IsExpected(Exception exception) => exception switch
    {
        AggregateException aggregate => aggregate.InnerExceptions.Count > 0
            && aggregate.InnerExceptions.All(IsExpected),
        UnauthorizedAccessException or FileNotFoundException or DirectoryNotFoundException => true,
        AuthenticationRequiredException or CredentialUnavailableException => true,
        AuthenticationFailedException auth => new[] { "AADSTS65001", "AADSTS65002", "AADSTS65004", "AADSTS90094", "AADSTS50105", "AADSTS650052" }
            .Any(code => auth.Message.Contains(code, StringComparison.Ordinal)),
        HttpRequestException { StatusCode: System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.NotFound } => true,
        ApiException { ResponseStatusCode: 403 or 404 } => true,
        RemoteContentUnavailableException unavailable => unavailable.IsExpected || unavailable.StatusCode is 403 or 404
            || unavailable.InnerException != null && IsExpected(unavailable.InnerException),
        InvalidDataException invalid => invalid.Message is "Directory sharing group cannot be classified without Graph access."
            or "SharePoint item permissions require native access."
            or "Recycle-bin inventory requires SharePoint-native access."
            or "Delegated Graph permissions may only show grants visible to the caller; native permission reconciliation is required."
            || invalid.Message == "Library field values could not be read." && invalid.InnerException != null && IsExpected(invalid.InnerException),
        IOException io => (io.HResult & 0xffff) is 2 or 3 or 5 or 32 or 33,
        _ => false
    };
}

internal sealed class RemoteScanFailureLog(ILogger logger)
{
    private readonly HashSet<string> _warnings = new(StringComparer.Ordinal);
    private long _unexpected;
    internal bool HasUnexpectedFailures => Interlocked.Read(ref _unexpected) > 0;

    internal void Reset()
    {
        Interlocked.Exchange(ref _unexpected, 0);
        lock (_warnings) _warnings.Clear();
    }

    internal void Record(string description, string path, Exception? exception = null, bool? expected = null, string? detail = null)
    {
        logger.LogDebug(exception, "{Description} {ItemPath}. {Reason}", description, path, detail ?? exception?.Message ?? "");
        if (expected ?? (exception != null && RemoteScanExceptionClassifier.IsExpected(exception))) return;
        Interlocked.Increment(ref _unexpected);
        var reason = (detail ?? exception?.Message ?? "").Replace('\r', ' ').Replace('\n', ' ');
        if (reason.Length > 1024) reason = reason[..1024] + "...";
        lock (_warnings)
        {
            if (_warnings.Count >= 8 || !_warnings.Add(description + ":" + exception?.GetType().Name + ":" + reason)) return;
            logger.LogWarning("{Description} {ItemPath}. {Reason}", description, path, reason);
        }
    }

    internal void WriteSummary(string drive, long content, long inspection, long additional, long deferred, long folders = 0)
    {
        if (content + inspection + additional + deferred + folders == 0) return;
        logger.Log(HasUnexpectedFailures ? LogLevel.Warning : LogLevel.Information,
            "Drive {DriveName} remains incomplete: {ContentCount} content scans, {InspectionCount} metadata/sharing inspections, {AdditionalCount} additional-content inspections, {DeferredCount} deferred reads, {FolderCount} source inspections remain pending. Resume state is preserved; individual diagnostics are available at debug level.",
            drive, content, inspection, additional, deferred, folders);
    }
}
