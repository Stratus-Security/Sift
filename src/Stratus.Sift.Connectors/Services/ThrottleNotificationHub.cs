using System.Net;

namespace Stratus.Sift.Connectors.Services;

public sealed class ThrottleNotificationHub
{
    private readonly object _lock = new();
    private ThrottleNotice? _latest;

    public event Action<ThrottleNotice>? Updated;

    public ThrottleNotice? Latest
    {
        get
        {
            lock (_lock)
            {
                return _latest;
            }
        }
    }

    public void Report(string service, HttpStatusCode statusCode, TimeSpan retryDelay, TimeSpan globalPause, string? resource = null)
    {
        var notice = new ThrottleNotice(
            service,
            statusCode,
            retryDelay <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : retryDelay,
            globalPause <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : globalPause,
            resource,
            DateTimeOffset.UtcNow);

        lock (_lock)
        {
            _latest = notice;
        }

        Updated?.Invoke(notice);
    }
}

public sealed record ThrottleNotice(
    string Service,
    HttpStatusCode StatusCode,
    TimeSpan RetryDelay,
    TimeSpan GlobalPause,
    string? Resource,
    DateTimeOffset ObservedAt)
{
    public TimeSpan RemainingGlobalPause
    {
        get
        {
            var remaining = ObservedAt + GlobalPause - DateTimeOffset.UtcNow;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }
    }
}
