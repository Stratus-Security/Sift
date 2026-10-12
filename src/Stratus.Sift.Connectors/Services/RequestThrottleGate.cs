using System.Net;

namespace Stratus.Sift.Connectors.Services;

internal sealed class RequestThrottleGate
{
    private readonly TimeProvider _timeProvider;
    private long _blockedUntilUtcTicks;

    public RequestThrottleGate(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async ValueTask WaitAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var blockedUntilTicks = Interlocked.Read(ref _blockedUntilUtcTicks);
            if (blockedUntilTicks <= 0)
            {
                return;
            }

            var now = _timeProvider.GetUtcNow();
            var blockedUntil = new DateTimeOffset(blockedUntilTicks, TimeSpan.Zero);
            var delay = blockedUntil - now;
            if (delay <= TimeSpan.Zero)
            {
                return;
            }

            // Split very long waits to stay within Task.Delay's supported timer range.
            await Task.Delay(delay > TimeSpan.FromDays(1) ? TimeSpan.FromDays(1) : delay, _timeProvider, cancellationToken);
        }
    }

    public TimeSpan Observe(HttpResponseMessage response, TimeSpan? fallbackDelay = null)
    {
        if (!ShouldThrottle(response.StatusCode))
        {
            return TimeSpan.Zero;
        }

        var delay = GetRetryAfterDelay(response, _timeProvider.GetUtcNow());
        return RegisterDelay(delay ?? fallbackDelay ?? TimeSpan.FromSeconds(2));
    }

    internal static TimeSpan? GetRetryAfterDelay(HttpResponseMessage response, DateTimeOffset now)
    {
        if (response.Headers.RetryAfter?.Delta is { } delta) return delta;
        return response.Headers.RetryAfter?.Date is { } date ? date - now : null;
    }

    public TimeSpan RegisterDelay(TimeSpan delay)
    {
        if (delay <= TimeSpan.Zero)
        {
            delay = TimeSpan.FromSeconds(1);
        }

        var nowTicks = _timeProvider.GetUtcNow().UtcTicks;
        var blockedUntilTicks = nowTicks + Math.Min(delay.Ticks, DateTimeOffset.MaxValue.UtcTicks - nowTicks);
        while (true)
        {
            var currentTicks = Interlocked.Read(ref _blockedUntilUtcTicks);
            if (currentTicks >= blockedUntilTicks)
            {
                return delay;
            }

            if (Interlocked.CompareExchange(ref _blockedUntilUtcTicks, blockedUntilTicks, currentTicks) == currentTicks)
            {
                return delay;
            }
        }
    }

    public static bool ShouldThrottle(HttpStatusCode statusCode)
    {
        return statusCode is HttpStatusCode.TooManyRequests
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;
    }
}
