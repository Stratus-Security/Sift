using System.Net;

namespace Stratus.Sift.Connectors.Services;

internal sealed class RequestThrottleGate
{
    private static readonly TimeSpan DefaultMaximumGateDelay = TimeSpan.FromSeconds(15);
    private readonly TimeSpan _maximumGateDelay;
    private long _blockedUntilUtcTicks;

    public RequestThrottleGate()
        : this(DefaultMaximumGateDelay)
    {
    }

    internal RequestThrottleGate(TimeSpan maximumGateDelay)
    {
        _maximumGateDelay = maximumGateDelay <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : maximumGateDelay;
    }

    public async ValueTask WaitAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var blockedUntilTicks = Interlocked.Read(ref _blockedUntilUtcTicks);
            if (blockedUntilTicks <= 0)
            {
                return;
            }

            var now = DateTimeOffset.UtcNow;
            var blockedUntil = new DateTimeOffset(blockedUntilTicks, TimeSpan.Zero);
            var delay = blockedUntil - now;
            if (delay <= TimeSpan.Zero)
            {
                return;
            }

            await Task.Delay(delay, cancellationToken);
        }
    }

    public TimeSpan Observe(HttpResponseMessage response, TimeSpan? fallbackDelay = null)
    {
        if (!ShouldThrottle(response.StatusCode))
        {
            return TimeSpan.Zero;
        }

        var delay = response.Headers.RetryAfter?.Delta;
        if ((!delay.HasValue || delay.Value <= TimeSpan.Zero) && response.Headers.RetryAfter?.Date is DateTimeOffset retryAfterDate)
        {
            delay = retryAfterDate - DateTimeOffset.UtcNow;
        }

        return RegisterDelay(delay ?? fallbackDelay ?? TimeSpan.FromSeconds(2));
    }

    public TimeSpan RegisterDelay(TimeSpan delay)
    {
        if (delay <= TimeSpan.Zero)
        {
            delay = TimeSpan.FromSeconds(1);
        }

        if (delay > _maximumGateDelay)
        {
            delay = _maximumGateDelay;
        }

        var blockedUntilTicks = DateTimeOffset.UtcNow.Add(delay).UtcTicks;
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
