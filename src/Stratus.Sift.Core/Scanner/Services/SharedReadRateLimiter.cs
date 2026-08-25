namespace Stratus.Sift.Scanner.Services;

internal sealed class SharedReadRateLimiter
{
    private readonly object _gate = new();
    private readonly TimeProvider _timeProvider;
    private readonly Func<TimeSpan, TimeProvider, CancellationToken, ValueTask> _delayAsync;
    private long _configuredRate;
    private double _availableBytes;
    private long _lastTimestamp;

    public SharedReadRateLimiter()
        : this(TimeProvider.System)
    {
    }

    internal SharedReadRateLimiter(
        TimeProvider timeProvider,
        Func<TimeSpan, TimeProvider, CancellationToken, ValueTask>? delayAsync = null)
    {
        _timeProvider = timeProvider;
        _delayAsync = delayAsync ?? (static (delay, provider, cancellationToken) =>
            new ValueTask(Task.Delay(delay, provider, cancellationToken)));
        _lastTimestamp = timeProvider.GetTimestamp();
    }

    public async ValueTask<TimeSpan> AcquireAsync(
        int bytes,
        long bytesPerSecond,
        CancellationToken cancellationToken)
    {
        if (bytes <= 0 || bytesPerSecond <= 0) return TimeSpan.Zero;

        var totalWait = TimeSpan.Zero;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TimeSpan delay;
            lock (_gate)
            {
                var now = _timeProvider.GetTimestamp();
                if (_configuredRate != bytesPerSecond)
                {
                    _configuredRate = bytesPerSecond;
                    _availableBytes = Math.Max(bytesPerSecond, bytes);
                    _lastTimestamp = now;
                }

                var burstCapacity = Math.Max(bytesPerSecond, bytes);
                var elapsed = _timeProvider.GetElapsedTime(_lastTimestamp, now).TotalSeconds;
                if (elapsed > 0)
                {
                    _availableBytes = Math.Min(burstCapacity, _availableBytes + (elapsed * bytesPerSecond));
                    _lastTimestamp = now;
                }

                if (_availableBytes >= bytes)
                {
                    _availableBytes -= bytes;
                    return totalWait;
                }

                var missingBytes = bytes - _availableBytes;
                delay = TimeSpan.FromSeconds(missingBytes / bytesPerSecond);
            }

            var waitStarted = _timeProvider.GetTimestamp();
            await _delayAsync(
                delay < TimeSpan.FromMilliseconds(1) ? TimeSpan.FromMilliseconds(1) : delay,
                _timeProvider,
                cancellationToken);
            totalWait += _timeProvider.GetElapsedTime(waitStarted, _timeProvider.GetTimestamp());
        }
    }
}
