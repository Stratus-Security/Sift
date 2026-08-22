using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;

namespace Stratus.Sift.Connectors.Slack;

/// <summary>
/// Serializes calls per Slack API method and learns a sustainable request interval after Slack
/// returns a rate limit. Slack applies quotas per method, workspace, and app/token, so unrelated
/// methods remain independent.
/// </summary>
internal sealed class SlackRateLimitGate
{
    private static readonly TimeSpan SafetyBuffer = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan MaximumDelay = TimeSpan.FromMinutes(15);

    private readonly ConcurrentDictionary<string, MethodState> _methods = new(StringComparer.OrdinalIgnoreCase);
    private readonly Func<DateTimeOffset> _getUtcNow;
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync;

    internal SlackRateLimitGate(
        Func<DateTimeOffset>? getUtcNow = null,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null)
    {
        _getUtcNow = getUtcNow ?? (() => DateTimeOffset.UtcNow);
        _delayAsync = delayAsync ?? ((delay, cancellationToken) => Task.Delay(delay, cancellationToken));
    }

    internal async Task<IDisposable> EnterAsync(string method, CancellationToken cancellationToken)
    {
        var state = GetState(method);
        await state.Mutex.WaitAsync(cancellationToken);
        try
        {
            while (true)
            {
                TimeSpan delay;
                lock (state.SyncRoot)
                {
                    delay = state.NotBeforeUtc - _getUtcNow();
                }

                if (delay <= TimeSpan.Zero)
                {
                    return new Lease(state.Mutex);
                }

                await _delayAsync(delay, cancellationToken);
            }
        }
        catch
        {
            state.Mutex.Release();
            throw;
        }
    }

    internal SlackRateLimitObservation ReportRateLimit(string method, TimeSpan? retryAfter, int attempt)
    {
        var state = GetState(method);
        var now = _getUtcNow();
        var serverDelay = NormalizeDelay(retryAfter ?? GetTransientRetryDelay(attempt));
        TimeSpan learnedInterval;
        TimeSpan pacingInterval;

        lock (state.SyncRoot)
        {
            learnedInterval = serverDelay;
            if (state.LastSuccessUtc.HasValue)
            {
                var elapsedSinceSuccess = now - state.LastSuccessUtc.Value;
                if (elapsedSinceSuccess > TimeSpan.Zero && elapsedSinceSuccess < MaximumDelay)
                {
                    learnedInterval = NormalizeDelay(elapsedSinceSuccess + serverDelay);
                }
            }

            if (learnedInterval > state.PacingInterval)
            {
                state.PacingInterval = learnedInterval;
            }

            var retryAt = now + serverDelay + SafetyBuffer;
            if (retryAt > state.NotBeforeUtc)
            {
                state.NotBeforeUtc = retryAt;
            }

            pacingInterval = state.PacingInterval;
        }

        return new SlackRateLimitObservation(serverDelay + SafetyBuffer, pacingInterval);
    }

    internal void ReportSuccess(string method)
    {
        var state = GetState(method);
        var now = _getUtcNow();
        lock (state.SyncRoot)
        {
            state.LastSuccessUtc = now;
            if (state.PacingInterval <= TimeSpan.Zero)
            {
                return;
            }

            var nextRequestAt = now + state.PacingInterval + SafetyBuffer;
            if (nextRequestAt > state.NotBeforeUtc)
            {
                state.NotBeforeUtc = nextRequestAt;
            }
        }
    }

    internal static TimeSpan GetTransientRetryDelay(int attempt)
        => TimeSpan.FromSeconds(Math.Min(60, Math.Pow(2, Math.Clamp(attempt, 0, 6))));

    internal static TimeSpan? GetRetryAfter(JsonElement response)
    {
        if (TryReadRetryAfter(response, out var retryAfter))
        {
            return retryAfter;
        }

        return response.TryGetProperty("response_metadata", out var metadata)
               && metadata.ValueKind == JsonValueKind.Object
               && TryReadRetryAfter(metadata, out retryAfter)
            ? retryAfter
            : null;
    }

    private static bool TryReadRetryAfter(JsonElement element, out TimeSpan retryAfter)
    {
        retryAfter = default;
        if (!element.TryGetProperty("retry_after", out var value))
        {
            return false;
        }

        double seconds;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out seconds)
            || value.ValueKind == JsonValueKind.String
            && double.TryParse(value.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out seconds))
        {
            retryAfter = TimeSpan.FromSeconds(Math.Max(0, seconds));
            return true;
        }

        return false;
    }

    private MethodState GetState(string method)
        => _methods.GetOrAdd(string.IsNullOrWhiteSpace(method) ? "unknown" : method, static _ => new MethodState());

    private static TimeSpan NormalizeDelay(TimeSpan delay)
    {
        if (delay < TimeSpan.FromSeconds(1))
        {
            return TimeSpan.FromSeconds(1);
        }

        return delay > MaximumDelay ? MaximumDelay : delay;
    }

    private sealed class MethodState
    {
        internal readonly SemaphoreSlim Mutex = new(1, 1);
        internal readonly object SyncRoot = new();
        internal DateTimeOffset NotBeforeUtc;
        internal DateTimeOffset? LastSuccessUtc;
        internal TimeSpan PacingInterval;
    }

    private sealed class Lease(SemaphoreSlim mutex) : IDisposable
    {
        private SemaphoreSlim? _mutex = mutex;

        public void Dispose()
        {
            Interlocked.Exchange(ref _mutex, null)?.Release();
        }
    }
}

internal readonly record struct SlackRateLimitObservation(TimeSpan RetryDelay, TimeSpan PacingInterval);
