using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli.Tests;

public sealed class SharedReadRateLimiterTests
{
    [Fact]
    public async Task AcquireAsync_UsesOneSecondBurstThenWaitsForRefill()
    {
        var clock = new ManualTimeProvider();
        var delays = new List<TimeSpan>();
        var limiter = new SharedReadRateLimiter(
            clock,
            (delay, _, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                delays.Add(delay);
                clock.Advance(delay);
                return ValueTask.CompletedTask;
            });

        var initialWait = await limiter.AcquireAsync(1024, 1024, CancellationToken.None);
        Assert.Equal(TimeSpan.Zero, initialWait);
        Assert.Empty(delays);

        var refillWait = await limiter.AcquireAsync(1024, 1024, CancellationToken.None);
        var delay = Assert.Single(delays);
        Assert.Equal(TimeSpan.FromSeconds(1), delay);
        Assert.Equal(TimeSpan.FromSeconds(1), refillWait);
    }

    [Fact]
    public async Task AcquireAsync_ObservesCancellationWhileWaiting()
    {
        var clock = new ManualTimeProvider();
        var limiter = new SharedReadRateLimiter(
            clock,
            (_, _, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ValueTask.CompletedTask;
            });
        await limiter.AcquireAsync(1024, 1024, CancellationToken.None);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            limiter.AcquireAsync(1024, 1024, cancellation.Token).AsTask());
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private long _timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => Interlocked.Read(ref _timestamp);

        public void Advance(TimeSpan duration) =>
            Interlocked.Add(ref _timestamp, duration.Ticks);
    }
}
