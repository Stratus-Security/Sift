using System.Diagnostics;

namespace Stratus.Sift.Scanner.Models;

/// <summary>
/// Optional low-overhead counters for scan profiling and benchmark diagnostics.
/// </summary>
public sealed class ScanDiagnostics
{
    private long _filesOpened;
    private long _filesSkipped;
    private long _bytesRead;
    private long _limiterWaitTimeSpanTicks;
    private long _ruleEvaluationTicks;

    public void RecordFileOpened() => Interlocked.Increment(ref _filesOpened);

    public void RecordFileSkipped() => Interlocked.Increment(ref _filesSkipped);

    public void RecordBytesRead(int bytes)
    {
        if (bytes > 0) Interlocked.Add(ref _bytesRead, bytes);
    }

    public void RecordLimiterWait(TimeSpan duration)
    {
        if (duration > TimeSpan.Zero)
        {
            Interlocked.Add(ref _limiterWaitTimeSpanTicks, duration.Ticks);
        }
    }

    public void RecordRuleEvaluation(long stopwatchTicks)
    {
        if (stopwatchTicks > 0) Interlocked.Add(ref _ruleEvaluationTicks, stopwatchTicks);
    }

    public ScanDiagnosticsSnapshot Snapshot() => new(
        Interlocked.Read(ref _filesOpened),
        Interlocked.Read(ref _filesSkipped),
        Interlocked.Read(ref _bytesRead),
        TimeSpan.FromTicks(Interlocked.Read(ref _limiterWaitTimeSpanTicks)),
        ToTimeSpan(Interlocked.Read(ref _ruleEvaluationTicks)));

    private static TimeSpan ToTimeSpan(long stopwatchTicks) =>
        TimeSpan.FromSeconds((double)stopwatchTicks / Stopwatch.Frequency);
}

public sealed record ScanDiagnosticsSnapshot(
    long FilesOpened,
    long FilesSkipped,
    long PhysicalBytesRead,
    TimeSpan AggregateLimiterWait,
    TimeSpan AggregateRuleEvaluationTime);
