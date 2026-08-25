using System.Diagnostics;
using System.Text.Json;
using Stratus.Sift.Scanner.Models;

namespace Stratus.Sift.Cli;

internal sealed class CliScanDiagnostics : IAsyncDisposable
{
    private readonly string? _outputPath;
    private readonly long _started = Stopwatch.GetTimestamp();
    private long _enumerationTicks;
    private long _candidates;
    private long _files;
    private long _directories;
    private long _maxQueueDepth;

    public CliScanDiagnostics(int workers, int queueCapacity, long maxReadBytesPerSecond, string? outputPath)
    {
        Workers = workers;
        QueueCapacity = queueCapacity;
        MaxReadBytesPerSecond = maxReadBytesPerSecond;
        _outputPath = outputPath;
    }

    public int Workers { get; }

    public int QueueCapacity { get; }

    public long MaxReadBytesPerSecond { get; }

    public ScanDiagnostics Scanner { get; } = new();

    public long BeginEnumeration() => Stopwatch.GetTimestamp();

    public void CompleteEnumeration(long startedAt) =>
        Interlocked.Add(ref _enumerationTicks, Stopwatch.GetTimestamp() - startedAt);

    public void RecordCandidate(bool directory)
        => RecordCandidates(directory ? 0 : 1, directory ? 1 : 0);

    public void RecordCandidates(int files, int directories)
    {
        var candidates = files + directories;
        if (candidates > 0)
        {
            Interlocked.Add(ref _candidates, candidates);
        }
        if (files > 0)
        {
            Interlocked.Add(ref _files, files);
        }
        if (directories > 0)
        {
            Interlocked.Add(ref _directories, directories);
        }
    }

    public void ObserveQueueDepth(long queueDepth)
    {
        long observed;
        while (queueDepth > (observed = Volatile.Read(ref _maxQueueDepth))
               && Interlocked.CompareExchange(ref _maxQueueDepth, queueDepth, observed) != observed)
        {
        }
    }

    public async Task WriteAsync(string path, CancellationToken cancellationToken)
    {
        var scanner = Scanner.Snapshot();
        var document = new CliScanDiagnosticsDocument(
            DateTimeOffset.UtcNow,
            Workers,
            QueueCapacity,
            MaxReadBytesPerSecond,
            Interlocked.Read(ref _candidates),
            Interlocked.Read(ref _files),
            Interlocked.Read(ref _directories),
            Interlocked.Read(ref _maxQueueDepth),
            ToMilliseconds(Interlocked.Read(ref _enumerationTicks)),
            ToMilliseconds(Stopwatch.GetTimestamp() - _started),
            scanner.FilesOpened,
            scanner.FilesSkipped,
            scanner.PhysicalBytesRead,
            scanner.AggregateLimiterWait.TotalMilliseconds,
            scanner.AggregateRuleEvaluationTime.TotalMilliseconds);

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        await using var stream = new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.Read);
        await JsonSerializer.SerializeAsync(
            stream,
            document,
            CliJsonContext.Default.CliScanDiagnosticsDocument,
            cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (!string.IsNullOrWhiteSpace(_outputPath))
        {
            await WriteAsync(_outputPath, CancellationToken.None);
        }
    }

    private static double ToMilliseconds(long ticks) =>
        TimeSpan.FromSeconds((double)ticks / Stopwatch.Frequency).TotalMilliseconds;
}

internal sealed record CliScanDiagnosticsDocument(
    DateTimeOffset GeneratedAtUtc,
    int Workers,
    int QueueCapacity,
    long MaxReadBytesPerSecond,
    long Candidates,
    long Files,
    long Directories,
    long MaximumQueueDepth,
    double EnumerationMilliseconds,
    double ElapsedMilliseconds,
    long FilesOpened,
    long FilesSkipped,
    long PhysicalBytesRead,
    double AggregateLimiterWaitMilliseconds,
    double AggregateRuleEvaluationMilliseconds);
