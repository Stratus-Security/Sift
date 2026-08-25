namespace Stratus.Sift.Cli;

internal sealed record CliFilesystemPerformanceOptions(
    int Threads = 0,
    long MaxReadBytesPerSecond = 0,
    string? DiagnosticsOutputPath = null)
{
    public int ResolveWorkerCount() => Threads > 0
        ? Threads
        : Math.Clamp(Environment.ProcessorCount * 2, 8, 64);
}
