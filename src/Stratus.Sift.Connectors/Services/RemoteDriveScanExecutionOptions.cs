namespace Stratus.Sift.Connectors.Services;

/// <summary>
/// Controls the bounded local processing pipeline used after a remote drive enumerates items.
/// Provider request concurrency remains owned by each connector.
/// </summary>
public sealed record RemoteDriveScanExecutionOptions(
    int WorkerCount = 4,
    int QueueCapacity = 256,
    bool EnumerateOnly = false);
