using System.Diagnostics;

namespace Stratus.Sift.Cli;

internal enum CliDiscoveryStage
{
    DomainController,
    Computers,
    Shares
}

internal sealed record CliDiscoverySnapshot(
    CliDiscoveryStage Stage,
    int ServersFound,
    int? TotalServers,
    int CompletedServers,
    int ActiveServers,
    int FailedServers,
    int SharesListed,
    int ReadableShares,
    long LastResultTimestamp);

// Observes discovery only; it does not control requests, retries, or deadlines.
internal sealed class CliDiscoveryProgress(Action<CliDiscoverySnapshot> onProgress, Action<string>? onWarning = null)
{
    private readonly object _gate = new();
    private int _timedOutServers;
    private CliDiscoverySnapshot _snapshot = new(CliDiscoveryStage.DomainController, 0, null, 0, 0, 0, 0, 0, Stopwatch.GetTimestamp());

    internal void FindingDomainController() => Update(snapshot => snapshot with
    {
        Stage = CliDiscoveryStage.DomainController,
        LastResultTimestamp = Stopwatch.GetTimestamp()
    });

    internal void FindingComputers() => Update(snapshot => snapshot with
    {
        Stage = CliDiscoveryStage.Computers,
        LastResultTimestamp = Stopwatch.GetTimestamp()
    });

    internal void ComputersFound(int count) => Update(snapshot => snapshot with
    {
        ServersFound = count,
        LastResultTimestamp = Stopwatch.GetTimestamp()
    });

    internal void FindingShares(int totalServers) => Update(snapshot => snapshot with
    {
        Stage = CliDiscoveryStage.Shares,
        ServersFound = totalServers,
        TotalServers = totalServers,
        LastResultTimestamp = Stopwatch.GetTimestamp()
    });

    internal void ServerStarted() => Update(snapshot => snapshot with { ActiveServers = snapshot.ActiveServers + 1 });

    internal int TimedOutServers => Volatile.Read(ref _timedOutServers);

    internal void ServerCompleted(bool failed, bool timedOut = false)
    {
        if (timedOut) Interlocked.Increment(ref _timedOutServers);
        Update(snapshot => snapshot with
        {
            ActiveServers = snapshot.ActiveServers - 1,
            CompletedServers = snapshot.CompletedServers + 1,
            FailedServers = snapshot.FailedServers + (failed ? 1 : 0),
            LastResultTimestamp = Stopwatch.GetTimestamp()
        });
    }

    internal void ShareListed() => SharesListed(1);

    internal void SharesListed(int count) => Update(snapshot => snapshot with
    {
        SharesListed = snapshot.SharesListed + count,
        LastResultTimestamp = Stopwatch.GetTimestamp()
    });

    internal void ShareReadable() => SharesReadable(1);

    internal void SharesReadable(int count) => Update(snapshot => snapshot with
    {
        ReadableShares = snapshot.ReadableShares + count,
        LastResultTimestamp = Stopwatch.GetTimestamp()
    });

    internal void Warning(string message) => onWarning?.Invoke(message);

    private void Update(Func<CliDiscoverySnapshot, CliDiscoverySnapshot> update)
    {
        lock (_gate)
        {
            _snapshot = update(_snapshot);
            // Serialize delivery so a slow observer cannot overwrite a newer snapshot.
            onProgress(_snapshot);
        }
    }
}
