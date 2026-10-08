using System.Diagnostics;
using System.Text.Json;
using Stratus.Sift.Cli;

namespace Stratus.Sift.Cli.Tests;

public class CliDiscoveryProgressTests
{
    [Fact]
    public void ConcurrentDiscovery_PreservesCountsAndDeliversSnapshotsInOrder()
    {
        var snapshots = new List<CliDiscoverySnapshot>();
        var progress = new CliDiscoveryProgress(snapshots.Add);
        progress.FindingShares(120);

        Parallel.For(0, 120, server =>
        {
            progress.ServerStarted();
            var failed = server % 3 == 0;
            if (!failed)
            {
                progress.ShareListed();
                progress.ShareListed();
                progress.ShareReadable();
            }
            progress.ServerCompleted(failed);
        });

        var final = snapshots[^1];
        Assert.Equal(120, final.CompletedServers);
        Assert.Equal(0, final.ActiveServers);
        Assert.Equal(40, final.FailedServers);
        Assert.Equal(160, final.SharesListed);
        Assert.Equal(80, final.ReadableShares);
        Assert.All(snapshots, snapshot => Assert.InRange(snapshot.ActiveServers, 0, 120));
        Assert.Equal(snapshots.Select(snapshot => snapshot.CompletedServers).Order(), snapshots.Select(snapshot => snapshot.CompletedServers));
    }

    [Fact]
    public async Task DiscoveryDisplay_UsesStageSpecificCountersThenReturnsToFileStats()
    {
        await using var display = new CliProgressDisplay("Test discovery");
        var progress = display.BeginDiscovery(domain: true);
        Assert.Contains("Finding domain controller", display.GetStatusText());
        Assert.DoesNotContain("Scanned", display.GetStatusText());

        progress.FindingComputers();
        progress.ComputersFound(50);
        Assert.Contains("Discovering AD computers | Servers found 50", display.GetStatusText());

        progress.FindingShares(50);
        progress.ServerStarted();
        progress.ShareListed();
        progress.ShareReadable();
        Assert.Contains("Servers 0/50 | Listed 1 | Readable 1 | Failed 0 | Active 1", display.GetStatusText());
        progress.ServerCompleted(failed: false);
        Assert.Contains("Servers 1/50", display.GetStatusText());
        Assert.DoesNotContain("Findings", display.GetStatusText());
        Assert.DoesNotContain("Rate", display.GetStatusText());

        display.EndDiscovery();
        display.SetPhase("Scanning SMB shares");
        display.AddFilesDiscovered(10);
        Assert.Contains("Scanning SMB shares | Discovered 10 | Scanned 0", display.GetStatusText());
    }

    [Fact]
    public async Task EnumerationSummary_ReportsDiscoveryAndRetainsWarningsWithoutFileStats()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sift-discovery-{Guid.NewGuid():N}.json");
        try
        {
            await using (var display = new CliProgressDisplay("Test discovery",
                new CliOutputOptions(path, CliOutputFormat.Json, CliOutputStyle.Default)))
            {
                var progress = display.BeginDiscovery(domain: false);
                progress.FindingShares(1);
                progress.ServerStarted();
                progress.ShareListed();
                progress.ShareReadable();
                progress.ServerCompleted(failed: false);
                for (var index = 0; index < 12; index++) progress.Warning($"test-warning-{index}");
                display.Complete("Network enumeration complete");
            }

            var document = JsonSerializer.Deserialize<CliJsonOutputDocument>(await File.ReadAllTextAsync(path));
            Assert.NotNull(document);
            Assert.Contains(document.Events, entry => entry.Kind == "discovery" && entry.Message.Contains("1/1 servers checked; 1 shares listed; 1 readable shares; 0 failed servers."));
            for (var index = 0; index < 12; index++)
                Assert.Contains(document.Events, entry => entry.Kind == "warning" && entry.Message.Contains($"test-warning-{index}"));
            Assert.Equal(0, document.FilesDiscovered);
            Assert.Equal(0, document.FilesScanned);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task SlowDiscovery_ShowsIdleTimeWithoutDeclaringFailure()
    {
        await using var display = new CliProgressDisplay("Test discovery");
        display.BeginDiscovery(domain: false);
        // Supply an old observation; no network or timing-sensitive wait is involved.
        var oldTimestamp = Stopwatch.GetTimestamp() - (long)(Stopwatch.Frequency * 65d);
        display.ReportDiscovery(new CliDiscoverySnapshot(CliDiscoveryStage.Shares, 20, 20, 0, 16, 0, 0, 0, oldTimestamp));

        var status = display.GetStatusText();
        Assert.Contains("Idle 01:", status);
        Assert.Contains("Failed 0 | Active 16", status);
        Assert.Equal(0, display.ErrorCount);
    }

    [Fact]
    public void TimedOutServerIsCountedAsFailedAndCompleted()
    {
        CliDiscoverySnapshot? snapshot = null;
        var progress = new CliDiscoveryProgress(value => snapshot = value);
        progress.FindingShares(1);
        progress.ServerStarted();
        progress.ServerCompleted(failed: true, timedOut: true);

        Assert.NotNull(snapshot);
        Assert.Equal(1, snapshot.CompletedServers);
        Assert.Equal(1, snapshot.FailedServers);
        Assert.Equal(0, snapshot.ActiveServers);
        Assert.Equal(1, progress.TimedOutServers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EnumerationTextSummary_HasDiscoveryTotalsWithoutFileScanCounters(bool snaffler)
    {
        var path = Path.Combine(Path.GetTempPath(), $"sift-discovery-{Guid.NewGuid():N}.txt");
        try
        {
            await using (var display = new CliProgressDisplay("Test discovery",
                new CliOutputOptions(path, CliOutputFormat.Cli, snaffler ? CliOutputStyle.Snaffler : CliOutputStyle.Default)))
            {
                var progress = display.BeginDiscovery(domain: false);
                progress.FindingShares(1);
                progress.ServerStarted();
                progress.SharesListed(3);
                progress.ShareReadable();
                progress.ServerCompleted(failed: false);
                display.Complete("Network enumeration complete");
            }

            var output = await File.ReadAllTextAsync(path);
            Assert.Contains("1/1 servers checked; 3 shares listed; 1 readable shares; 0 failed servers.", output);
            Assert.DoesNotContain("Files scanned:", output);
            Assert.DoesNotContain("Findings:", output);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
