using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Stratus.Sift.Cli;
using Stratus.Sift.FileSystem;
using System.Buffers.Binary;
using System.Text;

namespace Stratus.Sift.Cli.Tests;

public sealed class CliResumeStoreTests
{
    [Fact]
    public async Task CompletedItem_IsReloadedOnlyForTheSameScanAndUnchangedFile()
    {
        var directory = CreateTemporaryDirectory();
        var store = CreateStore(directory);
        var modified = new DateTime(2026, 8, 25, 1, 2, 3, DateTimeKind.Utc);
        var candidate = new FileScanCandidate(@"C:\Data\secret.txt", "secret.txt", false, 42, modified);
        var flushes = 0;

        try
        {
            await using (var first = store.OpenSession("local-scan-a", resume: false))
            {
                await first.MarkCompletedAsync(
                    candidate,
                    _ => Task.CompletedTask,
                    CancellationToken.None);
                await first.CommitAsync(
                    _ =>
                    {
                        flushes++;
                        return Task.CompletedTask;
                    },
                    CancellationToken.None);
            }

            await using var resumed = store.OpenSession("local-scan-a", resume: true);
            Assert.True(resumed.Contains(candidate));
            Assert.False(resumed.Contains(candidate with { Modified = modified.AddSeconds(1) }));

            await using var differentScan = store.OpenSession("local-scan-b", resume: true);
            Assert.False(differentScan.Contains(candidate));
            Assert.Equal(1, flushes);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task FullScan_ResetsAnExistingResumeJournal()
    {
        var directory = CreateTemporaryDirectory();
        var store = CreateStore(directory);
        var candidate = new FileScanCandidate(@"C:\Data\secret.txt", "secret.txt", false, 42, DateTime.UtcNow);

        try
        {
            await using (var first = store.OpenSession("same-scan", resume: false))
            {
                await first.MarkCompletedAsync(candidate, _ => Task.CompletedTask, CancellationToken.None);
                await first.CommitAsync(_ => Task.CompletedTask, CancellationToken.None);
            }

            await using var reset = store.OpenSession("same-scan", resume: false);
            Assert.False(reset.Contains(candidate));
            Assert.Equal(0, reset.CompletedCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task OutputFailure_DoesNotAdvanceTheDurableResumeJournal()
    {
        var directory = CreateTemporaryDirectory();
        var store = CreateStore(directory);
        var candidate = new FileScanCandidate(@"C:\Data\secret.txt", "secret.txt", false, 42, DateTime.UtcNow);

        try
        {
            await using (var interrupted = store.OpenSession("failed-output", resume: false))
            {
                await interrupted.MarkCompletedAsync(candidate, _ => Task.CompletedTask, CancellationToken.None);
                await Assert.ThrowsAsync<IOException>(() => interrupted
                    .CommitAsync(_ => throw new IOException("Output unavailable."), CancellationToken.None)
                    .AsTask());
            }

            await using var resumed = store.OpenSession("failed-output", resume: true);
            Assert.False(resumed.Contains(candidate));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task FastScan_StagesLargeBatchesWithoutForcingOutputOrCommittingThem()
    {
        var directory = CreateTemporaryDirectory();
        var store = CreateStore(directory);
        var outputFlushes = 0;

        try
        {
            await using (var interrupted = store.OpenSession("fast-scan", resume: false))
            {
                for (var index = 0; index < 20_000; index++)
                {
                    await interrupted.MarkRemoteCompletedAsync(
                        "drive-a",
                        $"item-{index}",
                        $"/item-{index}",
                        index,
                        _ =>
                        {
                            outputFlushes++;
                            return Task.CompletedTask;
                        },
                        CancellationToken.None);
                }

                Assert.Equal(0, outputFlushes);
                Assert.True(new FileInfo(Assert.Single(Directory.GetFiles(directory, "*.bin"))).Length > 200_000);
            }

            await using var resumed = store.OpenSession("fast-scan", resume: true);
            Assert.Equal(0, resumed.CompletedCount);
            Assert.Equal(56, new FileInfo(Assert.Single(Directory.GetFiles(directory, "*.bin"))).Length);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task JournalSize_IsBoundedByConfiguration()
    {
        var directory = CreateTemporaryDirectory();
        var store = CreateStore(directory, new Dictionary<string, string?>
        {
            ["ContentScanner:ResumeMaxJournalMiB"] = "1",
            ["ContentScanner:ResumeMaxDiskMiB"] = "1"
        });

        try
        {
            await using (var session = store.OpenSession("bounded-scan", resume: false))
            {
                for (var index = 0; index < 70_000; index++)
                {
                    await session.MarkRemoteCompletedAsync(
                        "drive-a",
                        $"item-{index}",
                        $"/item-{index}",
                        index,
                        _ => Task.CompletedTask,
                        CancellationToken.None);
                }

                await session.CommitAsync(_ => Task.CompletedTask, CancellationToken.None);
            }

            var journal = new FileInfo(Assert.Single(Directory.GetFiles(directory, "*.bin")));
            Assert.True(journal.Length <= 1024 * 1024);

            await using var resumed = store.OpenSession("bounded-scan", resume: true);
            Assert.True(resumed.CompletedCount <= 65_532);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Store_RemovesExpiredAndExcessJournals()
    {
        var directory = CreateTemporaryDirectory();
        var expired = Path.Combine(directory, "expired.bin");
        var excess = Path.Combine(directory, "excess.bin");
        await using (var stream = new FileStream(expired, FileMode.CreateNew, FileAccess.Write))
        {
            stream.SetLength(700_000);
        }
        await using (var stream = new FileStream(excess, FileMode.CreateNew, FileAccess.Write))
        {
            stream.SetLength(700_000);
        }
        File.SetLastWriteTimeUtc(expired, DateTime.UtcNow.AddDays(-2));

        var store = CreateStore(directory, new Dictionary<string, string?>
        {
            ["ContentScanner:ResumeRetentionDays"] = "1",
            ["ContentScanner:ResumeMaxJournalMiB"] = "1",
            ["ContentScanner:ResumeMaxDiskMiB"] = "1"
        });

        try
        {
            await using var session = store.OpenSession("current", resume: false);

            Assert.False(File.Exists(expired));
            Assert.True(Directory.GetFiles(directory, "*.bin").Sum(path => new FileInfo(path).Length) <= 1024 * 1024);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task TornNewestCommitSlot_FallsBackToThePreviousDurableCommit()
    {
        var directory = CreateTemporaryDirectory();
        var store = CreateStore(directory);

        try
        {
            await using (var session = store.OpenSession("torn-slot", resume: false))
            {
                await session.MarkRemoteCompletedAsync("drive", "first", "/first", 1, _ => Task.CompletedTask, CancellationToken.None);
                await session.CommitAsync(_ => Task.CompletedTask, CancellationToken.None);
                await session.MarkRemoteCompletedAsync("drive", "second", "/second", 2, _ => Task.CompletedTask, CancellationToken.None);
                await session.CommitAsync(_ => Task.CompletedTask, CancellationToken.None);
            }

            var path = Assert.Single(Directory.GetFiles(directory, "*.bin"));
            await using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                stream.Position = 8;
                await stream.WriteAsync(new byte[24]);
                stream.Flush(flushToDisk: true);
            }

            await using var resumed = store.OpenSession("torn-slot", resume: true);
            Assert.True(resumed.ContainsRemote("drive", "first", "/first", 1));
            Assert.False(resumed.ContainsRemote("drive", "second", "/second", 2));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task LegacyJournal_IsMigratedWithoutLosingCommittedProgress()
    {
        var directory = CreateTemporaryDirectory();
        var scope = "legacy-scan";
        var path = Path.Combine(directory, $"{CliResumeIdentity.Hash(scope)}.bin");
        var legacy = new byte[24];
        Encoding.ASCII.GetBytes("SIFTRES2").CopyTo(legacy, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(legacy.AsSpan(8), 123);
        BinaryPrimitives.WriteUInt64LittleEndian(legacy.AsSpan(16), 456);
        await File.WriteAllBytesAsync(path, legacy);
        var store = CreateStore(directory);

        try
        {
            await using var resumed = store.OpenSession(scope, resume: true);

            Assert.Equal(1, resumed.CompletedCount);
            var currentMagic = new byte[8];
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            Assert.Equal(8, await stream.ReadAsync(currentMagic));
            Assert.Equal("SIFTRES3", Encoding.ASCII.GetString(currentMagic));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ConnectorScope_IsStableButSeparatesAccountsRulesAndOptions()
    {
        var config = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Site"] = "https://example.test",
            ["Token"] = "secret-token"
        };

        var first = CliResumeIdentity.CreateConnectorScope("Test", config, "account-a", "rules-a", false, null);
        var reordered = CliResumeIdentity.CreateConnectorScope(
            "Test",
            new Dictionary<string, string> { ["Token"] = "secret-token", ["Site"] = "https://example.test" },
            "account-a",
            "rules-a",
            false,
            null);

        Assert.Equal(first, reordered);
        Assert.NotEqual(first, CliResumeIdentity.CreateConnectorScope("Test", config, "account-b", "rules-a", false, null));
        Assert.NotEqual(first, CliResumeIdentity.CreateConnectorScope("Test", config, "account-a", "rules-b", false, null));
        Assert.NotEqual(first, CliResumeIdentity.CreateConnectorScope("Test", config, "account-a", "rules-a", true, null));
        Assert.DoesNotContain("secret-token", first, StringComparison.Ordinal);
    }

    private static CliResumeStore CreateStore(
        string directory,
        IReadOnlyDictionary<string, string?>? settings = null)
    {
        var values = new Dictionary<string, string?>(settings ?? new Dictionary<string, string?>())
        {
            ["ContentScanner:ResumeDirectory"] = directory
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
        return new CliResumeStore(configuration, NullLogger<CliResumeStore>.Instance);
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sift-resume-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }
}
