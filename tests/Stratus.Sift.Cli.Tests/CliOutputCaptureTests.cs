using System.Text.Json;
using Stratus.Sift.Cli;

namespace Stratus.Sift.Cli.Tests;

public class CliOutputCaptureTests
{
    [Fact]
    public async Task CliOutput_ResumeAppendsWithoutRemovingExistingContent()
    {
        var path = CreateTemporaryPath("txt");
        try
        {
            await File.WriteAllTextAsync(path, $"existing line{Environment.NewLine}");
            var capture = new CliOutputCapture(path, CliOutputFormat.Cli, CliOutputStyle.Default, "Resumed scan", append: true);

            capture.RecordCliLines("new line");
            await capture.WriteAsync(Summary(filesScanned: 1));

            var output = await File.ReadAllTextAsync(path);
            Assert.Contains("existing line", output);
            Assert.Contains("new line", output);
            Assert.True(output.IndexOf("existing line", StringComparison.Ordinal) < output.IndexOf("new line", StringComparison.Ordinal));
        }
        finally
        {
            DeleteOutputFiles(path);
        }
    }

    [Fact]
    public async Task JsonOutput_ResumeMergesExistingRecordsAndTotals()
    {
        var path = CreateTemporaryPath("json");
        var originalStartedAt = DateTimeOffset.UtcNow.AddHours(-1);
        var existing = new CliJsonOutputDocument
        {
            Title = "Original scan",
            SummaryTitle = "Interrupted",
            StartedAtUtc = originalStartedAt,
            GeneratedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-30),
            Elapsed = TimeSpan.FromMinutes(30),
            FilesDiscovered = 10,
            FilesScanned = 8,
            Findings = 1,
            Errors = 2,
            Events =
            [
                new CliOutputEventRecord { Kind = "old", Message = "existing event", TimestampUtc = originalStartedAt }
            ],
            FindingsList =
            [
                new CliOutputFindingRecord { RuleName = "Existing finding", ResourcePath = "https://example.test/old" }
            ]
        };

        try
        {
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(existing));
            var capture = new CliOutputCapture(path, CliOutputFormat.Json, CliOutputStyle.Default, "Resumed scan", append: true);

            capture.RecordEvent("new", "resumed event");
            await capture.WriteAsync(new CliOutputCapture.CliOutputSummary(
                "Resume complete",
                TimeSpan.FromMinutes(5),
                FilesDiscovered: 4,
                FilesScanned: 3,
                Findings: 2,
                Errors: 1));

            var merged = JsonSerializer.Deserialize<CliJsonOutputDocument>(await File.ReadAllTextAsync(path));
            Assert.NotNull(merged);
            Assert.Equal(CliStoredOutputVersions.Current, merged.SchemaVersion);
            Assert.Equal("Original scan", merged.Title);
            Assert.Equal(originalStartedAt, merged.StartedAtUtc);
            Assert.Equal(TimeSpan.FromMinutes(35), merged.Elapsed);
            Assert.Equal(14, merged.FilesDiscovered);
            Assert.Equal(11, merged.FilesScanned);
            Assert.Equal(3, merged.Findings);
            Assert.Equal(3, merged.Errors);
            Assert.Contains(merged.Events, entry => entry.Message == "existing event");
            Assert.Contains(merged.Events, entry => entry.Message == "resumed event");
            Assert.Single(merged.FindingsList);
        }
        finally
        {
            DeleteOutputFiles(path);
        }
    }

    [Fact]
    public async Task JsonOutput_ResumeLeavesInvalidExistingFileUntouched()
    {
        var path = CreateTemporaryPath("json");
        const string invalidJson = "{not valid json";
        try
        {
            await File.WriteAllTextAsync(path, invalidJson);
            var capture = new CliOutputCapture(path, CliOutputFormat.Json, CliOutputStyle.Default, "Resumed scan", append: true);

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => capture.WriteAsync(Summary()));

            Assert.Contains("file was left unchanged", exception.Message);
            Assert.Equal(invalidJson, await File.ReadAllTextAsync(path));
        }
        finally
        {
            DeleteOutputFiles(path);
        }
    }

    [Fact]
    public void IncrementalConnectorScan_EnablesOutputAppend()
    {
        var output = new CliOutputOptions("scan.json", CliOutputFormat.Json, CliOutputStyle.Default);

        Assert.True(CliScanRunner.ResolveOutputOptions(output, fullScan: false)!.Append);
        Assert.False(CliScanRunner.ResolveOutputOptions(output, fullScan: true)!.Append);
    }

    [Fact]
    public async Task JsonOutput_CheckpointIsACompleteReadableDocument()
    {
        var path = CreateTemporaryPath("json");
        try
        {
            var capture = new CliOutputCapture(path, CliOutputFormat.Json, CliOutputStyle.Default, "Long scan");
            capture.RecordEvent("progress", "first durable batch");

            await capture.FlushCheckpointAsync(Summary(filesScanned: 128));

            var checkpoint = JsonSerializer.Deserialize<CliJsonOutputDocument>(await File.ReadAllTextAsync(path));
            Assert.NotNull(checkpoint);
            Assert.Equal(128, checkpoint.FilesScanned);
            Assert.Contains(checkpoint.Events, entry => entry.Message == "first durable batch");

            capture.RecordEvent("progress", "second durable batch");
            await capture.WriteAsync(Summary(filesScanned: 129));

            var completed = JsonSerializer.Deserialize<CliJsonOutputDocument>(await File.ReadAllTextAsync(path));
            Assert.NotNull(completed);
            Assert.Equal(129, completed.FilesScanned);
            Assert.Contains(completed.Events, entry => entry.Message == "second durable batch");
        }
        finally
        {
            DeleteOutputFiles(path);
        }
    }

    [Fact]
    public async Task CheckpointFlush_PropagatesWriterFailureWithoutHanging()
    {
        var path = CreateTemporaryPath("json");
        const string invalidJson = "{not valid json";
        try
        {
            await File.WriteAllTextAsync(path, invalidJson);
            var capture = new CliOutputCapture(path, CliOutputFormat.Json, CliOutputStyle.Default, "Resumed scan", append: true);

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(
                () => capture.FlushCheckpointAsync(Summary()).WaitAsync(TimeSpan.FromSeconds(5)));

            Assert.Contains("file was left unchanged", exception.Message);
            Assert.Equal(invalidJson, await File.ReadAllTextAsync(path));
        }
        finally
        {
            DeleteOutputFiles(path);
        }
    }

    [Fact]
    public async Task LocalScan_MissingPathReturnsOperationalFailure()
    {
        var missingPath = Path.Combine(Path.GetTempPath(), $"missing-content-scan-{Guid.NewGuid():N}");

        var exitCode = await Program.RunAsync(["local", "--path", missingPath]);

        Assert.Equal(CliExitCodes.Failed, exitCode);
    }

    [Fact]
    public async Task LocalScan_PreCancelledInvocationReturnsCancelledExitCode()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var exitCode = await Program.RunAsync(
            ["local", "--path", Path.GetTempPath()],
            cancellation.Token);

        Assert.Equal(CliExitCodes.Cancelled, exitCode);
    }

    [Fact]
    public async Task JsonOutput_LargeResultUsesBoundedWriterAndPreservesAllRecords()
    {
        var path = CreateTemporaryPath("json");
        try
        {
            var capture = new CliOutputCapture(path, CliOutputFormat.Json, CliOutputStyle.Default, "Large scan");
            for (var index = 0; index < 2_000; index++)
            {
                capture.RecordEvent("progress", $"event-{index}");
            }

            await capture.WriteAsync(Summary());

            var document = JsonSerializer.Deserialize<CliJsonOutputDocument>(await File.ReadAllTextAsync(path));
            Assert.NotNull(document);
            Assert.Equal(2_000, document.Events.Count);
            Assert.False(Directory.EnumerateFiles(
                    Path.GetDirectoryName(path)!,
                    Path.GetFileName(path) + ".*",
                    SearchOption.TopDirectoryOnly)
                .Where(candidate => !string.Equals(candidate, path, StringComparison.OrdinalIgnoreCase))
                .Any());
        }
        finally
        {
            DeleteOutputFiles(path);
        }
    }

    private static CliOutputCapture.CliOutputSummary Summary(long filesScanned = 0)
        => new("Complete", TimeSpan.FromSeconds(1), filesScanned, filesScanned, 0, 0);

    private static string CreateTemporaryPath(string extension)
        => Path.Combine(Path.GetTempPath(), $"snare-output-{Guid.NewGuid():N}.{extension}");

    private static void DeleteOutputFiles(string path)
    {
        File.Delete(path);
        File.Delete(path + ".partial");
    }
}
