using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class RemoteScanDiagnosticsRegressionTests
{
    [Theory]
    [InlineData(403, true)]
    [InlineData(404, true)]
    [InlineData(401, false)]
    [InlineData(400, false)]
    [InlineData(500, false)]
    public void ExpectedStatusClassification_DoesNotHideAuthenticationOrServiceBugs(int status, bool expected)
        => Assert.Equal(expected, RemoteScanExceptionClassifier.IsExpected(new HttpRequestException("Test", null, (HttpStatusCode)status)));

    [Fact]
    public void MixedEnumerationFailures_KeepUnexpectedErrorVisible()
    {
        var denied = new UnauthorizedAccessException();
        Assert.True(RemoteScanExceptionClassifier.IsExpected(new AggregateException(denied, new FileNotFoundException())));
        Assert.False(RemoteScanExceptionClassifier.IsExpected(new AggregateException(denied, new InvalidDataException("Bad server response"))));
        Assert.False(RemoteScanExceptionClassifier.IsExpectedForEnumeration(new HttpRequestException("Missing collection page", null, HttpStatusCode.NotFound)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExpectedReadFailures_RemainPendingWithoutRepeatedCheckpointWarnings(bool locked)
    {
        var logger = new RecordingLogger();
        var file = new FailingFile(locked ? new RemoteContentUnavailableException("Locked", false, true)
            : new UnauthorizedAccessException("Denied"));
        var result = await ScanAsync(new CheckpointDrive(file, 50), logger: logger);
        Assert.True(result.Incomplete);
        Assert.Equal(0, result.Scanned);
        Assert.Equal(0, result.Processed);
        Assert.Empty(result.Checkpoints);
        Assert.Null(result.FinalToken);
        Assert.DoesNotContain(logger.Entries, entry => entry.Level >= LogLevel.Warning);
        Assert.Single(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message.Contains("1 content scans"));
    }

    [Fact]
    public async Task UnexpectedReadFailures_AreBoundedAndStillPreventCompletion()
    {
        var logger = new RecordingLogger();
        var result = await ScanAsync(new CheckpointDrive(new FailingFile(new InvalidDataException("Corrupt remote response")), 30,
            fileCount: 30), logger: logger);
        Assert.True(result.Incomplete);
        Assert.Empty(result.Checkpoints);
        Assert.Equal(0, result.Processed);
        Assert.Null(result.FinalToken);
        var warnings = logger.Entries.Where(entry => entry.Level >= LogLevel.Warning).ToArray();
        Assert.InRange(warnings.Length, 1, 9);
        Assert.Contains(warnings, entry => entry.Message.Contains("Corrupt remote response"));
        Assert.Contains(warnings, entry => entry.Message.Contains("30 content scans"));
    }

    [Fact]
    public async Task NativeGenericListReader_DoesNotScanDocumentLibrariesAgain()
    {
        var requested = new List<string>();
        var rest = new SharePointRestClient(new StubCredential(), "Tests", new HttpClient(new Handler(request =>
        {
            requested.Add(request.RequestUri!.AbsolutePath);
            var value = request.RequestUri.AbsolutePath.EndsWith("/lists")
                ? (object)new { value = new[] { new { Id = "library", BaseType = 1 }, new { Id = "generic", BaseType = 0 } } }
                : new { value = new[] { new { Id = 1, Notes = "secret" } } };
            return Response(HttpStatusCode.OK, JsonSerializer.Serialize(value));
        })));
        var drive = new Microsoft365SiteDataDrive(null, rest, "tenant", "site", new("https://contoso.sharepoint.com/sites/Test"),
            Microsoft365CoverageOptions.Disabled with { ScanListsAndPages = true });
        var result = await ScanAsync(drive, extension: ".json");
        Assert.False(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.DoesNotContain(requested, path => path.Contains("'library'"));
        Assert.Contains(requested, path => path.Contains("'generic'"));
    }

    private sealed class FailingFile(Exception error) : IRemoteFile
    {
        public string Id => "file";
        public string Name => "test.txt";
        public string Path => "https://contoso.sharepoint.com/sites/Test/Documents/test.txt";
        public string WebUrl => Path;
        public long? Size => 10;
        public string? ContentType => null;
        public bool IsDeleted => false;
        public bool IsDirectory => false;
        public bool IsLink => false;
        public bool IsExternal => false;
        public Task<Stream?> GetContentAsync(CancellationToken ct = default) => Task.FromException<Stream?>(error);
        public Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken ct = default) => GetContentAsync(ct);
    }

    private sealed class CheckpointDrive(IRemoteFile file, int checkpointCount, int fileCount = 1) : IRemoteDrive
    {
        public string Id => "drive";
        public string Name => "Data";
        public string ConnectionId => "smb://server/Data";
        public string WebUrl => @"\\server\Data";
        public DatastoreType DriveType => DatastoreType.FileSystem;
        public long? TotalSize => null;
        public long? UsedSize => null;
        public Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken ct = default)
            => throw new NotSupportedException();
        public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
            Func<string, Task>? onCheckpoint = null, CancellationToken ct = default)
        {
            for (var i = 0; i < fileCount; i++) await onChange(file);
            for (var i = 0; i < checkpointCount; i++) if (onCheckpoint != null) await onCheckpoint("checkpoint" + i);
            return "final";
        }
    }

    private sealed class RecordingLogger : ILogger<RemoteDriveScanner>
    {
        internal ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();
        public bool IsEnabled(LogLevel level) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Enqueue((level, formatter(state, exception)));
    }
}
