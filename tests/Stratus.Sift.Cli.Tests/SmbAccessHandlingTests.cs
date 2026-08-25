using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SMBLibrary;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Models;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli.Tests;

public sealed class SmbAccessHandlingTests
{
    [Fact]
    public void CreateFileOpenException_MapsAccessDeniedToUnauthorizedAccess()
    {
        var exception = SmbKerberosService.CreateFileOpenException(
            @"ProgramData\Microsoft\Crypto\RSA\MachineKeys\key",
            NTStatus.STATUS_ACCESS_DENIED);

        var unauthorized = Assert.IsType<UnauthorizedAccessException>(exception);
        Assert.Contains("STATUS_ACCESS_DENIED (0xC0000022)", unauthorized.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateFileOpenException_PreservesUnexpectedFailuresAsIoErrors()
    {
        var exception = SmbKerberosService.CreateFileOpenException("data.txt", NTStatus.STATUS_DATA_ERROR);

        Assert.IsType<IOException>(exception);
    }

    [Fact]
    public void CreateFileOpenException_MapsSharingViolationToExpectedUnavailableContent()
    {
        var exception = SmbKerberosService.CreateFileOpenException(
            @"Windows\Logs\edb.log",
            NTStatus.STATUS_SHARING_VIOLATION);

        var unavailable = Assert.IsType<RemoteContentUnavailableException>(exception);
        Assert.False(unavailable.ShouldRetry);
        Assert.True(unavailable.IsExpected);
        Assert.Contains("STATUS_SHARING_VIOLATION (0xC0000043)", unavailable.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanDriveChangesAsync_LogsAccessDeniedAsDebugSkipInsteadOfError()
    {
        var logger = new RecordingLogger<RemoteDriveScanner>();
        var scanner = CreateScanner(logger, out var optimizer, out var policyMap);

        await ScanAsync(
            scanner,
            new SingleFileDrive(new ThrowingRemoteFile(
                "key.txt",
                @"\\winterfell\C$\ProgramData\Microsoft\Crypto\RSA\MachineKeys\key.txt",
                _ => throw new UnauthorizedAccessException("STATUS_ACCESS_DENIED (0xC0000022)"))),
            optimizer,
            policyMap,
            CancellationToken.None);

        Assert.DoesNotContain(logger.Entries, entry => entry.Level == LogLevel.Error);
        Assert.Contains(
            logger.Entries,
            entry => entry.Level == LogLevel.Debug
                && entry.Message.Contains("Skipping inaccessible item", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanDriveChangesAsync_LogsSharingViolationAsDebugSkipInsteadOfFailure()
    {
        var logger = new RecordingLogger<RemoteDriveScanner>();
        var scanner = CreateScanner(logger, out var optimizer, out var policyMap);
        var exception = SmbKerberosService.CreateFileOpenException(
            @"Windows\Logs\edb.log",
            NTStatus.STATUS_SHARING_VIOLATION);

        await ScanAsync(
            scanner,
            new SingleFileDrive(new ThrowingRemoteFile(
                "edb.log",
                @"\\winterfell\C$\Windows\Logs\edb.log",
                _ => throw exception)),
            optimizer,
            policyMap,
            CancellationToken.None);

        Assert.DoesNotContain(logger.Entries, entry => entry.Level is LogLevel.Error or LogLevel.Warning);
        Assert.Contains(
            logger.Entries,
            entry => entry.Level == LogLevel.Debug
                && entry.Message.Contains("Skipping temporarily unavailable item", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanDriveChangesAsync_PropagatesRequestedCancellationWithoutLoggingFailure()
    {
        using var cancellation = new CancellationTokenSource();
        var logger = new RecordingLogger<RemoteDriveScanner>();
        var scanner = CreateScanner(logger, out var optimizer, out var policyMap);
        var drive = new SingleFileDrive(new ThrowingRemoteFile(
            "multiprt.inf",
            @"\\winterfell\C$\Windows\INF\multiprt.inf",
            token =>
            {
                cancellation.Cancel();
                token.ThrowIfCancellationRequested();
                return null;
            }));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ScanAsync(scanner, drive, optimizer, policyMap, cancellation.Token));

        Assert.DoesNotContain(logger.Entries, entry => entry.Level == LogLevel.Error);
    }

    [Fact]
    public async Task ScanDriveChangesAsync_EnumerationOnlyTraversesWithoutOpeningContent()
    {
        var logger = new RecordingLogger<RemoteDriveScanner>();
        var scanner = CreateScanner(logger, out var optimizer, out var policyMap);
        var discovered = 0;
        var scanned = 0;

        await scanner.ScanDriveChangesAsync(
            new SingleFileDrive(new ThrowingRemoteFile(
                "secret.txt",
                @"\\winterfell\C$\Data\secret.txt",
                _ => throw new InvalidOperationException("Enumeration must not open content."))),
            deltaToken: null,
            optimizer,
            policyMap,
            ignoreRules: [],
            new ScanOptions(),
            onIssueFound: _ => Task.CompletedTask,
            onCheckpointToken: null,
            onNewDeltaToken: _ => Task.CompletedTask,
            onFilesDiscovered: count => discovered += count,
            onFilesScanned: count => scanned += count,
            onQueueDepth: null,
            onCurrentPath: null,
            ensureScanActive: null,
            CancellationToken.None,
            new RemoteDriveScanExecutionOptions(WorkerCount: 8, QueueCapacity: 512, EnumerateOnly: true));

        Assert.Equal(1, discovered);
        Assert.Equal(0, scanned);
        Assert.DoesNotContain(logger.Entries, entry => entry.Level == LogLevel.Error);
    }

    private static RemoteDriveScanner CreateScanner(
        RecordingLogger<RemoteDriveScanner> logger,
        out ClassifierOptimizer optimizer,
        out Dictionary<Guid, List<Policy>> policyMap)
    {
        var contentExtractor = new ContentExtractor();
        var scanner = new RemoteDriveScanner(
            logger,
            new FileScanner(NullLogger<FileScanner>.Instance, contentExtractor, new ValidatorFactory([])),
            contentExtractor);
        var classifier = new Classifier
        {
            Name = "Test content rule",
            Matches =
            [
                new ClassifierMatch
                {
                    Target = RuleTarget.Content,
                    Patterns = ["secret"],
                    IncludedExtensions = [".txt", ".log", ".inf"]
                }
            ]
        };
        optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([classifier]);
        policyMap = new Dictionary<Guid, List<Policy>>
        {
            [classifier.Id] = [new Policy { Name = "Test policy" }]
        };
        return scanner;
    }

    private static Task ScanAsync(
        RemoteDriveScanner scanner,
        IRemoteDrive drive,
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        CancellationToken cancellationToken)
        => scanner.ScanDriveChangesAsync(
            drive,
            deltaToken: null,
            optimizer,
            policyMap,
            ignoreRules: [],
            new ScanOptions(),
            onIssueFound: _ => Task.CompletedTask,
            onCheckpointToken: null,
            onNewDeltaToken: _ => Task.CompletedTask,
            onFilesScanned: null,
            onQueueDepth: null,
            onCurrentPath: null,
            ensureScanActive: null,
            cancellationToken);

    private sealed class SingleFileDrive(IRemoteFile file) : IRemoteDrive
    {
        public string Id => "drive";
        public string Name => "C$";
        public string ConnectionId => "smb://winterfell/C$";
        public string WebUrl => @"\\winterfell\C$";
        public DatastoreType DriveType => DatastoreType.FileSystem;
        public long? TotalSize => null;
        public long? UsedSize => null;

        public Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(
            string? deltaToken,
            CancellationToken cancellationToken = default)
        {
            IEnumerable<IRemoteFile> changes = [file];
            return Task.FromResult((changes, string.Empty));
        }
    }

    private sealed class ThrowingRemoteFile(
        string name,
        string path,
        Func<CancellationToken, Stream?> openContent) : IRemoteFile
    {
        public string Id => name;
        public string Name => name;
        public string Path => path;
        public string WebUrl => Path;
        public long? Size => 128;
        public string? ContentType => "text/plain";
        public bool IsDeleted => false;
        public bool IsDirectory => false;
        public bool IsLink => false;
        public bool IsExternal => false;

        public Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(openContent(cancellationToken));

        public Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default)
            => Task.FromResult(openContent(cancellationToken));
    }

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly ConcurrentQueue<LogEntry> _entries = new();

        public IReadOnlyCollection<LogEntry> Entries => _entries.ToArray();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => _entries.Enqueue(new LogEntry(logLevel, formatter(state, exception)));
    }

    public sealed record LogEntry(LogLevel Level, string Message);
}
