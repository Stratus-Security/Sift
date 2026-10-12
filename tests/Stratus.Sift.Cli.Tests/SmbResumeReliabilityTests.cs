using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SMBLibrary;
using SMBLibrary.Client;
using Stratus.Sift.Cli;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;
using FileAttributes = SMBLibrary.FileAttributes;

namespace Stratus.Sift.Cli.Tests;

public sealed class SmbResumeReliabilityTests
{
    [Theory]
    [InlineData(false, NTStatus.STATUS_ACCESS_DENIED)]
    [InlineData(true, NTStatus.STATUS_ACCESS_DENIED)]
    [InlineData(false, NTStatus.STATUS_DATA_ERROR)]
    [InlineData(true, NTStatus.STATUS_DATA_ERROR)]
    public void DirectoryOpenAndQueryFailures_AreNeverReturnedAsEmptyListings(bool queryFails, NTStatus status)
    {
        var stub = DispatchProxy.Create<ISMBFileStore, ListingStoreProxy>();
        var proxy = (ListingStoreProxy)stub;
        proxy.OpenStatus = queryFails ? NTStatus.STATUS_SUCCESS : status;
        proxy.QueryStatus = status;
        using var store = new SmbKerberosStore(stub);
        var exception = Assert.ThrowsAny<Exception>(() => store.ListDirectory("Users\\Unavailable"));
        Assert.Equal(status == NTStatus.STATUS_ACCESS_DENIED, exception is UnauthorizedAccessException);
        Assert.Equal(queryFails, proxy.Closed);
    }

    [Theory]
    [InlineData(NTStatus.STATUS_ACCESS_DENIED, false)]
    [InlineData(NTStatus.STATUS_SHARING_VIOLATION, false)]
    [InlineData(NTStatus.STATUS_DATA_ERROR, true)]
    public async Task UnreadableSubtree_DoesNotStopSiblingsOrAdvanceCheckpoints(NTStatus status, bool warning)
    {
        using var smb = CreateDrive();
        var attempts = new List<string>();
        var logger = new RecordingLogger();
        var unavailable = true;
        var drive = new RoutingDrive(smb, path =>
        {
            attempts.Add(path);
            if (path.Length == 0)
                return [Entry("Good", true), Entry("Unavailable", true)];
            if (path == "Unavailable" && unavailable)
                throw SmbKerberosService.CreateFileOpenException(path, status, directory: true);
            return [Entry("good.txt")];
        }, offerCheckpoint: true);
        var rule = new Classifier { Name = "Metadata probe", Matches = [new ClassifierMatch
        {
            Target = RuleTarget.FileName, Patterns = ["good.txt"]
        }] };
        var failed = await ScanAsync(drive, classifiers: [rule], logger: logger);
        Assert.True(failed.Incomplete);
        Assert.Single(failed.Findings);
        Assert.Equal(1, failed.Scanned);
        Assert.Equal(1, smb.EnumerationFailureCount);
        Assert.Equal(1, attempts.Count(path => path == "Unavailable"));
        Assert.Empty(failed.Checkpoints);
        Assert.Null(failed.FinalToken);
        Assert.Equal(warning, logger.Entries.Any(entry => entry.Level >= LogLevel.Warning));
        Assert.Contains(logger.Entries, entry => entry.Message.Contains("1 source inspections"));

        // A later scan tries the failed folder once again, and old failure state clears.
        attempts.Clear();
        unavailable = false;
        var recovered = await ScanAsync(drive, classifiers: [rule]);
        Assert.False(recovered.Incomplete);
        Assert.Equal(2, recovered.Findings.Count);
        Assert.Equal(0, smb.EnumerationFailureCount);
        Assert.Empty(smb.EnumerationFailures);
        Assert.Equal(1, attempts.Count(path => path == "Unavailable"));
    }

    [Fact]
    public async Task ManyDeniedFolders_KeepDiagnosticsBoundedAndRetainUnexpectedFailure()
    {
        using var smb = CreateDrive();
        var checkpoints = new List<string>();
        var attempts = 0;
        await smb.ProcessDirectoriesAsync(path =>
        {
            if (path.Length == 0)
                return Enumerable.Range(0, 100).Select(index => Entry(index.ToString(), true)).ToArray();
            attempts++;
            throw path == "0" ? new InvalidDataException("Unexpected final folder failure")
                : new UnauthorizedAccessException("Denied");
        }, null, _ => Task.CompletedTask, token => { checkpoints.Add(token); return Task.CompletedTask; });
        Assert.Equal(100, attempts);
        Assert.Equal(100, smb.EnumerationFailureCount);
        Assert.Equal(8, smb.EnumerationFailures.Count);
        Assert.Contains(smb.EnumerationFailures, failure => failure.Exception is InvalidDataException);
        Assert.Empty(checkpoints);
    }

    [Fact]
    public async Task FailureAfterSavedCheckpoint_KeepsFailedFolderInResumedStack()
    {
        using var smb = CreateDrive();
        var checkpoints = new List<string>();
        await smb.ProcessDirectoriesAsync(path =>
        {
            if (path.Length == 0)
                return Enumerable.Range(0, 130).Select(index => Entry(index.ToString(), true)).ToArray();
            if (path == "60") throw new UnauthorizedAccessException("Denied");
            return [];
        }, null, _ => Task.CompletedTask, token => { checkpoints.Add(token); return Task.CompletedTask; });
        var lastSafeCheckpoint = Assert.Single(checkpoints);
        Assert.Contains("60", SmbKerberosDrive.ParseCheckpoint(lastSafeCheckpoint));
        var attempts = new List<string>();
        await smb.ProcessDirectoriesAsync(path => { attempts.Add(path); return []; }, lastSafeCheckpoint,
            _ => Task.CompletedTask);
        Assert.Equal(1, attempts.Count(path => path == "60"));
        Assert.Equal(0, smb.EnumerationFailureCount);
    }

    [Fact]
    public async Task SameSizeEditsAndUnavailableTimestamps_AreScannedAgainOnResume()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ContentScanner:ResumeDirectory"] = directory
        }).Build();
        var store = new CliResumeStore(configuration, NullLogger<CliResumeStore>.Instance);
        using var smb = CreateDrive();
        using var pool = new SmbKerberosSessionPool(Connection(), "Data");
        IRemoteFile File(DateTime written, DateTime changed) => new SmbKerberosRemoteFile(Connection(), "Data", "test.txt",
            new FileDirectoryInformation { FileName = "test.txt", EndOfFile = 42, LastWriteTime = written, ChangeTime = changed }, false, pool);
        var firstTime = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var original = File(firstTime, firstTime);
        try
        {
            await using (var session = store.OpenSession("smb-versions", resume: false))
            {
                await session.MarkRemoteCompletedAsync(smb.ConnectionId, original.ResumeIdentity, original.Path, original.Size,
                    _ => Task.CompletedTask, CancellationToken.None, original.Version);
                var unknown = File(default, default);
                await session.MarkRemoteCompletedAsync(smb.ConnectionId, unknown.ResumeIdentity, unknown.Path, unknown.Size,
                    _ => Task.CompletedTask, CancellationToken.None, unknown.Version);
                await session.CommitAsync(_ => Task.CompletedTask, CancellationToken.None);
            }
            await using var resumed = store.OpenSession("smb-versions", resume: true);
            Assert.True(CliScanRunner.IsRemoteItemCompleted(resumed, smb, File(firstTime, firstTime)));
            Assert.False(CliScanRunner.IsRemoteItemCompleted(resumed, smb, File(firstTime.AddSeconds(1), firstTime)));
            Assert.False(CliScanRunner.IsRemoteItemCompleted(resumed, smb, File(firstTime, firstTime.AddSeconds(1))));
            Assert.False(CliScanRunner.IsRemoteItemCompleted(resumed, smb, File(default, default)));
            Assert.False(CliScanRunner.IsRemoteItemCompleted(resumed, smb, File(new DateTime(1601, 1, 1), default)));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void OldDirectoryStacks_RestartBecauseTheyMayHaveLostFailedSubtrees()
    {
        var current = SmbKerberosDrive.CreateCheckpoint(new Stack<string>(["Users\\Alice"]));
        Assert.Single(SmbKerberosDrive.ParseCheckpoint(current));
        Assert.Empty(SmbKerberosDrive.ParseCheckpoint(current.Replace("sift-smb-v3:", "sift-smb-v2:")));
    }

    private static SmbKerberosConnection Connection() => new(IPAddress.Loopback, "server.contoso.test", null, null,
        SmbAuthenticationProtocol.Ntlm, IsKerberosReady: false);
    private static SmbKerberosDrive CreateDrive() => new(Connection(), "Data", null, null);
    private static FileDirectoryInformation Entry(string name, bool directory = false) => new()
    {
        FileName = name, FileAttributes = directory ? FileAttributes.Directory : FileAttributes.Normal
    };

    private sealed class RoutingDrive(SmbKerberosDrive smb, Func<string, IReadOnlyList<FileDirectoryInformation>> list,
        bool offerCheckpoint = false)
        : IRemoteDrive, IRemoteDriveEnumerationReportProvider
    {
        public string Id => smb.Id;
        public string Name => smb.Name;
        public string ConnectionId => smb.ConnectionId;
        public string WebUrl => smb.WebUrl;
        public DatastoreType DriveType => smb.DriveType;
        public long? TotalSize => null;
        public long? UsedSize => null;
        public long EnumerationFailureCount => smb.EnumerationFailureCount;
        public IReadOnlyList<RemoteDriveEnumerationFailure> EnumerationFailures => smb.EnumerationFailures;
        public Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken ct = default)
            => throw new NotSupportedException();
        public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
            Func<string, Task>? onCheckpoint = null, CancellationToken ct = default)
        {
            var result = await smb.ProcessDirectoriesAsync(list, token, onChange, onCheckpoint, ct);
            if (offerCheckpoint && onCheckpoint != null) await onCheckpoint("reported-checkpoint");
            return result;
        }
    }

    public class ListingStoreProxy : DispatchProxy
    {
        internal NTStatus OpenStatus;
        internal NTStatus QueryStatus;
        internal bool Closed;
        protected override object? Invoke(MethodInfo? method, object?[]? args)
        {
            switch (method!.Name)
            {
                case "CreateFile":
                    args![0] = OpenStatus == NTStatus.STATUS_SUCCESS ? new object() : null;
                    args[1] = Activator.CreateInstance(method.GetParameters()[1].ParameterType.GetElementType()!);
                    return OpenStatus;
                case "QueryDirectory": args![0] = null; return QueryStatus;
                case "CloseFile": Closed = true; return NTStatus.STATUS_SUCCESS;
                case "Disconnect": return NTStatus.STATUS_SUCCESS;
                default: throw new NotSupportedException(method.Name);
            }
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
