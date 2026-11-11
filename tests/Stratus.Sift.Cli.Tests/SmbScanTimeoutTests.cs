using System.Net;
using System.Reflection;
using SMBLibrary;
using SMBLibrary.Client;
using Stratus.Sift.Cli;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class SmbScanTimeoutTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan TestLimit = TimeSpan.FromSeconds(10);
    private static SmbKerberosConnection Connection => new(IPAddress.Loopback, "server", null, null,
        SmbAuthenticationProtocol.Ntlm, IsKerberosReady: false);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TimeoutInterruptsTransport_AndMoreThan32FailuresDoNotExhaustCallCapacity(bool cancel)
    {
        // The previous implementation retained every timed-out call indefinitely;
        // after 32 calls even healthy sessions could no longer start any work.
        for (var index = 0; index < 36; index++)
        {
            using var release = new ManualResetEventSlim();
            using var cancellation = new CancellationTokenSource();
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var store = Store();
            store.Proxy.Read = () => { entered.TrySetResult(); release.Wait(); return [1]; };
            using var pool = new SmbKerberosSessionPool(Connection, "Data", () =>
                new SmbScanSession(() => new SmbScanSession.Connection(store.Store, () => closed.TrySetResult()),
                    Deadline, release.Set));
            try
            {
                using var stream = await SmbKerberosReadStream.OpenAsync(pool, "stalled.txt", 0, 1, cancellation.Token);
                var read = stream.ReadAsync(new byte[1].AsMemory(), cancellation.Token).AsTask();
                if (cancel)
                {
                    await entered.Task.WaitAsync(TestLimit);
                    cancellation.Cancel();
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => read.WaitAsync(TestLimit));
                }
                else
                    await Assert.ThrowsAsync<RemoteContentUnavailableException>(() => read.WaitAsync(TestLimit));
                await closed.Task.WaitAsync(TestLimit);
                Assert.Equal(0, store.Proxy.CloseCalls);
            }
            finally { release.Set(); }
        }

        using var healthy = new SmbScanOperation<object>(() => new object(), _ => { }, TestLimit);
        Assert.Equal(42, await healthy.RunAsync(_ => 42, "healthy SMB call after failures", default).WaitAsync(TestLimit));
    }

    [Fact]
    public async Task BlockingTransportInterrupt_DoesNotBlockDeadlineOrDispose()
    {
        using var releaseCall = new ManualResetEventSlim();
        using var releaseInterrupt = new ManualResetEventSlim();
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var interruptEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var interruptFinished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var operation = new SmbScanOperation<object>(() => new object(), _ => closed.TrySetResult(), Deadline, () =>
        {
            interruptEntered.TrySetResult();
            releaseInterrupt.Wait();
            interruptFinished.TrySetResult();
        });
        try
        {
            await Assert.ThrowsAsync<TimeoutException>(() => operation.RunAsync(_ =>
            {
                releaseCall.Wait();
                return 1;
            }, "stalled SMB operation", default).WaitAsync(TestLimit));
            await interruptEntered.Task.WaitAsync(TestLimit);
            operation.Dispose();
            Assert.False(closed.Task.IsCompleted);
        }
        finally { releaseCall.Set(); releaseInterrupt.Set(); }
        await Task.WhenAll(closed.Task, interruptFinished.Task).WaitAsync(TestLimit);
    }

    [Fact]
    public void CustomTimeout_LowersWireResponseTimeout_AndKeepsResumeIdentity()
    {
        var configured = Connection with { OperationTimeoutSeconds = 10 };
        Assert.Equal(TimeSpan.FromSeconds(10), configured.OperationTimeout);
        Assert.Equal(10_000, configured.ResponseTimeoutMs);
        Assert.Equal(30_000, Connection.ResponseTimeoutMs);
        using var original = new SmbKerberosDrive(Connection, "Data", null, null);
        using var changed = new SmbKerberosDrive(configured, "Data", null, null);
        Assert.Equal(original.ConnectionId, changed.ConnectionId);
    }

    [Fact]
    public async Task StalledRead_IsDeferredWithoutLateBufferWrites_AndNextFileUsesFreshSession()
    {
        using var release = new ManualResetEventSlim();
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var bad = Store();
        bad.Proxy.Read = () => { release.Wait(); return [1, 2, 3]; };
        var good = Store();
        var created = 0;
        using var pool = new SmbKerberosSessionPool(Connection, "Data", () =>
            ++created == 1 ? Session(bad.Store, closed) : Session(good.Store));
        var buffer = Enumerable.Repeat((byte)0xA5, 8).ToArray();
        try
        {
            using (var stream = await SmbKerberosReadStream.OpenAsync(pool, "stalled.txt", 0, 3, default))
            {
                var error = await Assert.ThrowsAsync<RemoteContentUnavailableException>(
                    () => stream.ReadAsync(buffer.AsMemory()).AsTask().WaitAsync(TestLimit));
                Assert.True(error.ShouldRetry);
                Assert.Contains("stalled.txt", error.Message);
                Assert.Equal(0, stream.Position);
            }
            Assert.False(closed.Task.IsCompleted); // The late call still owns its session.
            Assert.Equal(0, bad.Proxy.CloseCalls);
            using var next = await SmbKerberosReadStream.OpenAsync(pool, "healthy.txt", 0, 3, default).WaitAsync(TestLimit);
            var healthy = new byte[3];
            Assert.Equal(3, await next.ReadAsync(healthy.AsMemory()));
            Assert.Equal(new byte[] { 1, 2, 3 }, healthy);
            Assert.Equal(2, created);
        }
        finally { release.Set(); }
        await closed.Task.WaitAsync(TestLimit);
        Assert.All(buffer, value => Assert.Equal((byte)0xA5, value));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationOfStalledRead_ReturnsPromptlyAndDoesNotReuseTheSession(bool synchronous)
    {
        using var release = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var store = Store();
        store.Proxy.Read = () => { entered.TrySetResult(); release.Wait(); return [1]; };
        using var pool = new SmbKerberosSessionPool(Connection, "Data", () => Session(store.Store, closed, TestLimit));
        try
        {
            using var stream = await SmbKerberosReadStream.OpenAsync(pool, "cancel.txt", 0, 1, cancellation.Token);
            var read = synchronous ? Task.Run(() => stream.Read(new byte[1], 0, 1))
                : stream.ReadAsync(new byte[1].AsMemory(), cancellation.Token).AsTask();
            await entered.Task.WaitAsync(TestLimit);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => read.WaitAsync(TestLimit));
            Assert.Equal(0, store.Proxy.CloseCalls);
        }
        finally { release.Set(); }
        await closed.Task.WaitAsync(TestLimit);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(64)]
    public async Task StalledFile_DrainsCheckpointBarrier_AndOnlyHealthyFileIsCompleted(int workers)
    {
        using var release = new ManualResetEventSlim();
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var pool = new SmbKerberosSessionPool(Connection, "Data", () =>
        {
            var store = Store();
            store.Proxy.Read = () =>
            {
                if (store.Proxy.Path == "stalled.txt") release.Wait();
                return [1, 2, 3];
            };
            return new SmbScanSession(() => new SmbScanSession.Connection(store.Store, () =>
            {
                if (store.Proxy.Path == "stalled.txt") closed.TrySetResult();
            }), Deadline);
        });
        IRemoteFile File(string name) => new SmbKerberosRemoteFile(Connection, "Data", name,
            new FileDirectoryInformation { FileName = name, EndOfFile = 3 }, false, pool);
        var processed = new List<string>();
        try
        {
            var result = await ScanAsync(new CheckpointDrive([File("stalled.txt"), File("healthy.txt")]),
                executionOptions: new RemoteDriveScanExecutionOptions(WorkerCount: workers),
                processed: (file, _) => { processed.Add(file.Name); return ValueTask.CompletedTask; }).WaitAsync(TestLimit);
            Assert.Equal(new[] { "healthy.txt" }, processed);
            Assert.Equal(1, result.Scanned);
            Assert.True(result.Incomplete);
            Assert.Empty(result.Checkpoints);
            Assert.Null(result.FinalToken);
        }
        finally { release.Set(); }
        await closed.Task.WaitAsync(TestLimit);
    }

    [Fact]
    public async Task StalledClose_DoesNotHoldTheScannerOrPoolLease()
    {
        using var release = new ManualResetEventSlim();
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var store = Store();
        store.Proxy.Close = () => release.Wait();
        using var pool = new SmbKerberosSessionPool(Connection, "Data", () => Session(store.Store, closed));
        try
        {
            var stream = await SmbKerberosReadStream.OpenAsync(pool, "close.txt", 0, 1, default);
            await Task.Run(stream.Dispose).WaitAsync(TestLimit);
            Assert.False(closed.Task.IsCompleted);
            Assert.Equal(1, store.Proxy.CloseCalls);
        }
        finally { release.Set(); }
        await closed.Task.WaitAsync(TestLimit);
    }

    [Fact]
    public async Task CancelledConnect_CleansUpLateSessionAndDoesNotPublishIt()
    {
        using var release = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var operation = new SmbScanOperation<object>(() =>
        {
            entered.TrySetResult();
            release.Wait();
            return new object();
        }, _ => closed.TrySetResult(), TestLimit);
        try
        {
            var running = operation.RunAsync(_ => 42, "connecting", cancellation.Token);
            await entered.Task.WaitAsync(TestLimit);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running.WaitAsync(TestLimit));
            Assert.False(operation.IsAvailable);
            Assert.False(closed.Task.IsCompleted);
        }
        finally { release.Set(); }
        await closed.Task.WaitAsync(TestLimit);
    }

    [Fact]
    public async Task TimedOutDirectory_KeepsSiblingTraversalAndPreventsCheckpointAdvancement()
    {
        using var release = new ManualResetEventSlim();
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var blocked = new SmbScanOperation<object>(() => new object(), _ => closed.TrySetResult(), Deadline);
        using var drive = new SmbKerberosDrive(Connection, "Data", null, null);
        var found = new List<string>();
        var checkpoints = new List<string>();
        try
        {
            await drive.ProcessDirectoriesAsync(async (path, token) =>
            {
                if (path.Length == 0)
                    return new[] { Entry("Healthy", true), Entry("Stalled", true) };
                if (path == "Stalled")
                    await blocked.RunAsync(_ => { release.Wait(); return 0; }, "listing Stalled", token);
                return new[] { Entry("healthy.txt") };
            }, null, item => { found.Add(item.Path); return Task.CompletedTask; },
                checkpoint => { checkpoints.Add(checkpoint); return Task.CompletedTask; }).WaitAsync(TestLimit);
            Assert.Contains(found, path => path.EndsWith(@"Healthy\healthy.txt", StringComparison.Ordinal));
            Assert.Equal(1, drive.EnumerationFailureCount);
            Assert.IsType<TimeoutException>(Assert.Single(drive.EnumerationFailures).Exception);
            Assert.Empty(checkpoints);
        }
        finally { release.Set(); }
        await closed.Task.WaitAsync(TestLimit);
    }

    private static FileDirectoryInformation Entry(string name, bool directory = false) => new()
    {
        FileName = name,
        FileAttributes = directory ? SMBLibrary.FileAttributes.Directory : SMBLibrary.FileAttributes.Normal
    };

    private static SmbScanSession Session(SmbKerberosStore store, TaskCompletionSource? closed = null, TimeSpan? deadline = null)
        => new(() => new SmbScanSession.Connection(store, () => closed?.TrySetResult()), deadline ?? Deadline);

    private static (SmbKerberosStore Store, FileStoreProxy Proxy) Store()
    {
        var inner = DispatchProxy.Create<ISMBFileStore, FileStoreProxy>();
        return (new SmbKerberosStore(inner), (FileStoreProxy)inner);
    }

    private sealed class CheckpointDrive(IRemoteFile[] files) : IRemoteDrive
    {
        public string Id => "drive";
        public string Name => @"\\server\Data";
        public string ConnectionId => "smb-test";
        public string WebUrl => Name;
        public DatastoreType DriveType => DatastoreType.FileSystem;
        public long? TotalSize => null;
        public long? UsedSize => null;
        public Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken ct = default)
            => throw new NotSupportedException();
        public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
            Func<string, Task>? onCheckpoint = null, CancellationToken ct = default)
        {
            foreach (var file in files) await onChange(file);
            if (onCheckpoint != null) await onCheckpoint("checkpoint");
            return "final";
        }
    }

    public class FileStoreProxy : DispatchProxy
    {
        internal Func<byte[]> Read = () => [1, 2, 3];
        internal Action? Close;
        internal int CloseCalls;
        internal string? Path;

        protected override object? Invoke(MethodInfo? method, object?[]? args)
        {
            switch (method!.Name)
            {
                case "CreateFile":
                    Path = (string)args![2]!;
                    args[0] = new object(); args[1] = default(FileStatus); return NTStatus.STATUS_SUCCESS;
                case "get_MaxReadSize": return 65536u;
                case "ReadFile": args![0] = Read(); return NTStatus.STATUS_SUCCESS;
                case "CloseFile": Interlocked.Increment(ref CloseCalls); Close?.Invoke(); return NTStatus.STATUS_SUCCESS;
                default: throw new NotSupportedException(method.Name);
            }
        }
    }
}
