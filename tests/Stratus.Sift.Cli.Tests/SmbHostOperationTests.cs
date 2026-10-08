using Stratus.Sift.Cli;

namespace Stratus.Sift.Cli.Tests;

public class SmbHostOperationTests
{
    [Fact]
    public async Task SlowResponseWithinBudgetCompletes()
    {
        var value = await SmbHostOperation.RunAsync(
            _ =>
            {
                Thread.Sleep(80);
                return 42;
            },
            "test SMB call", CancellationToken.None, TimeSpan.FromSeconds(5));

        Assert.Equal(42, value);
    }

    [Fact]
    public async Task BlockedCallTimesOutWithoutPublishingLateResult()
    {
        using var release = new ManualResetEventSlim();
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var published = false;
        try
        {
            var resultTask = SmbHostOperation.RunAsync(
                _ =>
                {
                    try
                    {
                        release.Wait();
                        return 42;
                    }
                    finally { finished.TrySetResult(); }
                },
                "test blocked SMB call", CancellationToken.None, TimeSpan.FromMilliseconds(250));

            var error = await Assert.ThrowsAsync<TimeoutException>(async () =>
            {
                _ = await resultTask;
                published = true;
            });
            Assert.Contains("test blocked SMB call", error.Message);
        }
        finally { release.Set(); }

        await finished.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(published);
    }

    [Fact]
    public async Task CallerCancellationReturnsPromptly()
    {
        using var release = new ManualResetEventSlim();
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        try
        {
            var running = SmbHostOperation.RunAsync(
                _ =>
                {
                    try
                    {
                        release.Wait();
                        return 1;
                    }
                    finally { finished.TrySetResult(); }
                },
                "test cancellation", cancellation.Token, TimeSpan.FromSeconds(5));

            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
        }
        finally { release.Set(); }

        await finished.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }
}
