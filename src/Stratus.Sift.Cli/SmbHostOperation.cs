namespace Stratus.Sift.Cli;

// SMBLibrary uses synchronous socket operations. Keep timed-out calls isolated and
// cap the number that can remain blocked after their callers have moved on.
internal static class SmbHostOperation
{
    private static readonly SemaphoreSlim Slots = new(16, 16);
    internal static readonly TimeSpan DefaultDeadline = TimeSpan.FromMinutes(2);

    internal static async Task<T> RunAsync<T>(
        Func<CancellationToken, T> operation,
        string description,
        CancellationToken cancellationToken,
        TimeSpan? deadline = null)
    {
        var limit = deadline ?? DefaultDeadline;
        if (!await Slots.WaitAsync(limit, cancellationToken).ConfigureAwait(false))
        {
            throw new TimeoutException($"{description} could not start within {limit.TotalSeconds:N0} seconds because other SMB calls are still waiting on remote servers.");
        }

        using var operationCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var operationToken = operationCts.Token;
        var running = Task.Run(() =>
        {
            try { return operation(operationToken); }
            finally { Slots.Release(); }
        });

        try
        {
            return await running.WaitAsync(limit, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException ex) when (!running.IsCompleted)
        {
            operationCts.Cancel();
            ObserveFault(running);
            throw new TimeoutException($"{description} exceeded {limit.TotalSeconds:N0} seconds; continuing with the remaining hosts.", ex);
        }
        catch (OperationCanceledException)
        {
            operationCts.Cancel();
            ObserveFault(running);
            throw;
        }
    }

    private static void ObserveFault(Task task) => _ = task.ContinueWith(
        completed => _ = completed.Exception,
        CancellationToken.None,
        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
        TaskScheduler.Default);
}
