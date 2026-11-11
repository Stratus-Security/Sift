using System.Diagnostics;

namespace Stratus.Sift.Cli;

// A scan must not depend on a synchronous SMB call returning. Keep ownership of
// abandoned sessions with their call, and bound the number of blocked calls.
internal sealed class SmbScanOperation<TResource>(
    Func<TResource> create,
    Action<TResource> dispose,
    TimeSpan? deadline = null) : IDisposable where TResource : class
{
    private readonly object _sync = new();
    private readonly TimeSpan _deadline = deadline ?? TimeSpan.FromMinutes(2);
    private TResource? _resource;
    private bool _busy;
    private bool _disposed;

    internal bool IsAvailable { get { lock (_sync) return !_disposed; } }

    internal async Task<TResult> RunAsync<TResult>(
        Func<TResource, TResult> operation,
        string description,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync) ObjectDisposedException.ThrowIf(_disposed, this);
        var started = Stopwatch.GetTimestamp();
        if (!await SmbScanOperationSlots.Slots.WaitAsync(_deadline, cancellationToken).ConfigureAwait(false))
            throw new TimeoutException($"{description} could not start within {_deadline.TotalSeconds:N0} seconds because other SMB calls are still blocked.");
        var remaining = _deadline - Stopwatch.GetElapsedTime(started);
        if (remaining <= TimeSpan.Zero)
        {
            SmbScanOperationSlots.Slots.Release();
            throw new TimeoutException($"{description} exhausted its {_deadline.TotalSeconds:N0}-second deadline waiting for other SMB calls.");
        }

        using var operationCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = operationCts.Token;
        lock (_sync)
        {
            if (_disposed || _busy)
            {
                SmbScanOperationSlots.Slots.Release();
                ObjectDisposedException.ThrowIf(_disposed, this);
                throw new InvalidOperationException("An SMB scan session cannot run concurrent operations.");
            }
            _busy = true;
        }

        var running = Task.Run(() =>
        {
            try
            {
                token.ThrowIfCancellationRequested();
                _resource ??= create();
                token.ThrowIfCancellationRequested();
                return operation(_resource);
            }
            finally
            {
                TResource? abandoned = null;
                lock (_sync)
                {
                    _busy = false;
                    if (_disposed || token.IsCancellationRequested)
                    {
                        _disposed = true;
                        abandoned = _resource;
                        _resource = null;
                    }
                }
                try { if (abandoned != null) dispose(abandoned); }
                finally { SmbScanOperationSlots.Slots.Release(); }
            }
        });

        try
        {
            return await running.WaitAsync(remaining, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException exception) when (!running.IsCompleted)
        {
            operationCts.Cancel();
            Dispose();
            SmbScanOperationSlots.Observe(running);
            throw new TimeoutException($"{description} exceeded {_deadline.TotalSeconds:N0} seconds; the session was discarded and unfinished work remains pending for resume.", exception);
        }
        catch (OperationCanceledException)
        {
            operationCts.Cancel();
            Dispose();
            SmbScanOperationSlots.Observe(running);
            throw;
        }
    }

    public void Dispose()
    {
        TResource? idle;
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
            // The in-flight call owns the session until it returns. In particular,
            // never close or reuse its handles while a late read can still run.
            if (_busy) return;
            idle = _resource;
            _resource = null;
        }
        if (idle == null) return;
        SmbScanOperationSlots.Observe(DisposeIdleAsync(idle));
    }

    private async Task DisposeIdleAsync(TResource resource)
    {
        await SmbScanOperationSlots.Slots.WaitAsync().ConfigureAwait(false);
        try { await Task.Run(() => dispose(resource)).ConfigureAwait(false); }
        finally { SmbScanOperationSlots.Slots.Release(); }
    }
}

// Shared across all resource types and shares, including late cleanup calls.
internal static class SmbScanOperationSlots
{
    internal static readonly SemaphoreSlim Slots = new(32, 32);

    internal static void Observe(Task task) => _ = task.ContinueWith(
        completed => _ = completed.Exception,
        CancellationToken.None,
        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
        TaskScheduler.Default);
}
