using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal abstract class Microsoft365WorkloadDrive(string tenant, string workload, DatastoreType type, int maxItems)
    : IRemoteDrive, IRemoteDriveEnumerationReportProvider
{
    protected string Workload => workload;
    protected string Tenant => tenant;
    protected int MaxItems => maxItems;
    private readonly List<RemoteDriveEnumerationFailure> _failures = [];
    private readonly HashSet<string> _items = new(StringComparer.Ordinal);
    private Exception? _consumerFailure;
    private bool _itemLimitReached;
    public string Id => "m365-workload:" + workload;
    public string Name => "Microsoft 365 " + workload;
    public string ConnectionId => "m365-workload://" + Uri.EscapeDataString(tenant) + "/" + workload;
    public abstract string WebUrl { get; }
    public DatastoreType DriveType => type;
    public long? TotalSize => null;
    public long? UsedSize => null;
    public long EnumerationFailureCount { get; private set; }
    public IReadOnlyList<RemoteDriveEnumerationFailure> EnumerationFailures => _failures;

    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken ct = default)
    {
        var changes = new List<IRemoteFile>();
        await ProcessChangesAsync(token, item => { changes.Add(item); return Task.CompletedTask; }, cancellationToken: ct);
        return (changes, "");
    }
    public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint = null, CancellationToken cancellationToken = default)
    {
        _failures.Clear(); _items.Clear(); EnumerationFailureCount = 0; _consumerFailure = null; _itemLimitReached = false;
        // These APIs do not provide a consistent cross-service delta. Re-enumerate
        // and use content/version fingerprints; never persist a lossy page cursor.
        try { await Attempt(WebUrl, () => ReadAsync(onChange, cancellationToken), cancellationToken); }
        catch (Exception ex) when (_itemLimitReached && !ReferenceEquals(ex, _consumerFailure)
            && !(ex is OperationCanceledException && cancellationToken.IsCancellationRequested)) { Record(WebUrl, ex); }
        return "";
    }
    protected abstract Task ReadAsync(Func<IRemoteFile, Task> onChange, CancellationToken ct);
    protected async Task Emit(IRemoteFile item, Func<IRemoteFile, Task> onChange, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (_items.Contains(item.ResumeIdentity)) return;
        if (_items.Count >= maxItems)
        {
            _itemLimitReached = true;
            throw new InvalidDataException("Workload exceeded MaxWorkloadItems; remaining content stays pending.");
        }
        _items.Add(item.ResumeIdentity);
        // Completion/output failures belong to the scanner pipeline, not source diagnostics.
        try { await onChange(item); }
        catch (Exception ex) { _consumerFailure = ex; throw; }
    }
    protected async Task Attempt(string path, Func<Task> action, CancellationToken ct)
    {
        try { await action(); }
        catch (Exception ex) when (!_itemLimitReached && !ReferenceEquals(ex, _consumerFailure)
            && !(ex is OperationCanceledException && ct.IsCancellationRequested)) { Record(path, ex); }
    }
    protected void Record(string path, Exception ex)
    {
        EnumerationFailureCount++;
        var sample = new RemoteDriveEnumerationFailure(path, ex);
        if (_failures.Count < 8) _failures.Add(sample);
        else if (!RemoteScanExceptionClassifier.IsExpectedForEnumeration(ex)
            && _failures.All(failure => RemoteScanExceptionClassifier.IsExpectedForEnumeration(failure.Exception))) _failures[^1] = sample;
    }
    protected static string Link(string service, string id) => service.TrimEnd('/') + "/#sift-item=" + Segment(id);
}
