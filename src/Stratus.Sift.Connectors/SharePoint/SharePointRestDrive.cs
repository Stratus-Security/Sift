using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class SharePointRestDrive : IRemoteDrive
{
    private readonly SharePointRestClient _client;
    private readonly SharePointRestClient.RestLibrary _library;
    private readonly string _tenantId;
    private readonly Microsoft365CoverageOptions _coverage;

    public SharePointRestDrive(SharePointRestClient client, SharePointRestClient.RestLibrary library, string tenantId, string name,
        Microsoft365CoverageOptions? coverage = null)
    {
        _client = client;
        _library = library;
        _tenantId = tenantId;
        Name = name;
        _coverage = coverage ?? Microsoft365CoverageOptions.Disabled;
    }

    public string Id => _library.Id;
    public string Name { get; }
    public string ConnectionId => $"sharepoint://{_tenantId}/{Id}";
    public string WebUrl => _library.WebUrl.AbsoluteUri;
    public DatastoreType DriveType => _library.DriveType;
    public long? TotalSize => null;
    public long? UsedSize => null;

    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? deltaToken, CancellationToken cancellationToken = default)
    {
        var changes = new List<IRemoteFile>();
        var newDeltaToken = await ProcessChangesAsync(
            deltaToken,
            file =>
            {
                changes.Add(file);
                return Task.CompletedTask;
            },
            null,
            cancellationToken);

        return (changes, newDeltaToken);
    }

    public async Task<string> ProcessChangesAsync(
        string? deltaToken,
        Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint = null,
        CancellationToken cancellationToken = default)
    {
        if (_coverage.ReadSharing || _coverage.ScanLibraryFields || _coverage.ScanVersions) deltaToken = null;
        if (string.IsNullOrWhiteSpace(deltaToken))
        {
            await _client.ProcessLibraryFilesAsync(
                _library,
                item => onChange(new SharePointRestFile(_client, _library.Site.Url, item, _coverage)),
                cancellationToken);

            return string.Empty;
        }

        var currentToken = string.IsNullOrWhiteSpace(deltaToken) ? null : deltaToken;
        var pagingToken = (string?)null;
        var latestChangeToken = currentToken ?? string.Empty;

        var seenTokens = new HashSet<(string? Change, string? Paging)>();
        while (true)
        {
            if (seenTokens.Count >= Microsoft365CoverageOptions.MaxPages || !seenTokens.Add((currentToken, pagingToken)))
                throw new InvalidDataException("SharePoint changes repeated a token or exceeded the page limit.");
            var changeSet = await _client.GetListItemChangesAsync(_library, currentToken, pagingToken, cancellationToken);
            if (!string.IsNullOrWhiteSpace(changeSet.LastChangeToken))
            {
                latestChangeToken = changeSet.LastChangeToken!;
            }

            foreach (var item in changeSet.Items)
            {
                await onChange(new SharePointRestFile(_client, _library.Site.Url, item, _coverage));
            }

            // Rowset pagination is independent of MoreChanges. Finish the rows
            // for this change-token window before advancing or checkpointing it.
            if (!string.IsNullOrWhiteSpace(changeSet.PagingToken))
            {
                pagingToken = changeSet.PagingToken;
                continue;
            }

            pagingToken = null;
            if (changeSet.MoreChanges)
            {
                if (string.IsNullOrWhiteSpace(changeSet.LastChangeToken))
                    throw new InvalidDataException("SharePoint reported more changes without a continuation token.");
                if (onCheckpoint != null)
                {
                    await onCheckpoint(changeSet.LastChangeToken);
                }

                currentToken = changeSet.LastChangeToken;
                continue;
            }

            break;
        }

        return latestChangeToken;
    }
}
