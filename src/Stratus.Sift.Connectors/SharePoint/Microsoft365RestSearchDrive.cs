using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class Microsoft365RestSearchDrive(SharePointRestClient client, Uri root, string tenant,
    Microsoft365CoverageOptions options) : IRemoteDrive
{
    public string Id => "accessible-file-search-native";
    public string Name => "Accessible and shared files (SharePoint search index)";
    public string ConnectionId => $"sharepoint-search://{tenant}/native-accessible-files";
    public string WebUrl => root.AbsoluteUri;
    public DatastoreType DriveType => DatastoreType.SharePoint;
    public long? TotalSize => null;
    public long? UsedSize => null;
    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken cancellationToken = default)
    {
        var files = new List<IRemoteFile>();
        await ProcessChangesAsync(token, item => { files.Add(item); return Task.CompletedTask; }, cancellationToken: cancellationToken);
        return (files, string.Empty);
    }
    public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint = null, CancellationToken cancellationToken = default)
    {
        await foreach (var (site, file) in client.SearchAccessibleFilesAsync(root, cancellationToken))
            await onChange(new SharePointRestFile(client, site, file, options));
        return string.Empty;
    }
}
