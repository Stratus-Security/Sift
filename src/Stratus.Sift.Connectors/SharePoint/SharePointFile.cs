using Microsoft.Graph;
using Microsoft.Graph.Models;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;

namespace Stratus.Sift.Connectors.SharePoint;

public class SharePointFile : IRemoteFile
{
    private readonly GraphServiceClient _graphClient;
    private readonly DriveItem _item;
    private readonly string _driveId;
    private readonly string _currentTenantId;

    public SharePointFile(GraphServiceClient graphClient, string driveId, DriveItem item, string currentTenantId)
    {
        _graphClient = graphClient;
        _driveId = driveId;
        _item = item;
        _currentTenantId = currentTenantId;
    }

    public string Id => _item.Id ?? string.Empty;
    public string Name => _item.Name ?? string.Empty;
    public string Path => _item.WebUrl ?? Name;
    public string WebUrl => _item.WebUrl ?? string.Empty;
    public long? Size => _item.Size;
    public string? ContentType => _item.File?.MimeType;
    public bool IsDeleted => _item.Deleted != null;
    public bool IsDirectory => _item.Folder != null;

    public bool IsLink => _item.RemoteItem != null;

    public bool IsExternal
    {
        get
        {
            if (!IsLink)
            {
                return false;
            }

            if (_item.RemoteItem?.SharepointIds?.TenantId != null)
            {
                return !string.Equals(_item.RemoteItem.SharepointIds.TenantId, _currentTenantId, StringComparison.OrdinalIgnoreCase);
            }

            return true;
        }
    }

    public async Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default)
    {
        if (IsDeleted || _item.File == null)
        {
            return null;
        }

        try
        {
            return await _graphClient.Drives[_driveId].Items[Id].Content.GetAsync(cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            if (SharePointContentExceptionClassifier.TryWrap(ex, cancellationToken, out var wrapped))
            {
                throw wrapped;
            }

            throw;
        }
    }

    public async Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default)
    {
        if (IsDeleted || _item.File == null)
        {
            return null;
        }

        try
        {
            return await _graphClient.Drives[_driveId].Items[Id].Content.GetAsync(requestConfig =>
            {
                requestConfig.Headers.Add("Range", $"bytes={start}-{end}");
            }, cancellationToken);
        }
        catch (Exception ex)
        {
            if (SharePointContentExceptionClassifier.TryWrap(ex, cancellationToken, out var wrapped))
            {
                throw wrapped;
            }

            throw;
        }
    }

}
