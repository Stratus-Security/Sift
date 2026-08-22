using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class SharePointRestFile : IRemoteFile
{
    private readonly SharePointRestClient _client;
    private readonly Uri _siteUrl;
    private readonly SharePointRestClient.RestFileItem _item;

    public SharePointRestFile(SharePointRestClient client, Uri siteUrl, SharePointRestClient.RestFileItem item)
    {
        _client = client;
        _siteUrl = siteUrl;
        _item = item;
    }

    public string Id => _item.Id;
    public string Name => _item.Name;
    public string Path => _item.WebUrl.AbsoluteUri;
    public string WebUrl => _item.WebUrl.AbsoluteUri;
    public long? Size => _item.Size;
    public string? ContentType => null;
    public bool IsDeleted => _item.IsDeleted;
    public bool IsDirectory => _item.IsDirectory;
    public bool IsLink => false;
    public bool IsExternal => false;

    public async Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default)
    {
        if (IsDeleted || IsDirectory)
        {
            return null;
        }

        try
        {
            return await _client.OpenFileContentAsync(_siteUrl, _item.ServerRelativeUrl, rangeHeader: null, cancellationToken);
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
        if (IsDeleted || IsDirectory)
        {
            return null;
        }

        try
        {
            return await _client.OpenFileContentAsync(_siteUrl, _item.ServerRelativeUrl, $"bytes={start}-{end}", cancellationToken);
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
