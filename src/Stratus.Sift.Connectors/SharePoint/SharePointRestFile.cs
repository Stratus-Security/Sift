using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed partial class SharePointRestFile : IRemoteFile, IRemoteFileInspection, IRemoteFileSupplementProvider
{
    private readonly SharePointRestClient _client;
    private readonly Uri _siteUrl;
    private readonly SharePointRestClient.RestFileItem _item;
    private readonly Microsoft365CoverageOptions _coverage;

    public SharePointRestFile(SharePointRestClient client, Uri siteUrl, SharePointRestClient.RestFileItem item,
        Microsoft365CoverageOptions? coverage = null)
    {
        _client = client;
        _siteUrl = siteUrl;
        _item = item;
        _coverage = coverage ?? Microsoft365CoverageOptions.Disabled;
    }

    public string Id => _item.Id;
    public string Name => _item.Name;
    private bool ConvertContent => !IsDeleted && !IsDirectory && Microsoft365ContentProjection.Supports(Name);
    public string ContentName => ConvertContent ? Name + ".html" : Name;
    private Task<(string Drive, string Item)>? _projectionTarget;
    private Task<(string Drive, string Item)> ProjectionTarget(CancellationToken ct)
        => _projectionTarget ??= _coverage.GraphClient == null
            ? Task.FromException<(string, string)>(Microsoft365ContentProjection.Unavailable("Graph access is needed to convert this file."))
            : Microsoft365ContentProjection.ResolveNativeFile(_coverage.GraphClient, _siteUrl, _item.ServerRelativeUrl, ct);
    public string Path => _item.WebUrl.AbsoluteUri;
    public string WebUrl => _item.WebUrl.AbsoluteUri;
    public long? Size => ConvertContent ? null : _item.Size;
    public string? Version => _item.Version == null ? null : _item.Version + _sharingVersion + (ConvertContent ? Microsoft365ContentProjection.VersionSuffix : "");
    public string? ContentType => null;
    public bool IsDeleted => _item.IsDeleted;
    public bool IsDirectory => _item.IsDirectory;
    public bool IsLink => false;
    public bool IsExternal => Exposure is "External" or "Public";

    public async Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default)
    {
        if (IsDeleted || IsDirectory)
        {
            return null;
        }

        try
        {
            if (ConvertContent)
            {
                var target = await ProjectionTarget(cancellationToken);
                return await Microsoft365ContentProjection.Open(_coverage.GraphClient, target.Drive, target.Item, cancellationToken);
            }
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
        if (ConvertContent) return await GetContentAsync(cancellationToken);
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
