using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Abstractions;
using System.Runtime.CompilerServices;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;

namespace Stratus.Sift.Connectors.SharePoint;

public partial class SharePointFile : IRemoteFile, IRemoteFileTraversal, IRemoteFileInspection, IRemoteFileSupplementProvider
{
    private readonly GraphServiceClient _graphClient;
    private readonly DriveItem _item;
    private readonly string _driveId;
    private readonly string _currentTenantId;
    private readonly bool _isExternal;
    private readonly Microsoft365CoverageOptions _coverage = Microsoft365CoverageOptions.Disabled;
    private static readonly string[] TraversalSelectFields =
        ["id", "name", "webUrl", "size", "file", "folder", "deleted", "remoteItem", "sharepointIds", "eTag", "cTag", "lastModifiedDateTime", "createdBy", "parentReference", "shared", "publication"];

    public SharePointFile(GraphServiceClient graphClient, string driveId, DriveItem item, string currentTenantId, bool isExternal = false)
    {
        _graphClient = graphClient;
        _driveId = driveId;
        _item = item;
        _currentTenantId = currentTenantId;
        _isExternal = isExternal;
    }

    internal SharePointFile(GraphServiceClient graphClient, string driveId, DriveItem item, string tenantId,
        bool isExternal, Microsoft365CoverageOptions coverage) : this(graphClient, driveId, item, tenantId, isExternal)
        => _coverage = coverage;

    public string Id => _item.Id ?? string.Empty;
    public string TraversalIdentity => $"{_driveId.Length}:{_driveId}{Id}";
    public string ResumeIdentity => TraversalIdentity;
    public string Name => _item.Name ?? string.Empty;
    private bool ConvertContent => !IsDeleted && !IsDirectory && Microsoft365ContentProjection.Supports(Name);
    public string ContentName => ConvertContent ? Name + ".html" : Name;
    public string Path => _item.WebUrl ?? Name;
    public string WebUrl => _item.WebUrl ?? string.Empty;
    public long? Size => ConvertContent ? null : _item.Size;
    public string? Version => ServerVersion is null ? null : ServerVersion + _sharingVersion + (ConvertContent ? Microsoft365ContentProjection.VersionSuffix : "");
    public DateTimeOffset? LastEditedAtUtc => _item.LastModifiedDateTime;
    private string? ServerVersion => _item.ETag ?? _item.CTag
        ?? _item.LastModifiedDateTime?.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
    public string? ContentType => _item.File?.MimeType;
    public bool IsDeleted => _item.Deleted != null;
    public bool IsDirectory => _item.Folder != null || _item.RemoteItem?.Folder != null;

    public bool IsLink => _item.RemoteItem != null;

    public bool IsExternal
    {
        get
        {
            if (_isExternal) return true;
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

    public async Task<IRemoteFile?> ResolveLinkAsync(bool includeExternal, CancellationToken cancellationToken = default)
    {
        if (_item.RemoteItem is not { } remote) return this;
        var declaredTenant = remote.SharepointIds?.TenantId;
        if (!includeExternal && (_isExternal || (!string.IsNullOrWhiteSpace(declaredTenant)
            && !string.Equals(declaredTenant, _currentTenantId, StringComparison.OrdinalIgnoreCase)))) return null;
        var targetDrive = remote.ParentReference?.DriveId;
        if (string.IsNullOrWhiteSpace(targetDrive) || string.IsNullOrWhiteSpace(remote.Id))
            throw new InvalidDataException("SharePoint shortcut has no target drive/item identity.");

        var target = await _graphClient.Drives[targetDrive].Items[remote.Id].GetAsync(configuration =>
            configuration.QueryParameters.Select = TraversalSelectFields, cancellationToken);
        if (target == null || string.IsNullOrWhiteSpace(target.Id)
            || (target.Deleted == null && (string.IsNullOrWhiteSpace(target.Name)
                || (target.File == null && target.Folder == null && target.RemoteItem == null))))
            throw new InvalidDataException("SharePoint shortcut target response was empty or malformed.");

        var targetTenant = target.SharepointIds?.TenantId ?? declaredTenant;
        var external = _isExternal || string.IsNullOrWhiteSpace(targetTenant)
            || !string.Equals(targetTenant, _currentTenantId, StringComparison.OrdinalIgnoreCase);
        if (external && !includeExternal) return null;
        return new SharePointFile(_graphClient, targetDrive, target, _currentTenantId, external,
            _coverage with { NativeSiteUrl = null });
    }

    public async IAsyncEnumerable<IRemoteFile> GetChildrenAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var request = _graphClient.Drives[_driveId].Items[Id].Children;
        var response = await request.GetAsync(configuration =>
        {
            configuration.QueryParameters.Select = TraversalSelectFields;
            configuration.QueryParameters.Top = 999;
        }, cancellationToken);
        var visitedPages = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            if (response?.Value == null) throw new InvalidDataException("SharePoint shortcut children response was empty.");
            foreach (var child in response.Value)
            {
                if (string.IsNullOrWhiteSpace(child.Id) || (child.Deleted == null
                    && (string.IsNullOrWhiteSpace(child.Name) || (child.File == null && child.Folder == null && child.RemoteItem == null))))
                    throw new InvalidDataException("SharePoint shortcut child has no item identity, name, or file/folder kind.");
                yield return new SharePointFile(_graphClient, _driveId, child, _currentTenantId, _isExternal, _coverage);
            }
            if (string.IsNullOrWhiteSpace(response.OdataNextLink)) yield break;
            var next = new Uri(response.OdataNextLink);
            var graphRoot = new Uri(_graphClient.RequestAdapter.BaseUrl
                ?? throw new InvalidDataException("Graph client has no service URL."));
            if (next.Scheme != Uri.UriSchemeHttps || !next.Host.Equals(graphRoot.Host, StringComparison.OrdinalIgnoreCase)
                || next.Port != graphRoot.Port || visitedPages.Count >= Microsoft365CoverageOptions.MaxPages || !visitedPages.Add(next.AbsoluteUri))
                throw new InvalidDataException("SharePoint shortcut returned an invalid or repeated continuation link.");
            var requestInfo = request.ToGetRequestInformation();
            requestInfo.URI = next;
            response = await _graphClient.RequestAdapter.SendAsync(requestInfo,
                DriveItemCollectionResponse.CreateFromDiscriminatorValue, cancellationToken: cancellationToken);
        }
    }

    public async Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default)
    {
        if (IsDeleted || (_item.File == null && _item.RemoteItem?.File == null))
        {
            return null;
        }

        try
        {
            var target = GetContentTarget();
            if (ConvertContent) return await Microsoft365ContentProjection.Open(_graphClient, target.DriveId, target.ItemId, cancellationToken);
            return await _graphClient.Drives[target.DriveId].Items[target.ItemId].Content.GetAsync(cancellationToken: cancellationToken);
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
        if (IsDeleted || (_item.File == null && _item.RemoteItem?.File == null))
        {
            return null;
        }

        try
        {
            var target = GetContentTarget();
            return await _graphClient.Drives[target.DriveId].Items[target.ItemId].Content.GetAsync(requestConfig =>
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

    private (string DriveId, string ItemId) GetContentTarget()
    {
        if (_item.RemoteItem is not { } remote) return (_driveId, Id);
        if (string.IsNullOrWhiteSpace(remote.ParentReference?.DriveId) || string.IsNullOrWhiteSpace(remote.Id))
            throw new InvalidDataException("SharePoint shortcut has no target drive/item identity.");
        return (remote.ParentReference.DriveId, remote.Id);
    }
}
