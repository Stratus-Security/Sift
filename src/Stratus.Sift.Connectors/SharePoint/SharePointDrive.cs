using Microsoft.Graph;
using Microsoft.Graph.Drives.Item.Items.Item.Delta;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Abstractions;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.SharePoint;

public class SharePointDrive : IRemoteDrive
{
    private const int DeltaPageSize = 999;
    private static readonly string[] DeltaSelectFields = ["id", "name", "webUrl", "size", "file", "folder", "deleted", "remoteItem", "eTag", "cTag", "lastModifiedDateTime", "createdBy", "parentReference", "sharepointIds", "shared"];

    private readonly GraphServiceClient _graphClient;
    private readonly Drive _drive;
    private readonly string _tenantId;
    private readonly string? _rootItemId;
    private readonly string? _nameOverride;
    private readonly string? _webUrlOverride;
    private readonly Microsoft365CoverageOptions _coverage = Microsoft365CoverageOptions.Disabled;

    public DatastoreType DriveType { get; }

    public SharePointDrive(
        GraphServiceClient graphClient,
        Drive drive,
        string tenantId,
        DatastoreType driveType = DatastoreType.SharePoint,
        string? rootItemId = null,
        string? nameOverride = null,
        string? webUrlOverride = null)
    {
        _graphClient = graphClient;
        _drive = drive;
        _tenantId = tenantId;
        _rootItemId = string.IsNullOrWhiteSpace(rootItemId) ? null : rootItemId;
        _nameOverride = nameOverride;
        _webUrlOverride = webUrlOverride;
        DriveType = driveType;
    }

    internal SharePointDrive(GraphServiceClient client, Drive drive, string tenantId, DatastoreType type,
        Microsoft365CoverageOptions coverage, string? rootItemId = null, string? name = null, string? webUrl = null)
        : this(client, drive, tenantId, type, rootItemId, name, webUrl) => _coverage = coverage;

    public string Id => _drive.Id ?? string.Empty;
    public string Name => !string.IsNullOrWhiteSpace(_nameOverride) ? _nameOverride : _drive.Name ?? "Unknown Drive";
    public string ConnectionId => string.IsNullOrWhiteSpace(_rootItemId)
        ? $"sharepoint://{_tenantId}/{Id}"
        : $"sharepoint://{_tenantId}/{Id}/items/{Uri.EscapeDataString(_rootItemId)}";
    public string WebUrl => !string.IsNullOrWhiteSpace(_webUrlOverride) ? _webUrlOverride : _drive.WebUrl ?? string.Empty;
    public long? TotalSize => _drive.Quota?.Total;
    public long? UsedSize => _drive.Quota?.Used;
    internal string? RootItemId => _rootItemId;
    internal bool IsScoped => !string.IsNullOrWhiteSpace(_rootItemId);

    internal SharePointDrive WithDriveType(DatastoreType driveType, string? name = null)
        => new(
            _graphClient,
            _drive,
            _tenantId,
            driveType,
            _coverage,
            _rootItemId,
            name ?? _nameOverride,
            _webUrlOverride);

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
        // Changes to group membership and historical content need not appear in the source delta.
        // Re-enumerate metadata while the item journal skips unchanged content downloads.
        var refreshCoverage = _coverage.ReadSharing || _coverage.ScanLibraryFields || _coverage.ScanVersions;
        try
        {
            var token = await ProcessDeltaPagesAsync(refreshCoverage ? null : deltaToken, onChange,
                refreshCoverage ? null : onCheckpoint, cancellationToken);
            return refreshCoverage ? string.Empty : token;
        }
        catch (ApiException ex) when (ex.ResponseStatusCode == 410)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Invalidate both the source token and the item journal before a fresh crawl.
            // Recovery is attempted once; a second 410 propagates as an incomplete scan.
            if (onCheckpoint != null)
            {
                await onCheckpoint(string.Empty);
            }
            var token = await ProcessDeltaPagesAsync(null, onChange, refreshCoverage ? null : onCheckpoint, cancellationToken);
            return refreshCoverage ? string.Empty : token;
        }
    }

    private async Task<string> ProcessDeltaPagesAsync(
        string? deltaToken,
        Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint,
        CancellationToken cancellationToken)
    {
        string currentLink = deltaToken ?? string.Empty;
        var visitedLinks = new HashSet<string>(StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(currentLink)) visitedLinks.Add(currentLink);
        DeltaGetResponse? response;

        var deltaRequest = _graphClient.Drives[Id].Items[_rootItemId ?? "root"].Delta;
        if (string.IsNullOrEmpty(currentLink))
        {
            response = await deltaRequest.GetAsDeltaGetResponseAsync(requestConfiguration =>
            {
                requestConfiguration.QueryParameters.Top = DeltaPageSize;
                requestConfiguration.QueryParameters.Select = DeltaSelectFields;
            }, cancellationToken: cancellationToken);
        }
        else
        {
            var requestInfo = deltaRequest.ToGetRequestInformation();
            requestInfo.URI = new Uri(currentLink);
            response = await _graphClient.RequestAdapter.SendAsync<DeltaGetResponse>(
                requestInfo,
                DeltaGetResponse.CreateFromDiscriminatorValue,
                cancellationToken: cancellationToken);
        }

        while (response != null)
        {
            if (response.Value == null)
            {
                throw new InvalidDataException("Graph delta response did not contain an item collection.");
            }
            foreach (var item in response.Value)
            {
                await onChange(new SharePointFile(_graphClient, Id, item, _tenantId, false, _coverage));
            }

            if (string.IsNullOrEmpty(response.OdataNextLink))
            {
                return !string.IsNullOrWhiteSpace(response.OdataDeltaLink)
                    ? response.OdataDeltaLink
                    : throw new InvalidDataException("Graph delta enumeration ended without a final delta token.");
            }

            if (!visitedLinks.Add(response.OdataNextLink))
            {
                throw new InvalidDataException("Graph delta enumeration returned a repeated continuation link.");
            }

            if (onCheckpoint != null)
            {
                await onCheckpoint(response.OdataNextLink);
            }

            var requestInfo = deltaRequest.ToGetRequestInformation();
            requestInfo.URI = new Uri(response.OdataNextLink);
            response = await _graphClient.RequestAdapter.SendAsync<DeltaGetResponse>(
                requestInfo,
                DeltaGetResponse.CreateFromDiscriminatorValue,
                cancellationToken: cancellationToken);
        }

        throw new InvalidDataException("Graph delta response was empty.");
    }
}
