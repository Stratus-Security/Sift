using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Kiota.Abstractions;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Models;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

public partial class SharePointFile
{
    private string _sharingVersion = string.Empty;
    private bool _accessComplete = true;
    private string? _exposure;
    private string? _owner;
    private Uri? _nativeSite;
    private async Task<Uri?> NativeSiteAsync(CancellationToken ct)
    {
        if (_nativeSite != null) return _nativeSite;
        if (Uri.TryCreate(_item.SharepointIds?.SiteUrl, UriKind.Absolute, out var site)) return _nativeSite = site;
        if (_coverage.NativeSiteUrl != null && new Uri(WebUrl).Host.Equals(_coverage.NativeSiteUrl.Host, StringComparison.OrdinalIgnoreCase)
            && new Uri(WebUrl).AbsolutePath.StartsWith(_coverage.NativeSiteUrl.AbsolutePath.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase))
            return _nativeSite = _coverage.NativeSiteUrl;
        if (_coverage.NativeClient == null) return null;
        var resolved = await _coverage.NativeClient.TryResolveSiteAsync(new Uri(WebUrl), ct);
        return _nativeSite = resolved?.Url;
    }
    private readonly List<AclEntry> _acls = [];
    public string Exposure => _exposure ?? (IsExternal ? "External" : _coverage.ReadSharing ? "Unknown" : "Internal");
    public string Owner => _owner ?? _item.CreatedBy?.User?.DisplayName ?? _item.CreatedBy?.User?.Id ?? "Cloud";
    public IReadOnlyList<AclEntry> AclEntries => _acls;
    public bool IsContentComplete => _accessComplete;

    public async Task PrepareAsync(CancellationToken cancellationToken)
    {
        if (!_coverage.ReadSharing || IsDeleted || IsLink) return;
        var reader = new Microsoft365GraphReader(_graphClient);
        var permissions = new List<JsonElement>();
        _acls.Clear();
        try
        {
            await foreach (var permission in reader.EnumerateAsync($"drives/{Segment(_driveId)}/items/{Segment(Id)}/permissions", cancellationToken))
            {
                if (permissions.Count >= 10_000) throw new InvalidDataException("File permissions exceed the inspection limit.");
                permissions.Add(permission);
            }
            var publicAccess = false;
            var externalAccess = IsExternal;
            var organizationAccess = false;
            var unknown = false;
            foreach (var permission in permissions)
            {
                var roles = permission.TryGetProperty("roles", out var roleValues) && roleValues.ValueKind == JsonValueKind.Array
                    ? string.Join(",", roleValues.EnumerateArray().Select(value => value.GetString())) : "unknown";
                var inherited = permission.TryGetProperty("inheritedFrom", out _);
                if (permission.TryGetProperty("link", out var link))
                {
                    var scope = String(link, "scope");
                    publicAccess |= scope == "anonymous";
                    organizationAccess |= scope == "organization";
                    _acls.Add(new()
                    {
                        Identity = "sharing-link:" + (scope ?? "unknown"),
                        Permissions = roles,
                        AccessControlType = "Allow",
                        IsInherited = inherited
                    });
                    unknown |= scope is not ("anonymous" or "organization" or "users");
                }
                var actors = new List<JsonElement>();
                if (permission.TryGetProperty("grantedToV2", out var actor)) actors.Add(actor);
                if (permission.TryGetProperty("grantedTo", out actor)) actors.Add(actor);
                foreach (var key in new[] { "grantedToIdentitiesV2", "grantedToIdentities" })
                    if (permission.TryGetProperty(key, out var collection) && collection.ValueKind == JsonValueKind.Array)
                        actors.AddRange(collection.EnumerateArray());
                foreach (var identity in actors)
                {
                    foreach (var kind in new[] { "user", "group", "siteUser", "siteGroup" })
                    {
                        if (!identity.TryGetProperty(kind, out var principal)) continue;
                        var principalId = String(principal, "id");
                        var label = String(principal, "email") ?? String(principal, "loginName")
                            ?? String(principal, "displayName") ?? principalId ?? "unknown";
                        _acls.Add(new() { Identity = label, Permissions = roles, AccessControlType = "Allow", IsInherited = inherited });
                        if (label.Contains("#ext#", StringComparison.OrdinalIgnoreCase)) externalAccess = true;
                        else if (kind is "user" or "group" && !string.IsNullOrWhiteSpace(principalId))
                        {
                            try
                            {
                                externalAccess |= await Microsoft365PrincipalReader.IsGuestAsync(_graphClient, kind, principalId, cancellationToken);
                            }
                            catch (ApiException ex) when (!cancellationToken.IsCancellationRequested
                                && ex.ResponseStatusCode is 403 or 404
                                && !_coverage.GraphPermissionsAreComplete && _coverage.NativeClient != null)
                            {
                                // Graph can retain grants for deleted users, or hide
                                // directory details from delegated callers. Complete
                                // native reconciliation below must resolve the gap.
                                unknown = true;
                            }
                        }
                        else if (kind is "siteGroup" or "siteUser" && principalId != null)
                        {
                            var site = await NativeSiteAsync(cancellationToken);
                            if (_coverage.NativeClient == null || site == null) unknown = true;
                            else externalAccess |= await Microsoft365NativeAccessReader.IsSitePrincipalGuestAsync(
                                _coverage.NativeClient, site, kind, principalId, _coverage, cancellationToken);
                        }
                    }
                }
                if (permission.TryGetProperty("invitation", out _) && actors.Count == 0) unknown = true;
            }
            _exposure = publicAccess ? "Public" : externalAccess ? "External" : unknown ? "Unknown"
                : organizationAccess ? "Organization" : "Restricted";
            var nativeFingerprint = "";
            if (!_coverage.GraphPermissionsAreComplete)
            {
                var site = await NativeSiteAsync(cancellationToken);
                if (_coverage.NativeClient == null || site == null)
                    throw new InvalidDataException("Delegated Graph permissions may only show grants visible to the caller; native permission reconciliation is required.");
                var relative = Uri.UnescapeDataString(new Uri(WebUrl).AbsolutePath);
                var resource = _item.SharepointIds?.ListId is { } listId && _item.SharepointIds.ListItemId is { } itemId
                    ? $"web/lists('{SharePointRestClient.ResourcePath(listId)}')/items({Microsoft365NativeAccessReader.ValidatedNumber(itemId)})"
                    : $"web/GetFileByServerRelativePath(decodedurl='{SharePointRestClient.ResourcePath(relative)}')/ListItemAllFields";
                var access = await Microsoft365NativeAccessReader.ReadAsync(_coverage.NativeClient, site,
                    resource, _coverage, cancellationToken);
                nativeFingerprint = access.Fingerprint;
                _owner = access.Owner;
                _acls.AddRange(access.Acls);
                _exposure = publicAccess || access.Exposure == "Public" ? "Public"
                    : externalAccess || access.Exposure == "External" ? "External" : access.Exposure;
                unknown = false;
            }
            _sharingVersion = ":sharing:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                nativeFingerprint + _exposure + "\n" + string.Join('\n', permissions.Select(value => value.GetRawText()).Order(StringComparer.Ordinal)))));
            if (unknown && !publicAccess && !externalAccess)
                throw new InvalidDataException("Some sharing principals could not be classified; exposure remains unknown.");
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            _accessComplete = false;
            if (_exposure is not ("Public" or "External")) _exposure = "Unknown";
            throw;
        }
    }

    public async IAsyncEnumerable<IRemoteFile> GetSupplementalFilesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (IsDeleted || IsDirectory || IsLink || (!_coverage.ScanLibraryFields && !_coverage.ScanVersions)) yield break;
        var reader = new Microsoft365GraphReader(_graphClient);
        var prefix = $"drives/{Segment(_driveId)}/items/{Segment(Id)}";
        var currentVersion = _item.Publication?.VersionId;
        Exception? fieldFailure = null;
        Microsoft365ContentFile? fieldFile = null;
        if (_coverage.ScanLibraryFields)
        {
            try
            {
                using var document = await reader.GetAsync(prefix + "/listItem?$expand=fields", cancellationToken);
                if (!document.RootElement.TryGetProperty("fields", out var fields) || fields.ValueKind != JsonValueKind.Object)
                    throw new InvalidDataException("Library item response had no field values.");
                currentVersion ??= String(fields, "_UIVersionString");
                fieldFile = Microsoft365ContentFile.Text(TraversalIdentity + ":fields", Name + ".fields.json", WebUrl + "#sift-fields",
                    SearchableText(fields), _accessComplete, Exposure, Owner, _acls);
            }
            catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested)) { fieldFailure = ex; }
            if (fieldFile != null) yield return fieldFile;
        }
        if (_coverage.ScanVersions)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var historicalCount = 0;
            await foreach (var version in reader.EnumerateAsync(prefix + "/versions", cancellationToken))
            {
                var versionId = Microsoft365GraphReader.Id(version);
                if (!seen.Add(versionId)) continue;
                if (string.IsNullOrWhiteSpace(currentVersion))
                {
                    using var current = await reader.GetAsync(prefix + "?$select=id,publication", cancellationToken);
                    if (current.RootElement.TryGetProperty("publication", out var publication))
                        currentVersion = String(publication, "versionId");
                    if (string.IsNullOrWhiteSpace(currentVersion))
                        throw new InvalidDataException("Current file version could not be established.");
                }
                // Graph includes the current version in history, but its version
                // content endpoint rejects it. The main file already scans it.
                if (versionId == currentVersion) continue;
                if (++historicalCount > _coverage.MaxVersionsPerFile) throw new InvalidDataException("File history exceeds MaxVersionsPerFile.");
                var size = long.TryParse(String(version, "size"), out var bytes) ? bytes : (long?)null;
                var contentUrl = reader.Url(prefix + $"/versions/{Segment(versionId)}/content");
                yield return new Microsoft365ContentFile(TraversalIdentity + ":version:" + versionId, Name,
                    WebUrl + "#sift-version=" + Uri.EscapeDataString(versionId), "version:" + versionId + _sharingVersion
                        + (ConvertContent ? Microsoft365ContentProjection.VersionSuffix : ""),
                    ConvertContent ? null : size, async (range, ct) => ConvertContent
                        ? await Microsoft365ContentProjection.Open(_graphClient, _driveId, Id, ct, versionId)
                        : await reader.OpenAsync(contentUrl, ct, range), _accessComplete, Exposure, Owner, _acls)
                    { ContentName = ContentName };
            }
        }
        if (fieldFailure != null) throw new InvalidDataException("Library fields could not be read.", fieldFailure);
    }
}
