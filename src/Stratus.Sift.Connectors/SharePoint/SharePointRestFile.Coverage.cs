using System.Runtime.CompilerServices;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Models;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed partial class SharePointRestFile
{
    private string _sharingVersion = "";
    private Microsoft365Access? _access;
    public bool IsContentComplete { get; private set; } = true;
    public string Exposure => _access?.Exposure ?? (_coverage.ReadSharing ? "Unknown" : "Internal");
    public string Owner => _access?.Owner ?? "Cloud";
    public IReadOnlyList<AclEntry> AclEntries => _access?.Acls ?? [];
    private string Resource => $"web/{(IsDirectory ? "GetFolderByServerRelativePath" : "GetFileByServerRelativePath")}(decodedurl='{SharePointRestClient.ResourcePath(_item.ServerRelativeUrl)}')";
    public async Task PrepareAsync(CancellationToken ct)
    {
        if (!_coverage.ReadSharing || IsDeleted) return;
        try
        {
            _access = await Microsoft365NativeAccessReader.ReadAsync(_client, _siteUrl, Resource + "/ListItemAllFields", _coverage, ct);
            _sharingVersion = ":sharing:" + _access.Fingerprint;
        }
        catch (Exception) when (!ct.IsCancellationRequested) { IsContentComplete = false; throw; }
    }
    public async IAsyncEnumerable<IRemoteFile> GetSupplementalFilesAsync([EnumeratorCancellation] CancellationToken ct)
    {
        if (IsDeleted || IsDirectory) yield break;
        Exception? fieldFailure = null;
        Microsoft365ContentFile? fieldFile = null;
        if (_coverage.ScanLibraryFields)
        {
            try
            {
                using var fields = await _client.ReadJsonAsync(SharePointRestClient.Api(_siteUrl, Resource + "/ListItemAllFields"), ct);
                fieldFile = Microsoft365ContentFile.Text(Id + ":fields", Name + ".fields.json", WebUrl + "#sift-fields",
                    SearchableText(fields.RootElement), IsContentComplete, Exposure, Owner, AclEntries);
            }
            catch (Exception ex) when (!(ex is OperationCanceledException && ct.IsCancellationRequested)) { fieldFailure = ex; }
            if (fieldFile != null) yield return fieldFile;
        }
        if (_coverage.ScanVersions)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            await foreach (var version in _client.EnumerateJsonAsync(SharePointRestClient.Api(_siteUrl, Resource + "/Versions?$top=200"), ct))
            {
                var id = String(version, "ID") ?? String(version, "Id") ?? String(version, "VersionLabel")
                    ?? throw new InvalidDataException("Historical file has no version ID.");
                if (!seen.Add(id)) continue;
                if (seen.Count > _coverage.MaxVersionsPerFile) throw new InvalidDataException("File history exceeds MaxVersionsPerFile.");
                var url = String(version, "Url") ?? throw new InvalidDataException("Historical file has no content URL.");
                var size = long.TryParse(String(version, "Size"), out var bytes) ? bytes : (long?)null;
                yield return new Microsoft365ContentFile(Id + ":version:" + id, Name, WebUrl + "#sift-version=" + Uri.EscapeDataString(id),
                    "version:" + id + _sharingVersion + (ConvertContent ? Microsoft365ContentProjection.VersionSuffix : ""), ConvertContent ? null : size, async (range, token) =>
                    {
                        if (!ConvertContent) return await _client.OpenHistoricalContentAsync(_siteUrl, url, range, token);
                        var target = await ProjectionTarget(token);
                        return await Microsoft365ContentProjection.Open(_coverage.GraphClient, target.Drive, target.Item, token, String(version, "VersionLabel") ?? id);
                    }, IsContentComplete, Exposure, Owner, AclEntries)
                    { ContentName = ContentName };
            }
        }
        if (fieldFailure != null) throw new InvalidDataException("Library field values could not be read.", fieldFailure);
    }
}
