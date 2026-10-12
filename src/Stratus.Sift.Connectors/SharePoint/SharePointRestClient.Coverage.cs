using System.Runtime.CompilerServices;
using System.Text.Json;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed partial class SharePointRestClient
{
    internal async IAsyncEnumerable<(Uri Site, RestFileItem File)> SearchAccessibleFilesAsync(Uri root,
        [EnumeratorCancellation] CancellationToken ct)
    {
        const int limit = 500;
        long cursor = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var failures = 0;
        for (var page = 0; page < Microsoft365CoverageOptions.MaxPages; page++)
        {
            var query = Uri.EscapeDataString($"'IndexDocId>{cursor} AND IsDocument:1'");
            var properties = Uri.EscapeDataString("'Path,SPWebUrl,DocId'");
            using var document = await GetJsonDocumentAsync(Api(root,
                $"search/query?querytext={query}&rowlimit={limit}&trimduplicates=false&selectproperties={properties}&sortlist='[docid]:ascending'"), ct);
            var rows = ExtractSearchRows(document.RootElement).ToList();
            foreach (var row in rows)
            {
                if (seen.Count >= 1_000_000) throw new InvalidDataException("Accessible-file search exceeded its item limit.");
                if (!long.TryParse(row.GetValueOrDefault("DocId"), out var id) || id <= cursor)
                    throw new InvalidDataException("Accessible-file search returned a non-advancing document cursor.");
                cursor = id;
                (Uri Site, RestFileItem File)? result = null;
                try
                {
                    var site = new Uri(row.GetValueOrDefault("SPWebUrl") ?? throw new InvalidDataException("Search file has no site URL."));
                    var fileUrl = new Uri(row.GetValueOrDefault("Path") ?? throw new InvalidDataException("Search file has no URL."));
                    if (site.Scheme != Uri.UriSchemeHttps || !Microsoft365Cloud.IsSharePointHost(site.Host)
                        || fileUrl.Authority != site.Authority) throw new InvalidDataException("Search file changed service origin.");
                    var decoded = Uri.UnescapeDataString(fileUrl.AbsolutePath);
                    if (!seen.Add(fileUrl.AbsoluteUri)) continue;
                    if (seen.Count > 1_000_000) throw new InvalidDataException("Accessible-file search exceeded its item limit.");
                    using var metadata = await GetJsonDocumentAsync(Api(site,
                        $"web/GetFileByServerRelativePath(decodedurl='{ResourcePath(decoded)}')?$select=Name,ServerRelativeUrl,UniqueId,Length,ETag,TimeLastModified"), ct);
                    var value = metadata.RootElement;
                    if (value.TryGetProperty("d", out var wrapped)) value = wrapped;
                    var name = String(value, "Name") ?? throw new InvalidDataException("Search file has no authoritative filename.");
                    var identity = String(value, "UniqueId") ?? throw new InvalidDataException("Search file has no stable identity.");
                    var size = long.TryParse(String(value, "Length"), out var bytes) ? bytes : (long?)null;
                    var version = String(value, "ETag") ?? String(value, "TimeLastModified");
                    result = (site, new(identity, name, decoded, BuildWebUrl(site, decoded), false, false, size, version));
                }
                catch (Exception ex) when (!(ex is OperationCanceledException && ct.IsCancellationRequested)) { failures++; }
                if (result.HasValue) yield return result.Value;
            }
            if (rows.Count < limit)
            {
                if (failures > 0) throw new InvalidDataException($"{failures} indexed files could not be resolved.");
                yield break;
            }
        }
        throw new InvalidDataException("Accessible-file search exceeded its page limit.");
    }
    internal async IAsyncEnumerable<JsonElement> EnumerateJsonAsync(Uri uri,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var count = 0;
        await foreach (var item in EnumeratePagedCollectionAsync(uri, false, cancellationToken))
        {
            if (++count > 1_000_000) throw new InvalidDataException("SharePoint collection exceeds its item limit.");
            yield return item.Clone();
        }
    }

    internal Task<JsonDocument> ReadJsonAsync(Uri uri, CancellationToken cancellationToken)
        => GetJsonDocumentAsync(uri, cancellationToken);

    internal static Uri Api(Uri site, string path) => new(site.AbsoluteUri.TrimEnd('/') + "/_api/" + path);
    // Escape the OData string literal and HTTP parameter once. The existing
    // helper already encodes spaces, percent signs, and escaped apostrophes.
    internal static string ResourcePath(string decodedPath) => EscapeODataStringLiteral(decodedPath);

    internal async Task<Stream?> OpenHistoricalContentAsync(Uri site, string versionUrl, string? range, CancellationToken cancellationToken)
    {
        // FileVersion.Url can be web-relative, not just server-relative. '#' in a
        // returned filename must not be interpreted as a browser fragment.
        var url = new Uri(new Uri(site.AbsoluteUri.TrimEnd('/') + "/"), versionUrl.Replace("#", "%23", StringComparison.Ordinal));
        if (url.Scheme != site.Scheme || !url.Host.Equals(site.Host, StringComparison.OrdinalIgnoreCase) || url.Port != site.Port)
            throw new InvalidDataException("SharePoint historical content URL changed origin.");
        var response = await SendAsync(System.Net.Http.HttpMethod.Get, url, null, "application/octet-stream", range, cancellationToken,
            System.Net.Http.HttpCompletionOption.ResponseHeadersRead);
        try
        {
            await EnsureSuccessStatusCodeWithBodyAsync(response, cancellationToken);
            return new ResponseLifetimeStream(await response.Content.ReadAsStreamAsync(cancellationToken), response);
        }
        catch { response.Dispose(); throw; }
    }
}
