using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Azure;
using Azure.Core;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class SharePointRestClient
{
    internal const string SharePointOnlineManagementShellClientId = "9bc3ab49-b65d-410a-85ad-de819febfddc";

    private const int DefaultMaxRetryCount = 10;
    private const int ListChangeRowLimit = 2000;
    private static readonly TimeSpan DefaultRetriesTimeLimit = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan TokenRefreshSkew = TimeSpan.FromMinutes(5);

    private readonly TokenCredential _credential;
    private readonly HttpClient _httpClient;
    private readonly ILogger? _logger;
    private readonly ThrottleNotificationHub? _throttleNotifications;
    private readonly string _productPrefix;
    private readonly ConcurrentDictionary<string, AccessToken> _tokenCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly RequestThrottleGate _throttleGate = new();

    internal SharePointRestClient(
        TokenCredential credential,
        string productPrefix,
        HttpClient httpClient,
        ILogger? logger = null,
        ThrottleNotificationHub? throttleNotifications = null)
    {
        _credential = credential;
        _productPrefix = productPrefix;
        _httpClient = httpClient;
        _logger = logger;
        _throttleNotifications = throttleNotifications;
    }

    internal static SharePointRestClient Create(
        TokenCredential credential,
        string productPrefix,
        ILogger? logger = null,
        ThrottleNotificationHub? throttleNotifications = null,
        HttpMessageHandler? finalHandler = null)
    {
        var httpClient = new HttpClient(finalHandler ?? new HttpClientHandler())
        {
            Timeout = DefaultTimeout
        };

        return new SharePointRestClient(credential, productPrefix, httpClient, logger, throttleNotifications);
    }

    internal static Uri NormalizeRootUrl(Uri uri)
    {
        return new Uri(uri.GetLeftPart(UriPartial.Authority).TrimEnd('/') + "/");
    }

    internal async Task<IReadOnlyList<RestSite>> SearchAccessibleSitesAsync(Uri sharePointRootUrl, CancellationToken cancellationToken)
    {
        var rootUrl = NormalizeRootUrl(sharePointRootUrl);
        const int rowLimit = 500;
        var startRow = 0;
        var sites = new List<RestSite>();
        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (true)
        {
            var uri = BuildSearchQueryUri(rootUrl, startRow, rowLimit);
            using var document = await GetJsonDocumentAsync(uri, cancellationToken);
            var rows = ExtractSearchRows(document.RootElement).ToList();
            if (rows.Count == 0)
            {
                break;
            }

            foreach (var row in rows)
            {
                var siteUrlValue = row.TryGetValue("Path", out var pathValue) ? pathValue : null;
                siteUrlValue ??= row.TryGetValue("SPWebUrl", out var webUrlValue) ? webUrlValue : null;
                siteUrlValue ??= row.TryGetValue("SPSiteUrl", out var siteCollectionValue) ? siteCollectionValue : null;
                if (!Uri.TryCreate(siteUrlValue, UriKind.Absolute, out var siteUri))
                {
                    continue;
                }

                if (siteUri.AbsolutePath.StartsWith("/contentstorage/", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var normalizedUrl = siteUri.AbsoluteUri.TrimEnd('/');
                if (!seenUrls.Add(normalizedUrl))
                {
                    continue;
                }

                var title = row.TryGetValue("Title", out var titleValue) && !string.IsNullOrWhiteSpace(titleValue)
                    ? titleValue
                    : siteUri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? siteUri.Host;

                sites.Add(new RestSite(title, new Uri(normalizedUrl)));
            }

            if (rows.Count < rowLimit)
            {
                break;
            }

            startRow += rowLimit;
        }

        return sites;
    }

    internal async Task<IReadOnlyList<Uri>> GetFollowedLocationUrlsAsync(Uri sharePointRootUrl, CancellationToken cancellationToken)
    {
        var rootUrl = NormalizeRootUrl(sharePointRootUrl);
        var requestUri = new Uri(rootUrl.AbsoluteUri.TrimEnd('/') + "/_api/social.following/my/followed(types=6)");
        using var document = await GetJsonDocumentAsync(requestUri, cancellationToken);
        var locations = new List<Uri>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var actors = EnumerateCollection(document.RootElement, "Followed")
            .Concat(EnumerateCollection(document.RootElement, "d", "Followed"))
            .Concat(EnumerateCollection(document.RootElement, "value"));

        foreach (var actor in actors)
        {
            var value = TryGetStringProperty(actor, "ContentUri")
                ?? TryGetStringProperty(actor, "FollowedContentUri")
                ?? TryGetStringProperty(actor, "Uri");
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
                || !uri.Host.Equals(rootUrl.Host, StringComparison.OrdinalIgnoreCase)
                || !seen.Add(uri.AbsoluteUri))
            {
                continue;
            }

            locations.Add(uri);
        }

        return locations;
    }

    internal async Task<RestSite?> TryResolveSiteAsync(Uri targetUri, CancellationToken cancellationToken)
    {
        var rootUrl = NormalizeRootUrl(targetUri);
        foreach (var candidatePath in EnumerateCandidateSitePaths(targetUri.AbsolutePath))
        {
            var requestUri = BuildSiteMetadataUri(rootUrl, candidatePath);
            using var response = await SendAsync(
                HttpMethod.Get,
                requestUri,
                jsonBody: null,
                acceptHeader: "application/json;odata=nometadata",
                rangeHeader: null,
                cancellationToken: cancellationToken);

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                continue;
            }

            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

            if (!(TryGetNestedProperty(document.RootElement, out var urlElement, "Url")
                  || TryGetNestedProperty(document.RootElement, out urlElement, "d", "Url"))
                || urlElement.ValueKind != JsonValueKind.String
                || !Uri.TryCreate(urlElement.GetString(), UriKind.Absolute, out var resolvedSiteUrl))
            {
                continue;
            }

            var title = (TryGetNestedProperty(document.RootElement, out var titleElement, "Title")
                || TryGetNestedProperty(document.RootElement, out titleElement, "d", "Title"))
                && titleElement.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(titleElement.GetString())
                    ? titleElement.GetString()!
                    : resolvedSiteUrl.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? resolvedSiteUrl.Host;

            return new RestSite(title, new Uri(resolvedSiteUrl.AbsoluteUri.TrimEnd('/')));
        }

        return null;
    }

    internal async Task<IReadOnlyList<RestLibrary>> GetLibrariesAsync(RestSite site, CancellationToken cancellationToken)
    {
        var requestUri = new Uri(
            site.Url.AbsoluteUri.TrimEnd('/') +
            "/_api/web/lists?$select=Id,Title,Hidden,BaseTemplate,ItemCount,RootFolder/ServerRelativeUrl,RootFolder/Name&$expand=RootFolder&$filter=BaseTemplate eq 101 and Hidden eq false");

        using var document = await GetJsonDocumentAsync(requestUri, cancellationToken);
        var libraries = new List<RestLibrary>();
        foreach (var element in EnumerateCollection(document.RootElement, "value")
                     .Concat(EnumerateCollection(document.RootElement, "d", "results")))
        {
            var listId = TryGetStringProperty(element, "Id");
            var title = TryGetStringProperty(element, "Title");
            var rootFolder = TryGetNestedStringProperty(element, "RootFolder", "ServerRelativeUrl");
            if (string.IsNullOrWhiteSpace(listId) || string.IsNullOrWhiteSpace(title) || string.IsNullOrWhiteSpace(rootFolder))
            {
                continue;
            }

            var webUrl = new Uri(NormalizeRootUrl(site.Url), rootFolder);
            libraries.Add(new RestLibrary(
                NormalizeGuid(listId),
                    title,
                    site,
                    rootFolder,
                    webUrl,
                    DetermineDriveType(webUrl.AbsoluteUri),
                    TryGetInt32Property(element, "ItemCount")));
        }

        return libraries;
    }

    internal async Task<RestChangeSet> GetListItemChangesAsync(RestLibrary library, string? changeToken, string? pagingToken, CancellationToken cancellationToken)
    {
        var requestUri = new Uri(
            library.Site.Url.AbsoluteUri.TrimEnd('/') +
            $"/_api/web/lists('{NormalizeGuid(library.Id)}')/GetListItemChangesSinceToken");

        var payload = BuildListItemChangesPayload(library, changeToken, pagingToken);
        using var response = await SendAsync(
            HttpMethod.Post,
            requestUri,
            payload,
            "application/xml",
            rangeHeader: null,
            cancellationToken);

        await EnsureSuccessStatusCodeWithBodyAsync(response, cancellationToken);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var document = await XDocument.LoadAsync(stream, LoadOptions.None, cancellationToken);
        var items = ParseChangedItems(document, library);
        var changesElement = document.Descendants().FirstOrDefault(element => element.Name.LocalName.Equals("Changes", StringComparison.OrdinalIgnoreCase));
        var dataElement = document.Descendants().FirstOrDefault(element => element.Name.LocalName.Equals("data", StringComparison.OrdinalIgnoreCase));

        var lastChangeToken = changesElement?.Attribute("LastChangeToken")?.Value;
        var pagingValue = dataElement?.Attribute("ListItemCollectionPositionNext")?.Value;
        var moreChanges = string.Equals(changesElement?.Attribute("MoreChanges")?.Value, "TRUE", StringComparison.OrdinalIgnoreCase);

        return new RestChangeSet(items, lastChangeToken, pagingValue, moreChanges);
    }

    internal async Task<IReadOnlyList<RestFileItem>> EnumerateLibraryFilesAsync(RestLibrary library, CancellationToken cancellationToken)
    {
        var items = new List<RestFileItem>();
        await ProcessLibraryFilesAsync(
            library,
            item =>
            {
                items.Add(item);
                return Task.CompletedTask;
            },
            cancellationToken);

        return items;
    }

    internal async Task ProcessLibraryFilesAsync(
        RestLibrary library,
        Func<RestFileItem, Task> onFile,
        CancellationToken cancellationToken)
    {
        var visitedFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await EnumerateFolderFilesAsync(library, library.RootFolderServerRelativeUrl, onFile, visitedFolders, cancellationToken);
    }

    internal async Task<Stream?> OpenFileContentAsync(
        Uri siteUrl,
        string serverRelativeUrl,
        string? rangeHeader,
        CancellationToken cancellationToken)
    {
        var requestUri = BuildFileContentUri(siteUrl, serverRelativeUrl);
        var response = await SendAsync(
            HttpMethod.Get,
            requestUri,
            jsonBody: null,
            acceptHeader: null,
            rangeHeader: rangeHeader,
            cancellationToken: cancellationToken,
            completionOption: HttpCompletionOption.ResponseHeadersRead);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            response.Dispose();
            return null;
        }

        await EnsureSuccessStatusCodeWithBodyAsync(response, cancellationToken);
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return new ResponseLifetimeStream(stream, response);
    }

    private async Task<JsonDocument> GetJsonDocumentAsync(Uri requestUri, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(
            HttpMethod.Get,
            requestUri,
            jsonBody: null,
            acceptHeader: "application/json;odata=nometadata",
            rangeHeader: null,
            cancellationToken);

        await EnsureSuccessStatusCodeWithBodyAsync(response, cancellationToken);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
    }

    private async Task<JsonDocument?> TryGetJsonDocumentAsync(Uri requestUri, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(
            HttpMethod.Get,
            requestUri,
            jsonBody: null,
            acceptHeader: "application/json;odata=nometadata",
            rangeHeader: null,
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        await EnsureSuccessStatusCodeWithBodyAsync(response, cancellationToken);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        Uri requestUri,
        string? jsonBody,
        string? acceptHeader,
        string? rangeHeader,
        CancellationToken cancellationToken,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead)
    {
        var startTime = DateTimeOffset.UtcNow;

        for (var attempt = 0; ; attempt++)
        {
            await _throttleGate.WaitAsync(cancellationToken);

            using var request = new HttpRequestMessage(method, requestUri);
            if (!string.IsNullOrWhiteSpace(acceptHeader))
            {
                request.Headers.TryAddWithoutValidation("Accept", acceptHeader);
            }

            if (!string.IsNullOrWhiteSpace(rangeHeader))
            {
                request.Headers.TryAddWithoutValidation("Range", rangeHeader);
            }

            request.Headers.UserAgent.ParseAdd(_productPrefix);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await GetAccessTokenAsync(requestUri, cancellationToken));

            if (jsonBody != null)
            {
                request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            }

            HttpResponseMessage response;
            try
            {
                response = await _httpClient.SendAsync(request, completionOption, cancellationToken);
            }
            catch (Exception ex) when (IsRetryableTransportFailure(ex, cancellationToken)
                                       && attempt < DefaultMaxRetryCount
                                       && DateTimeOffset.UtcNow - startTime < DefaultRetriesTimeLimit)
            {
                await Task.Delay(GetRetryDelay(attempt, null), cancellationToken);
                continue;
            }

            if (!ShouldRetry(response.StatusCode)
                || attempt >= DefaultMaxRetryCount
                || DateTimeOffset.UtcNow - startTime >= DefaultRetriesTimeLimit)
            {
                return response;
            }

            var retryDelay = GetRetryDelay(attempt, response.Headers.RetryAfter?.Delta);
            var gateDelay = _throttleGate.Observe(response, retryDelay);
            _throttleNotifications?.Report("SharePoint", response.StatusCode, retryDelay, gateDelay, requestUri.Authority);

            _logger?.LogDebug(
                "Retrying SharePoint REST request {Method} {Uri} after HTTP {StatusCode} (attempt {Attempt}).",
                method,
                requestUri,
                (int)response.StatusCode,
                attempt + 1);

            response.Dispose();
            await Task.Delay(retryDelay, cancellationToken);
        }
    }

    private async Task<string> GetAccessTokenAsync(Uri requestUri, CancellationToken cancellationToken)
    {
        var scope = $"{requestUri.Scheme}://{requestUri.Authority}/.default";
        if (_tokenCache.TryGetValue(scope, out var cachedToken)
            && cachedToken.ExpiresOn > DateTimeOffset.UtcNow.Add(TokenRefreshSkew))
        {
            return cachedToken.Token;
        }

        var accessToken = await _credential.GetTokenAsync(new TokenRequestContext([scope]), cancellationToken);
        _tokenCache[scope] = accessToken;
        return accessToken.Token;
    }

    private static Uri BuildSearchQueryUri(Uri rootUrl, int startRow, int rowLimit)
    {
        var queryText = Uri.EscapeDataString("'(contentclass:STS_Site OR contentclass:STS_Web)'");
        var selectProperties = Uri.EscapeDataString("'Title,Path,SPWebUrl,SPSiteUrl,SiteName'");
        return new Uri(
            rootUrl.AbsoluteUri.TrimEnd('/') +
            $"/_api/search/query?querytext={queryText}&trimduplicates=false&rowlimit={rowLimit}&startrow={startRow}&selectproperties={selectProperties}");
    }

    private static Uri BuildSiteMetadataUri(Uri rootUrl, string candidatePath)
    {
        if (candidatePath == "/")
        {
            return new Uri(rootUrl.AbsoluteUri.TrimEnd('/') + "/_api/web?$select=Title,Url");
        }

        return new Uri(rootUrl, candidatePath.TrimStart('/').TrimEnd('/') + "/_api/web?$select=Title,Url");
    }

    private static Uri BuildFileContentUri(Uri siteUrl, string serverRelativeUrl)
    {
        var escapedServerRelativeUrl = EscapeODataStringLiteral(serverRelativeUrl);

        return new Uri(
            siteUrl.AbsoluteUri.TrimEnd('/') +
            $"/_api/web/GetFileByServerRelativeUrl('{escapedServerRelativeUrl}')/$value");
    }

    private static Uri BuildFolderFilesUri(Uri siteUrl, string serverRelativeUrl)
    {
        var escapedServerRelativeUrl = EscapeODataStringLiteral(serverRelativeUrl);
        return new Uri(
            siteUrl.AbsoluteUri.TrimEnd('/') +
            $"/_api/web/GetFolderByServerRelativeUrl('{escapedServerRelativeUrl}')/Files?$select=Name,ServerRelativeUrl,UniqueId,Length");
    }

    private static Uri BuildFolderFoldersUri(Uri siteUrl, string serverRelativeUrl)
    {
        var escapedServerRelativeUrl = EscapeODataStringLiteral(serverRelativeUrl);
        return new Uri(
            siteUrl.AbsoluteUri.TrimEnd('/') +
            $"/_api/web/GetFolderByServerRelativeUrl('{escapedServerRelativeUrl}')/Folders?$select=Name,ServerRelativeUrl");
    }

    private static string BuildListItemChangesPayload(RestLibrary library, string? changeToken, string? pagingToken)
    {
        var queryOptions = new StringBuilder();
        queryOptions.Append("<QueryOptions><ViewAttributes Scope=\"RecursiveAll\" /><IncludeMandatoryColumns>FALSE</IncludeMandatoryColumns><DateInUtc>TRUE</DateInUtc><IncludePermissions>FALSE</IncludePermissions><IncludeAttachmentUrls>FALSE</IncludeAttachmentUrls>");
        queryOptions.Append("<Folder>");
        queryOptions.Append(SecurityElement.Escape(library.RootFolderServerRelativeUrl));
        queryOptions.Append("</Folder>");
        if (!string.IsNullOrWhiteSpace(pagingToken))
        {
            queryOptions.Append("<Paging ListItemCollectionPositionNext=\"");
            queryOptions.Append(SecurityElement.Escape(pagingToken));
            queryOptions.Append("\" />");
        }

        queryOptions.Append("</QueryOptions>");

        var query = new System.Text.Json.Nodes.JsonObject
        {
            ["ViewName"] = string.Empty,
            ["Query"] = "<Query />",
            ["QueryOptions"] = queryOptions.ToString(),
            ["RowLimit"] = ListChangeRowLimit.ToString(),
            ["Contains"] = "<Contains />",
            ["ViewFields"] = "<ViewFields><FieldRef Name=\"UniqueId\" /><FieldRef Name=\"FileRef\" /><FieldRef Name=\"FileLeafRef\" /><FieldRef Name=\"FSObjType\" /><FieldRef Name=\"File_x0020_Size\" /><FieldRef Name=\"HTML_x0020_File_x0020_Type\" /></ViewFields>"
        };

        query["ChangeToken"] = string.IsNullOrWhiteSpace(changeToken) ? null : changeToken;

        return new System.Text.Json.Nodes.JsonObject
        {
            ["query"] = query
        }.ToJsonString();
    }

    private async Task EnumerateFolderFilesAsync(
        RestLibrary library,
        string folderServerRelativeUrl,
        Func<RestFileItem, Task> onFile,
        HashSet<string> visitedFolders,
        CancellationToken cancellationToken)
    {
        if (!visitedFolders.Add(folderServerRelativeUrl))
        {
            return;
        }

        using (var filesDocument = await TryGetJsonDocumentAsync(BuildFolderFilesUri(library.Site.Url, folderServerRelativeUrl), cancellationToken))
        {
            if (filesDocument == null)
            {
                return;
            }

            foreach (var element in EnumerateCollection(filesDocument.RootElement, "value")
                         .Concat(EnumerateCollection(filesDocument.RootElement, "d", "results")))
            {
                var serverRelativeUrl = TryGetStringProperty(element, "ServerRelativeUrl");
                var name = TryGetStringProperty(element, "Name");
                if (string.IsNullOrWhiteSpace(serverRelativeUrl) || string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                var id = TryGetStringProperty(element, "UniqueId") ?? name;
                var lengthValue = TryGetStringProperty(element, "Length");
                long? size = long.TryParse(lengthValue, out var parsedSize) ? parsedSize : null;
                var webUrl = new Uri(NormalizeRootUrl(library.Site.Url), serverRelativeUrl);

                await onFile(new RestFileItem(
                    id,
                    name,
                    serverRelativeUrl,
                    webUrl,
                    false,
                    false,
                    size));
            }
        }

        using var foldersDocument = await TryGetJsonDocumentAsync(BuildFolderFoldersUri(library.Site.Url, folderServerRelativeUrl), cancellationToken);
        if (foldersDocument == null)
        {
            return;
        }

        foreach (var element in EnumerateCollection(foldersDocument.RootElement, "value")
                     .Concat(EnumerateCollection(foldersDocument.RootElement, "d", "results")))
        {
            var childFolderUrl = TryGetStringProperty(element, "ServerRelativeUrl");
            if (string.IsNullOrWhiteSpace(childFolderUrl)
                || childFolderUrl.Equals(folderServerRelativeUrl, StringComparison.OrdinalIgnoreCase)
                || childFolderUrl.Contains("/Forms", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            await EnumerateFolderFilesAsync(library, childFolderUrl, onFile, visitedFolders, cancellationToken);
        }
    }

    private static async Task EnsureSuccessStatusCodeWithBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        string? body = null;
        try
        {
            body = await response.Content.ReadAsStringAsync(cancellationToken);
        }
        catch
        {
            // Best-effort diagnostics only.
        }

        if (!string.IsNullOrWhiteSpace(body))
        {
            var trimmedBody = body.Length > 512 ? body[..512] + "..." : body;
            throw new HttpRequestException(
                $"Response status code does not indicate success: {(int)response.StatusCode} ({response.ReasonPhrase}). Body: {trimmedBody}",
                null,
                response.StatusCode);
        }

        throw new HttpRequestException(
            $"Response status code does not indicate success: {(int)response.StatusCode} ({response.ReasonPhrase}).",
            null,
            response.StatusCode);
    }

    private static string EscapeODataStringLiteral(string value)
    {
        return Uri.EscapeDataString(value.Replace("'", "''"))
            .Replace("%2F", "/", StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<RestFileItem> ParseChangedItems(XDocument document, RestLibrary library)
    {
        var items = new List<RestFileItem>();
        foreach (var row in document.Descendants().Where(element => element.Name.LocalName.Equals("row", StringComparison.OrdinalIgnoreCase)))
        {
            var serverRelativeUrl = GetAttributeValue(row, "FileRef");
            serverRelativeUrl = ExtractLookupValue(serverRelativeUrl);
            if (string.IsNullOrWhiteSpace(serverRelativeUrl)
                || !serverRelativeUrl.StartsWith(library.RootFolderServerRelativeUrl, StringComparison.OrdinalIgnoreCase)
                || serverRelativeUrl.Equals(library.RootFolderServerRelativeUrl, StringComparison.OrdinalIgnoreCase)
                || serverRelativeUrl.Contains("/Forms/", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var name = ExtractLookupValue(GetAttributeValue(row, "FileLeafRef"));
            if (string.IsNullOrWhiteSpace(name))
            {
                name = serverRelativeUrl.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault() ?? serverRelativeUrl;
            }

            var id = ExtractLookupValue(GetAttributeValue(row, "UniqueId"))
                ?? ExtractLookupValue(GetAttributeValue(row, "ID"))
                ?? name;
            var fsObjType = ExtractLookupValue(GetAttributeValue(row, "FSObjType"));
            var isDirectory = string.Equals(fsObjType, "1", StringComparison.OrdinalIgnoreCase);
            var sizeValue = ExtractLookupValue(GetAttributeValue(row, "File_x0020_Size"));
            long? size = long.TryParse(sizeValue, out var parsedSize) ? parsedSize : null;
            var webUrl = new Uri(NormalizeRootUrl(library.Site.Url), serverRelativeUrl);

            items.Add(new RestFileItem(
                id,
                name,
                serverRelativeUrl,
                webUrl,
                isDirectory,
                false,
                size));
        }

        return items;
    }

    private static IEnumerable<Dictionary<string, string>> ExtractSearchRows(JsonElement root)
    {
        var rows = EnumerateCollection(root, "PrimaryQueryResult", "RelevantResults", "Table", "Rows")
            .Concat(EnumerateCollection(root, "d", "query", "PrimaryQueryResult", "RelevantResults", "Table", "Rows"));

        foreach (var row in rows)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var cell in EnumerateCollection(row, "Cells"))
            {
                var key = TryGetStringProperty(cell, "Key");
                var value = TryGetStringProperty(cell, "Value");
                if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                values[key] = value;
            }

            if (values.Count > 0)
            {
                yield return values;
            }
        }
    }

    private static IEnumerable<JsonElement> EnumerateCollection(JsonElement element, params string[] path)
    {
        if (!TryGetNestedProperty(element, out var target, path))
        {
            yield break;
        }

        if (target.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in target.EnumerateArray())
            {
                yield return item;
            }

            yield break;
        }

        if (target.ValueKind == JsonValueKind.Object
            && TryGetProperty(target, "results", out var resultsElement)
            && resultsElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in resultsElement.EnumerateArray())
            {
                yield return item;
            }
        }
    }

    private static bool TryGetNestedProperty(JsonElement element, out JsonElement value, params string[] path)
    {
        value = element;
        foreach (var segment in path)
        {
            if (value.ValueKind != JsonValueKind.Object || !TryGetProperty(value, segment, out value))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryGetProperty(JsonElement element, string propertyName, out JsonElement value)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (property.NameEquals(propertyName) || property.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    private static string? TryGetStringProperty(JsonElement element, string propertyName)
    {
        return TryGetProperty(element, propertyName, out var valueElement) && valueElement.ValueKind == JsonValueKind.String
            ? valueElement.GetString()
            : null;
    }

    private static string? TryGetNestedStringProperty(JsonElement element, params string[] path)
    {
        return TryGetNestedProperty(element, out var valueElement, path) && valueElement.ValueKind == JsonValueKind.String
            ? valueElement.GetString()
            : null;
    }

    private static IEnumerable<string> EnumerateCandidateSitePaths(string absolutePath)
    {
        var trimmedPath = absolutePath.Trim('/');
        if (string.IsNullOrWhiteSpace(trimmedPath))
        {
            yield return "/";
            yield break;
        }

        var segments = trimmedPath.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (var length = segments.Length; length >= 1; length--)
        {
            yield return "/" + string.Join('/', segments.Take(length));
        }
    }

    private static string NormalizeGuid(string value)
    {
        return value.Trim().Trim('{', '}');
    }

    private static string? GetAttributeValue(XElement element, string logicalName)
    {
        foreach (var attribute in element.Attributes())
        {
            if (attribute.Name.LocalName.Equals(logicalName, StringComparison.OrdinalIgnoreCase)
                || attribute.Name.ToString().Equals(logicalName, StringComparison.OrdinalIgnoreCase)
                || attribute.Name.ToString().EndsWith("_" + logicalName, StringComparison.OrdinalIgnoreCase))
            {
                return attribute.Value;
            }
        }

        return null;
    }

    private static int? TryGetInt32Property(JsonElement element, string propertyName)
    {
        if (!TryGetNestedProperty(element, out var propertyValue, propertyName))
        {
            return null;
        }

        return propertyValue.ValueKind switch
        {
            JsonValueKind.Number when propertyValue.TryGetInt32(out var value) => value,
            JsonValueKind.String when int.TryParse(propertyValue.GetString(), out var value) => value,
            _ => null
        };
    }

    private static string? ExtractLookupValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var separatorIndex = value.IndexOf(";#", StringComparison.Ordinal);
        return separatorIndex >= 0 ? value[(separatorIndex + 2)..] : value;
    }

    private static DatastoreType DetermineDriveType(string webUrl)
    {
        if (webUrl.Contains("-my.sharepoint.com", StringComparison.OrdinalIgnoreCase)
            || webUrl.Contains("/personal/", StringComparison.OrdinalIgnoreCase))
        {
            return DatastoreType.OneDrive;
        }

        if (webUrl.Contains("/teams/", StringComparison.OrdinalIgnoreCase))
        {
            return DatastoreType.Teams;
        }

        return DatastoreType.SharePoint;
    }

    private static bool ShouldRetry(HttpStatusCode statusCode)
    {
        return RequestThrottleGate.ShouldThrottle(statusCode);
    }

    private static bool IsRetryableTransportFailure(Exception exception, CancellationToken cancellationToken)
    {
        if (exception is OperationCanceledException && cancellationToken.IsCancellationRequested)
        {
            return false;
        }

        return exception is HttpRequestException httpRequestException && !httpRequestException.StatusCode.HasValue
            || exception is TimeoutException
            || exception is TaskCanceledException;
    }

    private static TimeSpan GetRetryDelay(int attempt, TimeSpan? retryAfter)
    {
        if (retryAfter.HasValue && retryAfter.Value > TimeSpan.Zero)
        {
            return retryAfter.Value;
        }

        var seconds = Math.Min(10, Math.Pow(2, attempt));
        return TimeSpan.FromSeconds(seconds);
    }

    internal sealed record RestSite(string Title, Uri Url);

    internal sealed record RestLibrary(
        string Id,
        string Title,
        RestSite Site,
        string RootFolderServerRelativeUrl,
        Uri WebUrl,
        DatastoreType DriveType,
        int? ItemCount);

    internal sealed record RestFileItem(
        string Id,
        string Name,
        string ServerRelativeUrl,
        Uri WebUrl,
        bool IsDirectory,
        bool IsDeleted,
        long? Size);

    internal sealed record RestChangeSet(
        IReadOnlyList<RestFileItem> Items,
        string? LastChangeToken,
        string? PagingToken,
        bool MoreChanges);

    private sealed class ResponseLifetimeStream : Stream
    {
        private readonly Stream _innerStream;
        private readonly HttpResponseMessage _response;

        public ResponseLifetimeStream(Stream innerStream, HttpResponseMessage response)
        {
            _innerStream = innerStream;
            _response = response;
        }

        public override bool CanRead => _innerStream.CanRead;
        public override bool CanSeek => _innerStream.CanSeek;
        public override bool CanWrite => _innerStream.CanWrite;
        public override long Length => _innerStream.Length;
        public override long Position
        {
            get => _innerStream.Position;
            set => _innerStream.Position = value;
        }

        public override void Flush() => _innerStream.Flush();
        public override int Read(byte[] buffer, int offset, int count) => _innerStream.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => _innerStream.Seek(offset, origin);
        public override void SetLength(long value) => _innerStream.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => _innerStream.Write(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => _innerStream.ReadAsync(buffer, cancellationToken);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => _innerStream.ReadAsync(buffer, offset, count, cancellationToken);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask DisposeAsync()
        {
            _response.Dispose();
            return _innerStream.DisposeAsync();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _innerStream.Dispose();
                _response.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
