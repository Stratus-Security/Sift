using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
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

internal sealed partial class SharePointRestClient
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

    internal async Task<IReadOnlyList<RestSite>> SearchAccessibleSitesAsync(Uri sharePointRootUrl, CancellationToken cancellationToken,
        Action<RestSite>? onSiteDiscovered = null)
    {
        var rootUrl = NormalizeRootUrl(sharePointRootUrl);
        const int rowLimit = 500;
        long? lastDocId = null;
        var sites = new List<RestSite>();
        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (true)
        {
            var uri = BuildSearchQueryUri(rootUrl, lastDocId, rowLimit);
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

                var site = new RestSite(title, new Uri(normalizedUrl));
                sites.Add(site);
                onSiteDiscovered?.Invoke(site);
            }

            if (rows.Count < rowLimit)
            {
                break;
            }

            // Seek by the search index identity instead of StartRow, which is capped at 50,000.
            foreach (var row in rows)
            {
                if (!row.TryGetValue("DocId", out var value)
                    || !long.TryParse(value, System.Globalization.NumberStyles.None,
                        System.Globalization.CultureInfo.InvariantCulture, out var docId)
                    || (lastDocId.HasValue && docId <= lastDocId.Value))
                    throw new InvalidDataException("SharePoint search did not return increasing DocId values for continuation.");
                lastDocId = docId;
            }
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
            "/_api/web/lists?$select=Id,Title,Hidden,BaseType,BaseTemplate,ItemCount,RootFolder/ServerRelativeUrl,RootFolder/Name&$expand=RootFolder&$filter=BaseType eq 1");

        var libraries = new List<RestLibrary>();
        await foreach (var element in EnumeratePagedCollectionAsync(requestUri, false, cancellationToken))
        {
            // BaseType identifies every file-backed library, including pictures, forms,
            // pages, catalogs and custom templates. Generic lists remain a separate workload.
            if (TryGetInt32Property(element, "BaseType") is int baseType && baseType != 1) continue;
            var listId = TryGetStringProperty(element, "Id");
            var title = TryGetStringProperty(element, "Title");
            var rootFolder = TryGetNestedStringProperty(element, "RootFolder", "ServerRelativeUrl");
            if (string.IsNullOrWhiteSpace(listId) || string.IsNullOrWhiteSpace(title) || string.IsNullOrWhiteSpace(rootFolder))
            {
                continue;
            }

            var webUrl = BuildWebUrl(site.Url, rootFolder);
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

    private async IAsyncEnumerable<JsonElement> EnumeratePagedCollectionAsync(
        Uri initialUri,
        bool allowMissing,
        [EnumeratorCancellation] CancellationToken cancellationToken,
        Action? onMissing = null)
    {
        Uri? requestUri = initialUri;
        var visitedPages = new HashSet<string>(StringComparer.Ordinal);
        while (requestUri != null)
        {
            if (visitedPages.Count >= Microsoft365CoverageOptions.MaxPages || !visitedPages.Add(requestUri.AbsoluteUri))
            {
                throw new InvalidDataException("SharePoint returned a repeated collection continuation link.");
            }

            using var document = allowMissing
                ? await TryGetJsonDocumentAsync(requestUri, cancellationToken)
                : await GetJsonDocumentAsync(requestUri, cancellationToken);
            if (document == null)
            {
                if (visitedPages.Count > 1)
                {
                    throw new InvalidDataException("A SharePoint collection continuation page was unavailable.");
                }
                onMissing?.Invoke();
                yield break;
            }

            var root = document.RootElement;
            if (!(TryGetNestedProperty(root, out var collection, "value")
                  || TryGetNestedProperty(root, out collection, "d", "results"))
                || collection.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException("SharePoint collection response did not contain an array.");
            }

            foreach (var element in collection.EnumerateArray())
            {
                yield return element;
            }

            var nextLink = TryGetStringProperty(root, "@odata.nextLink")
                ?? TryGetStringProperty(root, "odata.nextLink")
                ?? TryGetNestedStringProperty(root, "d", "__next");
            if (string.IsNullOrWhiteSpace(nextLink))
            {
                yield break;
            }

            var nextUri = new Uri(requestUri, nextLink);
            if (nextUri.Scheme != initialUri.Scheme
                || !nextUri.Authority.Equals(initialUri.Authority, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("SharePoint returned a collection continuation link outside the requested host.");
            }
            requestUri = nextUri;
        }
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

            if (!ShouldRetry(response.StatusCode))
            {
                return response;
            }

            // Share the pause even when this request has exhausted its retry budget.
            var retryDelay = GetRetryDelay(attempt, RequestThrottleGate.GetRetryAfterDelay(response, DateTimeOffset.UtcNow));
            var gateDelay = _throttleGate.Observe(response, retryDelay);
            _throttleNotifications?.Report("SharePoint", response.StatusCode, retryDelay, gateDelay, requestUri.Authority);

            if (attempt >= DefaultMaxRetryCount
                || DateTimeOffset.UtcNow - startTime >= DefaultRetriesTimeLimit)
            {
                return response;
            }

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

    private static Uri BuildSearchQueryUri(Uri rootUrl, long? lastDocId, int rowLimit)
    {
        var restriction = lastDocId.HasValue ? $"IndexDocId>{lastDocId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)} AND " : string.Empty;
        var queryText = Uri.EscapeDataString($"'{restriction}(contentclass:STS_Site OR contentclass:STS_Web)'");
        var selectProperties = Uri.EscapeDataString("'Title,Path,SPWebUrl,SPSiteUrl,SiteName,DocId'");
        return new Uri(
            rootUrl.AbsoluteUri.TrimEnd('/') +
            $"/_api/search/query?querytext={queryText}&trimduplicates=false&rowlimit={rowLimit}&sortlist='docid:ascending'&selectproperties={selectProperties}");
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
            $"/_api/web/GetFileByServerRelativePath(decodedUrl='{escapedServerRelativeUrl}')/$value");
    }

    private static Uri BuildFolderFilesUri(Uri siteUrl, string serverRelativeUrl)
    {
        var escapedServerRelativeUrl = EscapeODataStringLiteral(serverRelativeUrl);
        return new Uri(
            siteUrl.AbsoluteUri.TrimEnd('/') +
            $"/_api/web/GetFolderByServerRelativePath(decodedUrl='{escapedServerRelativeUrl}')/Files?$select=Name,ServerRelativeUrl,UniqueId,Length,ETag,TimeLastModified");
    }

    private static Uri BuildFolderFoldersUri(Uri siteUrl, string serverRelativeUrl)
    {
        var escapedServerRelativeUrl = EscapeODataStringLiteral(serverRelativeUrl);
        return new Uri(
            siteUrl.AbsoluteUri.TrimEnd('/') +
            $"/_api/web/GetFolderByServerRelativePath(decodedUrl='{escapedServerRelativeUrl}')/Folders?$select=Name,ServerRelativeUrl");
    }

    internal static Uri BuildWebUrl(Uri siteUrl, string decodedServerRelativeUrl)
    {
        // ServerRelativeUrl is decoded; Uri otherwise interprets '#' as a fragment
        // and literal percent escapes as already encoded characters.
        var encodedPath = string.Join('/', decodedServerRelativeUrl.Split('/').Select(Uri.EscapeDataString));
        return new Uri(NormalizeRootUrl(siteUrl), encodedPath);
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
            ["ViewFields"] = "<ViewFields><FieldRef Name=\"UniqueId\" /><FieldRef Name=\"FileRef\" /><FieldRef Name=\"FileLeafRef\" /><FieldRef Name=\"FSObjType\" /><FieldRef Name=\"File_x0020_Size\" /><FieldRef Name=\"HTML_x0020_File_x0020_Type\" /><FieldRef Name=\"owshiddenversion\" /><FieldRef Name=\"Modified\" /></ViewFields>"
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

        var missingFolder = false;
        await foreach (var element in EnumeratePagedCollectionAsync(
                           BuildFolderFilesUri(library.Site.Url, folderServerRelativeUrl), true, cancellationToken,
                           () => missingFolder = true))
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
            var webUrl = BuildWebUrl(library.Site.Url, serverRelativeUrl);

            await onFile(new RestFileItem(
                id,
                name,
                serverRelativeUrl,
                webUrl,
                false,
                false,
                size,
                TryGetStringProperty(element, "ETag") ?? TryGetStringProperty(element, "TimeLastModified"),
                TryGetStringProperty(element, "TimeLastModified")));
        }

        if (missingFolder) return;

        await foreach (var element in EnumeratePagedCollectionAsync(
                           BuildFolderFoldersUri(library.Site.Url, folderServerRelativeUrl), true, cancellationToken))
        {
            var childFolderUrl = TryGetStringProperty(element, "ServerRelativeUrl");
            if (string.IsNullOrWhiteSpace(childFolderUrl)
                || childFolderUrl.Equals(folderServerRelativeUrl, StringComparison.OrdinalIgnoreCase)
                || IsSystemFormsPath(library, childFolderUrl))
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
            var detail = body;
            try
            {
                using var error = JsonDocument.Parse(body);
                // Decode the service message, including escaped field names, so
                // diagnostics and narrowly scoped schema fallbacks see the same text.
                detail = TryGetNestedStringProperty(error.RootElement, "odata.error", "message", "value")
                    ?? TryGetNestedStringProperty(error.RootElement, "error", "message", "value")
                    ?? TryGetNestedStringProperty(error.RootElement, "error", "message") ?? body;
            }
            catch (JsonException) { /* Non-JSON errors retain the bounded response body. */ }
            var trimmedBody = detail.Length > 512 ? detail[..512] + "..." : detail;
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

    private static bool IsSystemFormsPath(RestLibrary library, string serverRelativeUrl)
    {
        var formsRoot = library.RootFolderServerRelativeUrl.TrimEnd('/') + "/Forms";
        return serverRelativeUrl.TrimEnd('/').Equals(formsRoot, StringComparison.OrdinalIgnoreCase)
            || serverRelativeUrl.StartsWith(formsRoot + "/", StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<RestFileItem> ParseChangedItems(XDocument document, RestLibrary library)
    {
        var items = new List<RestFileItem>();
        foreach (var row in document.Descendants().Where(element => element.Name.LocalName.Equals("row", StringComparison.OrdinalIgnoreCase)))
        {
            var serverRelativeUrl = GetAttributeValue(row, "FileRef");
            serverRelativeUrl = ExtractLookupValue(serverRelativeUrl);
            // CAML rowsets commonly omit the leading slash in FileRef, unlike
            // the REST folder/file endpoints and the library root metadata.
            if (!string.IsNullOrWhiteSpace(serverRelativeUrl) && !serverRelativeUrl.StartsWith('/'))
                serverRelativeUrl = "/" + serverRelativeUrl;
            if (string.IsNullOrWhiteSpace(serverRelativeUrl)
                || !serverRelativeUrl.StartsWith(library.RootFolderServerRelativeUrl.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase)
                || IsSystemFormsPath(library, serverRelativeUrl))
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
            var webUrl = BuildWebUrl(library.Site.Url, serverRelativeUrl);

            items.Add(new RestFileItem(
                id,
                name,
                serverRelativeUrl,
                webUrl,
                isDirectory,
                false,
                size,
                ExtractLookupValue(GetAttributeValue(row, "owshiddenversion"))
                    ?? ExtractLookupValue(GetAttributeValue(row, "Modified")),
                ExtractLookupValue(GetAttributeValue(row, "Modified"))));
        }

        return items;
    }

    private static IEnumerable<Dictionary<string, string>> ExtractSearchRows(JsonElement root)
    {
        if (!(TryGetCollection(root, out var rows, "PrimaryQueryResult", "RelevantResults", "Table", "Rows")
              || TryGetCollection(root, out rows, "d", "query", "PrimaryQueryResult", "RelevantResults", "Table", "Rows")))
        {
            throw new InvalidDataException("SharePoint search response did not contain a result row collection.");
        }

        foreach (var row in rows.EnumerateArray())
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!TryGetCollection(row, out var cells, "Cells"))
            {
                throw new InvalidDataException("SharePoint search result row did not contain a cell collection.");
            }
            foreach (var cell in cells.EnumerateArray())
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
        if (!TryGetCollection(element, out var collection, path))
        {
            yield break;
        }

        foreach (var item in collection.EnumerateArray())
        {
            yield return item;
        }
    }

    private static bool TryGetCollection(JsonElement element, out JsonElement collection, params string[] path)
    {
        if (!TryGetNestedProperty(element, out collection, path)) return false;
        if (collection.ValueKind == JsonValueKind.Array) return true;
        return collection.ValueKind == JsonValueKind.Object
            && TryGetProperty(collection, "results", out collection)
            && collection.ValueKind == JsonValueKind.Array;
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
        yield return "/";
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
        long? Size,
        string? Version = null,
        string? LastModified = null);

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
