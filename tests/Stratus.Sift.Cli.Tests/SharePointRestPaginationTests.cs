using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Xml.Linq;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Cli.Tests;

public sealed class SharePointRestPaginationTests
{
    [Theory]
    [InlineData("{}")]
    [InlineData("{\"PrimaryQueryResult\":{\"RelevantResults\":{\"Table\":{\"Rows\":{}}}}}")]
    [InlineData("{\"PrimaryQueryResult\":{\"RelevantResults\":{\"Table\":{\"Rows\":[{}]}}}}")]
    public async Task MalformedSearch_ThrowsAndMarksDiscoveryIncomplete(string body)
    {
        var client = Client(_ => Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, body));
        await Assert.ThrowsAsync<InvalidDataException>(() => client.SearchAccessibleSitesAsync(Site().Url, CancellationToken.None));
        var connector = new SharePointConnector(client, "tenant", new Uri("https://contoso.sharepoint.com"));

        Assert.Empty(await connector.GetDrivesAsync());

        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Contains("site search", Assert.Single(connector.DiscoveryReport.Warnings), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidEmptySearch_RemainsCompleteInBothResponseFormats(bool verbose)
    {
        object rows = verbose ? new { results = Array.Empty<object>() } : Array.Empty<object>();
        object result = new { PrimaryQueryResult = new { RelevantResults = new { Table = new { Rows = rows } } } };
        if (verbose) result = new { d = new { query = result } };
        var client = Client(_ => Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, JsonSerializer.Serialize(result)));
        var connector = new SharePointConnector(client, "tenant", new Uri("https://contoso.sharepoint.com"));

        Assert.Empty(await connector.GetDrivesAsync());

        Assert.True(connector.DiscoveryReport.IsComplete);
        Assert.Empty(connector.DiscoveryReport.Warnings);
    }

    [Fact]
    public async Task FailedSearch_ContinuesWithValidFollowedLocations()
    {
        var client = Client(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            if (url.Contains("/search/query", StringComparison.Ordinal)) return Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, "{}");
            if (url.Contains("/social.following", StringComparison.Ordinal)) return Microsoft365ReliabilityTests.Response(HttpStatusCode.OK,
                """{"Followed":[{"ContentUri":"https://contoso.sharepoint.com/sites/Test/Documents/file.txt"}]}""");
            if (url.Contains("/lists?", StringComparison.Ordinal)) return Page([new { Id = "list", Title = "Documents",
                RootFolder = new { ServerRelativeUrl = "/sites/Test/Documents" } }], null, "@odata.nextLink");
            return Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, """{"Title":"Test","Url":"https://contoso.sharepoint.com/sites/Test"}""");
        });
        var connector = new SharePointConnector(client, "tenant", new Uri("https://contoso.sharepoint.com"), discoverFollowedLocations: true);

        Assert.Single(await connector.GetDrivesAsync());
        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Single(connector.DiscoveryReport.Warnings);
    }

    [Theory]
    [InlineData("")]
    [InlineData("/Reports")]
    public async Task RootSiteLibraryTarget_ResolvesThroughTenantRoot(string folder)
    {
        var rootRequests = 0;
        var client = Client(request =>
        {
            var uri = request.RequestUri!;
            if (uri.AbsolutePath == "/_api/web")
            {
                rootRequests++;
                return Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, """{"Title":"Root","Url":"https://contoso.sharepoint.com"}""");
            }
            if (uri.AbsoluteUri.Contains("/lists?", StringComparison.Ordinal)) return Page([new { Id = "list", Title = "Documents",
                RootFolder = new { ServerRelativeUrl = "/Shared Documents" } }], null, "@odata.nextLink");
            return Microsoft365ReliabilityTests.Response(HttpStatusCode.NotFound, "{}");
        });
        var connector = new SharePointConnector(client, "tenant", null, useConfiguredTargets: true,
            configuredSiteTargets: [new Uri("https://contoso.sharepoint.com/Shared%20Documents" + folder)]);

        Assert.Equal("list", Assert.Single(await connector.GetDrivesAsync()).Id);
        Assert.Equal(1, rootRequests);
        Assert.True(connector.DiscoveryReport.IsComplete);
    }

    [Theory]
    [InlineData("test#2026.txt")]
    [InlineData("test%20name.txt")]
    [InlineData("O'Brien #50%.txt")]
    [InlineData("文書#25%.txt")]
    public async Task DecodedPaths_RoundTripThroughBrowserUrlsAndResourcePathRequests(string name)
    {
        const string libraryPath = "/sites/Test/Documents#2026";
        var filePath = libraryPath + "/" + name;
        var downloadRequests = 0;
        var client = Client(request =>
        {
            var uri = request.RequestUri!;
            Assert.Empty(uri.Fragment);
            if (uri.AbsoluteUri.Contains("/lists?", StringComparison.Ordinal)) return Page([new { Id = "list", Title = "Documents",
                RootFolder = new { ServerRelativeUrl = libraryPath } }], null, "@odata.nextLink");
            if (uri.AbsoluteUri.Contains("GetListItemChangesSinceToken", StringComparison.Ordinal))
            {
                var xml = new XElement("listitems", new XElement("Changes", new XAttribute("LastChangeToken", "next")),
                    new XElement("data", new XElement("row", new XAttribute("ows_UniqueId", "item"),
                        new XAttribute("ows_FileRef", filePath), new XAttribute("ows_FileLeafRef", name))));
                return Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, xml.ToString());
            }
            if (uri.AbsoluteUri.Contains("/$value", StringComparison.Ordinal))
            {
                downloadRequests++;
                Assert.Contains("GetFileByServerRelativePath(decodedUrl=", uri.AbsoluteUri, StringComparison.Ordinal);
                Assert.Contains(filePath.Replace("'", "''"), Uri.UnescapeDataString(uri.AbsoluteUri), StringComparison.Ordinal);
                return Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, "secret");
            }
            Assert.Contains("GetFolderByServerRelativePath(decodedUrl=", uri.AbsoluteUri, StringComparison.Ordinal);
            Assert.Contains(libraryPath, Uri.UnescapeDataString(uri.AbsoluteUri), StringComparison.Ordinal);
            return uri.AbsoluteUri.Contains("/Files?", StringComparison.Ordinal)
                ? Page([new { Name = name, UniqueId = "item", ServerRelativeUrl = filePath, Length = "6" }], null, "@odata.nextLink")
                : Page([], null, "@odata.nextLink");
        });
        var library = Assert.Single(await client.GetLibrariesAsync(Site(), CancellationToken.None));
        Assert.Equal(libraryPath, Uri.UnescapeDataString(library.WebUrl.AbsolutePath));
        Assert.Empty(library.WebUrl.Fragment);
        var files = new List<IRemoteFile>();
        await new SharePointRestDrive(client, library, "tenant", "Documents").ProcessChangesAsync(null,
            file => { files.Add(file); return Task.CompletedTask; });
        var file = Assert.Single(files);
        var webUri = new Uri(file.WebUrl);
        Assert.Empty(webUri.Fragment);
        Assert.Empty(webUri.Query);
        Assert.Equal(filePath, Uri.UnescapeDataString(webUri.AbsolutePath));
        using var stream = await file.GetContentAsync();
        using var reader = new StreamReader(stream!);
        Assert.Equal("secret", await reader.ReadToEndAsync());
        var changes = await client.GetListItemChangesAsync(library, "previous", null, CancellationToken.None);
        Assert.Equal(file.WebUrl, Assert.Single(changes.Items).WebUrl.AbsoluteUri);
        Assert.Equal(1, downloadRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExhaustedRestRetries_StillPauseSubsequentRequests(bool dateHeader)
    {
        var attempts = 0;
        var client = Client(_ =>
        {
            attempts++;
            if (attempts > 11) return Page([], null, "@odata.nextLink");
            var response = Microsoft365ReliabilityTests.Response(HttpStatusCode.TooManyRequests, "{}");
            response.Headers.RetryAfter = attempts < 11
                ? new RetryConditionHeaderValue(TimeSpan.FromMilliseconds(1))
                : dateHeader
                    ? new RetryConditionHeaderValue(DateTimeOffset.UtcNow.AddMinutes(2))
                    : new RetryConditionHeaderValue(TimeSpan.FromMinutes(2));
            return response;
        });

        var failure = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetLibrariesAsync(Site(), CancellationToken.None));
        Assert.Equal(HttpStatusCode.TooManyRequests, failure.StatusCode);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetLibrariesAsync(Site(), cancellation.Token));

        Assert.Equal(11, attempts);
    }

    [Fact]
    public async Task FolderEnumeration_SkipsOnlyLibrarySystemFormsDirectory()
    {
        var visited = new List<string>();
        var client = Client(request =>
        {
            var url = Uri.UnescapeDataString(request.RequestUri!.AbsoluteUri);
            visited.Add(url);
            if (url.Contains("Documents/Forms'", StringComparison.Ordinal))
                throw new InvalidOperationException("System Forms folder should not be enumerated.");
            if (url.Contains("/Folders?", StringComparison.Ordinal))
            {
                if (url.Contains("Documents'", StringComparison.Ordinal)) return Page([
                    new { Name = "Forms", ServerRelativeUrl = "/sites/Test/Documents/Forms" },
                    new { Name = "Forms2026", ServerRelativeUrl = "/sites/Test/Documents/Forms2026" },
                    new { Name = "Archive", ServerRelativeUrl = "/sites/Test/Documents/Archive" }], null, "@odata.nextLink");
                if (url.Contains("Documents/Archive'", StringComparison.Ordinal)) return Page([
                    new { Name = "Forms", ServerRelativeUrl = "/sites/Test/Documents/Archive/Forms" }], null, "@odata.nextLink");
                return Page([], null, "@odata.nextLink");
            }
            if (url.Contains("Documents/Forms2026'", StringComparison.Ordinal)) return Page([FileItem("current")], null, "@odata.nextLink");
            if (url.Contains("Documents/Archive/Forms'", StringComparison.Ordinal)) return Page([FileItem("archived")], null, "@odata.nextLink");
            return Page([], null, "@odata.nextLink");
        });

        var files = await client.EnumerateLibraryFilesAsync(Library(), CancellationToken.None);

        Assert.Equal(["current", "archived"], files.Select(file => file.Id));
        Assert.Contains(visited, url => url.Contains("Documents/Forms2026'", StringComparison.Ordinal));
        Assert.Contains(visited, url => url.Contains("Documents/Archive/Forms'", StringComparison.Ordinal));
    }

    [Fact]
    public async Task IncrementalChanges_SkipOnlyLibrarySystemFormsDirectory()
    {
        var client = Client(_ => Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, """
            <listitems>
              <Changes LastChangeToken="next" />
              <data>
                <row ows_UniqueId="system" ows_FileRef="/sites/Test/Documents/Forms/AllItems.aspx" />
                <row ows_UniqueId="current" ows_FileRef="/sites/Test/Documents/Forms2026/secret.txt" />
                <row ows_UniqueId="archived" ows_FileRef="/sites/Test/Documents/Archive/Forms/secret.txt" />
              </data>
            </listitems>
            """));

        var changes = await client.GetListItemChangesAsync(Library(), "previous", null, CancellationToken.None);

        Assert.Equal(["current", "archived"], changes.Items.Select(file => file.Id));
        Assert.Equal("next", changes.LastChangeToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingConfiguredLibrary_MarksRestDiscoveryIncomplete(bool includeValidTarget)
    {
        var client = Client(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            if (url.Contains("/Missing/", StringComparison.Ordinal)) return Microsoft365ReliabilityTests.Response(HttpStatusCode.NotFound, "{}");
            if (url.Contains("/lists?", StringComparison.Ordinal)) return Page([new { Id = "list-1", Title = "Documents", ItemCount = 1,
                RootFolder = new { ServerRelativeUrl = "/sites/Test/Documents" } }], null, "@odata.nextLink");
            return Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, """{"Title":"Test","Url":"https://contoso.sharepoint.com/sites/Test"}""");
        });
        var targets = new List<Uri> { new("https://contoso.sharepoint.com/sites/Test/Missing") };
        if (includeValidTarget) targets.Add(Site().Url);
        var connector = new SharePointConnector(client, "tenant", null, useConfiguredTargets: true, configuredSiteTargets: targets);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Equal(includeValidTarget ? 1 : 0, drives.Count);
        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Contains("No document library matches", Assert.Single(connector.DiscoveryReport.Warnings), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("@odata.nextLink")]
    [InlineData("odata.nextLink")]
    [InlineData("__next")]
    public async Task Libraries_FollowsContinuationLinks(string format)
    {
        var requests = new List<string>();
        var client = Client(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            requests.Add(url);
            var secondPage = url.Contains("page=2");
            return Page([new { Id = secondPage ? "list-2" : "list-1", Title = "Documents", ItemCount = 1,
                    RootFolder = new { ServerRelativeUrl = "/sites/Test/Documents" } }],
                secondPage ? null : "/sites/Test/_api/web/lists?page=2", format);
        });

        var libraries = await client.GetLibrariesAsync(Site(), CancellationToken.None);

        Assert.Equal(["list-1", "list-2"], libraries.Select(library => library.Id));
        Assert.Equal(2, requests.Count);
    }

    [Theory]
    [InlineData("@odata.nextLink")]
    [InlineData("odata.nextLink")]
    [InlineData("__next")]
    public async Task FilesAndFolders_FollowsEveryPageAndRecursesIntoLaterFolders(string format)
    {
        var requests = new List<string>();
        var client = Client(request =>
        {
            var url = Uri.UnescapeDataString(request.RequestUri!.AbsoluteUri);
            requests.Add(url);
            if (url.Contains("/next-files")) return Page([FileItem("second")], null, format);
            if (url.Contains("/next-folders")) return Page([new { Name = "Nested", ServerRelativeUrl = "/sites/Test/Documents/Nested" }], null, format);
            if (url.Contains("/Nested'") && url.Contains("/Files?")) return Page([FileItem("nested")], null, format);
            if (url.Contains("/Nested'") && url.Contains("/Folders?")) return Page([], null, format);
            if (url.Contains("/Files?")) return Page([FileItem("first")], "/sites/Test/_api/next-files", format);
            if (url.Contains("/Folders?")) return Page([], "/sites/Test/_api/next-folders", format);
            throw new InvalidOperationException(url);
        });
        var files = new List<IRemoteFile>();

        await new SharePointRestDrive(client, Library(), "tenant", "Documents").ProcessChangesAsync(null,
            file => { files.Add(file); return Task.CompletedTask; });

        Assert.Equal(["first", "second", "nested"], files.Select(file => file.Id));
        Assert.All(files, file => Assert.Equal("v1", file.Version));
        Assert.Equal(6, requests.Count);
        Assert.Contains(requests, url => url.Contains("ETag,TimeLastModified"));
    }

    [Theory]
    [InlineData(403)]
    [InlineData(404)]
    public async Task MissingOrDeniedContinuationPage_FailsInsteadOfCompleting(int status)
    {
        var client = Client(request => request.RequestUri!.AbsoluteUri.Contains("page=2")
            ? Microsoft365ReliabilityTests.Response((HttpStatusCode)status, """{"error":{"message":"Mock failure"}}""")
            : Page([FileItem("first")], "/sites/Test/_api/files?page=2", "@odata.nextLink"));
        var drive = new SharePointRestDrive(client, Library(), "tenant", "Documents");
        var files = new List<IRemoteFile>();

        await Assert.ThrowsAnyAsync<Exception>(() => drive.ProcessChangesAsync(null,
            file => { files.Add(file); return Task.CompletedTask; }));

        Assert.Single(files);
    }

    [Fact]
    public async Task RepeatedContinuationLink_FailsWithoutLooping()
    {
        var requests = 0;
        var client = Client(_ => { requests++; return Page([], "/sites/Test/_api/lists?page=2", "@odata.nextLink"); });

        await Assert.ThrowsAsync<InvalidDataException>(() => client.GetLibrariesAsync(Site(), CancellationToken.None));

        Assert.Equal(2, requests);
    }

    [Fact]
    public async Task FailedLibraryPage_MarksConnectorDiscoveryIncomplete()
    {
        var client = Client(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            if (url.Contains("page=2")) return Microsoft365ReliabilityTests.Response(HttpStatusCode.Forbidden, "{}");
            if (url.Contains("/lists?")) return Page([new { Id = "list-1", Title = "Documents", ItemCount = 1,
                RootFolder = new { ServerRelativeUrl = "/sites/Test/Documents" } }], "/sites/Test/_api/lists?page=2", "@odata.nextLink");
            return Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, """{"Title":"Test","Url":"https://contoso.sharepoint.com/sites/Test"}""");
        });
        var connector = new SharePointConnector(client, "tenant", null, useConfiguredTargets: true,
            configuredSiteTargets: [Site().Url]);

        await connector.GetDrivesAsync();

        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Contains("incomplete", connector.DiscoveryReport.Coverage, StringComparison.Ordinal);
        Assert.Equal(1, connector.DiscoveryReport.SourceCounts["discovery failures"]);
        Assert.Empty(connector.DiscoveryReport.Warnings);
        Assert.Equal(1, connector.DiscoveryReport.SourceCounts["inaccessible library inventories"]);
    }

    private static SharePointRestClient Client(Func<HttpRequestMessage, HttpResponseMessage> callback)
        => new(new Microsoft365ReliabilityTests.StubCredential(), "Tests",
            new HttpClient(new Microsoft365ReliabilityTests.Handler(callback)));

    private static SharePointRestClient.RestSite Site()
        => new("Test", new Uri("https://contoso.sharepoint.com/sites/Test"));

    private static SharePointRestClient.RestLibrary Library()
        => new("list", "Documents", Site(), "/sites/Test/Documents",
            new Uri("https://contoso.sharepoint.com/sites/Test/Documents"), DatastoreType.SharePoint, 3);

    private static object FileItem(string id) => new
    {
        Name = id + ".txt",
        UniqueId = id,
        ServerRelativeUrl = "/sites/Test/Documents/" + id + ".txt",
        Length = "6",
        ETag = "v1"
    };

    private static HttpResponseMessage Page(object[] items, string? next, string format)
    {
        var collection = new Dictionary<string, object?> { [format == "__next" ? "results" : "value"] = items };
        if (next != null) collection[format] = next;
        object root = format == "__next" ? new Dictionary<string, object?> { ["d"] = collection } : collection;
        return Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, JsonSerializer.Serialize(root));
    }
}
