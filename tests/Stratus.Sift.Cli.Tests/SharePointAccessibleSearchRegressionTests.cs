using System.Net;
using System.Text.Json;
using Stratus.Sift.Connectors.SharePoint;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class SharePointAccessibleSearchRegressionTests
{
    private const string SiteUrl = "https://contoso.sharepoint.com/sites/Test";
    private const string SyntaxError = "We didn't understand your search terms. Make sure they're using proper syntax.";
    private static HttpResponseMessage Json(object value) => Response(HttpStatusCode.OK, JsonSerializer.Serialize(value));
    private static SharePointRestClient Rest(Func<HttpRequestMessage, HttpResponseMessage> callback)
        => new(new StubCredential(), "Tests", new HttpClient(new Handler(callback)));

    [Fact]
    public async Task AccessibleFileSearch_UsesAcceptedSortAndAdvancesPastDuplicateHits()
    {
        var searches = 0;
        var metadataReads = 0;
        var rest = Rest(request =>
        {
            var uri = request.RequestUri!;
            if (uri.AbsolutePath.EndsWith("/search/query"))
            {
                var query = Uri.UnescapeDataString(uri.Query);
                // Reproduce the live server rejection, including the otherwise
                // misleading search-terms message for an invalid sort field.
                if (query.Contains("sortlist='[docid]:ascending'", StringComparison.Ordinal))
                    return Response(HttpStatusCode.BadRequest, SyntaxError);
                Assert.Contains("sortlist='docid:ascending'", query);
                Assert.Contains("trimduplicates=false", query);
                Assert.DoesNotContain("startrow", query, StringComparison.OrdinalIgnoreCase);
                searches++;
                Assert.Contains(searches == 1 ? "IndexDocId>0 AND IsDocument:1" : "IndexDocId>500 AND IsDocument:1", query);
                return Search(searches == 1 ? 1 : 501, searches == 1 ? 500 : 1, duplicatePaths: true);
            }
            if (uri.AbsolutePath.EndsWith("/$value")) return Response(HttpStatusCode.OK, "secret");
            metadataReads++;
            var second = Uri.UnescapeDataString(uri.AbsolutePath).Contains("second.txt", StringComparison.Ordinal);
            var name = second ? "second.txt" : "first.txt";
            return Json(new { Name = name, UniqueId = name, ServerRelativeUrl = "/sites/Test/Documents/" + name, Length = 6, ETag = "v1" });
        });
        var result = await ScanAsync(new Microsoft365RestSearchDrive(rest, new("https://contoso.sharepoint.com"),
            "tenant", Microsoft365CoverageOptions.Disabled));
        Assert.False(result.Incomplete);
        Assert.Equal(2, result.Processed);
        Assert.Equal(2, result.Findings.Count);
        Assert.Equal(2, searches);
        Assert.Equal(2, metadataReads);
        Assert.Empty(result.Checkpoints);
    }

    [Fact]
    public async Task EmptyAccessibleSearch_CompletesWithoutResolvingFiles()
    {
        var requests = 0;
        var rest = Rest(request =>
        {
            requests++;
            Assert.EndsWith("/search/query", request.RequestUri!.AbsolutePath);
            Assert.Contains("sortlist='docid:ascending'", Uri.UnescapeDataString(request.RequestUri.Query));
            return Search(1, 0);
        });
        var files = new List<SharePointRestClient.RestFileItem>();
        await foreach (var (_, file) in rest.SearchAccessibleFilesAsync(new("https://contoso.sharepoint.com"), CancellationToken.None))
            files.Add(file);
        Assert.Empty(files);
        Assert.Equal(1, requests);
    }

    [Theory]
    [InlineData("repeated")]
    [InlineData("descending")]
    public async Task NonAdvancingAccessibleSearch_StopsInsteadOfLooping(string invalid)
    {
        var searches = 0;
        var rest = Rest(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/search/query"))
            {
                searches++;
                return Search(1, 2, invalid: invalid);
            }
            return Json(new { Name = "first.txt", UniqueId = "first", Length = 6, ETag = "v1" });
        });
        var files = new List<SharePointRestClient.RestFileItem>();
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
        {
            await foreach (var (_, file) in rest.SearchAccessibleFilesAsync(new("https://contoso.sharepoint.com"), CancellationToken.None))
                files.Add(file);
        });
        Assert.Single(files);
        Assert.Equal(1, searches);
    }

    private static HttpResponseMessage Search(int first, int count, bool duplicatePaths = false, string? invalid = null)
        => Json(new { PrimaryQueryResult = new { RelevantResults = new { Table = new {
            Rows = Enumerable.Range(first, count).Select((id, index) => new { Cells = new[] {
                new { Key = "DocId", Value = invalid == "repeated" && index == 1 ? first.ToString()
                    : invalid == "descending" && index == 1 ? "0" : id.ToString() },
                new { Key = "SPWebUrl", Value = SiteUrl },
                new { Key = "Path", Value = SiteUrl + "/Documents/"
                    + (duplicatePaths ? first == 1 ? "first.txt" : "second.txt" : "file" + id + ".txt") } } })
        } } } });
}
