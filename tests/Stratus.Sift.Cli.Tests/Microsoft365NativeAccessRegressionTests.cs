using System.Net;
using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Connectors.SharePoint;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class Microsoft365NativeAccessRegressionTests
{
    private const string SiteUrl = "https://contoso.sharepoint.com/sites/Test";
    private const string InvalidEmailQuery = """
        {"odata.error":{"code":"-1, Microsoft.SharePoint.SPException","message":{"lang":"en-US","value":"The query to field 'Author/Email' is not valid."}}}
        """;
    private static readonly Microsoft365CoverageOptions Sharing = Microsoft365CoverageOptions.Disabled with { ReadSharing = true };
    private static HttpResponseMessage Json(object value) => Response(HttpStatusCode.OK, JsonSerializer.Serialize(value));
    private static SharePointRestClient Rest(Func<HttpRequestMessage, HttpResponseMessage> callback)
        => new(new StubCredential(), "Tests", new HttpClient(new Handler(callback)));
    private static HttpResponseMessage Roles() => Json(new { value = new[] {
        new { Member = new { LoginName = "spo-grid-all-users/tenant", PrincipalType = 4 },
            RoleDefinitionBindings = new[] { new { Name = "Read" } } } } });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NativeSharing_UsesPersonLookupEMailAndCompletesContentScan(bool verbose)
    {
        var requests = new List<Uri>();
        var rest = Rest(request =>
        {
            requests.Add(request.RequestUri!);
            if (request.RequestUri!.AbsolutePath.EndsWith("/RoleAssignments")) return Roles();
            var query = Uri.UnescapeDataString(request.RequestUri.Query);
            if (query.Contains("Author/Email", StringComparison.Ordinal))
                return Response(HttpStatusCode.BadRequest, InvalidEmailQuery);
            Assert.Contains("Author/EMail", query);
            Assert.Contains("$expand=Author", query);
            var metadata = new { Author = new { Title = "Alice", EMail = "alice@stratus.security" }, HasUniqueRoleAssignments = false };
            return verbose ? Json(new { d = metadata }) : Json(metadata);
        });
        var file = Microsoft365ContentFile.Text("list:1", "item.json", SiteUrl + "/Lists/Test/1", "secret")
            .WithInspection(ct => Microsoft365NativeAccessReader.ReadAsync(rest, new(SiteUrl),
                "web/lists('11111111-1111-1111-1111-111111111111')/items(1)", Sharing, ct));
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), extension: ".json");

        Assert.False(result.Incomplete);
        Assert.Equal(1, result.Processed);
        Assert.Equal("final", result.FinalToken);
        var finding = Assert.Single(result.Findings);
        Assert.Equal("Organization", finding.Exposure);
        Assert.Equal("alice@stratus.security", finding.Owner);
        Assert.True(Assert.Single(finding.AclEntries!).IsInherited);
        Assert.Equal(2, requests.Count);
    }

    [Theory]
    [InlineData("The query to field 'Author/Title' is not valid.")]
    [InlineData("The query to field 'Author/EMail' is not valid.")]
    [InlineData("The $expand query is not valid for field 'Author'.")]
    public async Task MissingAuthorProjection_DoesNotPreventPermissionInspection(string errorMessage)
    {
        var requests = new List<Uri>();
        var rest = Rest(request =>
        {
            requests.Add(request.RequestUri!);
            if (request.RequestUri!.AbsolutePath.EndsWith("/RoleAssignments")) return Roles();
            if (Uri.UnescapeDataString(request.RequestUri.Query).Contains("$expand=Author", StringComparison.Ordinal))
                return JsonError(errorMessage);
            Assert.Equal("?$select=HasUniqueRoleAssignments", Uri.UnescapeDataString(request.RequestUri.Query));
            return Json(new { HasUniqueRoleAssignments = true });
        });
        var access = await Microsoft365NativeAccessReader.ReadAsync(rest, new(SiteUrl), "web/list/item", Sharing, CancellationToken.None);
        Assert.Equal("Organization", access.Exposure);
        Assert.Equal("Cloud", access.Owner);
        Assert.False(Assert.Single(access.Acls).IsInherited);
        Assert.Equal(3, requests.Count);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(403)]
    public async Task OtherMetadataErrors_PreserveContentAndLeaveSharingIncomplete(int status)
    {
        var requests = 0;
        var rest = Rest(_ => { requests++; return Response((HttpStatusCode)status,
            """{"odata.error":{"code":"-1","message":{"value":"Permission inspection unavailable."}}}"""); });
        var file = Microsoft365ContentFile.Text("list:1", "item.json", SiteUrl + "/Lists/Test/1", "secret")
            .WithInspection(ct => Microsoft365NativeAccessReader.ReadAsync(rest, new(SiteUrl), "web/list/item", Sharing, ct));
        var skipCalls = 0;
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), extension: ".json",
            skip: _ => { skipCalls++; return true; });
        Assert.True(result.Incomplete);
        Assert.Equal("Unknown", Assert.Single(result.Findings).Exposure);
        Assert.Equal(0, result.Processed);
        Assert.Equal(0, skipCalls);
        Assert.Null(result.FinalToken);
        Assert.Equal(1, requests);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(403)]
    public async Task SubsiteFailures_ReportStatusAndServerReasonWhileKeepingParentSources(int status)
    {
        var rest = Rest(request => request.RequestUri!.AbsolutePath.EndsWith("/webs")
            ? Response((HttpStatusCode)status, """{"odata.error":{"message":{"value":"Subsite enumeration unavailable."}}}""")
            : request.RequestUri.AbsolutePath.EndsWith("/web") ? Json(new { Title = "Test", Url = SiteUrl })
            : Json(new { value = Array.Empty<object>() }));
        var connector = new SharePointConnector(rest, "tenant", new(SiteUrl), useConfiguredTargets: true,
            configuredSiteTargets: [new(SiteUrl)], coverage: Microsoft365CoverageOptions.Disabled with
            { RecurseSubsites = true, ScanListsAndPages = true });
        Assert.Single(await connector.GetDrivesAsync());
        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Equal(1, connector.DiscoveryReport.SourceCounts["discovery failures"]);
        if (status == 403)
        {
            Assert.Empty(connector.DiscoveryReport.Warnings);
            Assert.Equal(1, connector.DiscoveryReport.SourceCounts["inaccessible subsite inventories"]);
        }
        else
        {
            var warning = Assert.Single(connector.DiscoveryReport.Warnings, value => value.Contains("Subsites"));
            Assert.Contains(status.ToString(), warning);
            Assert.Contains("Subsite enumeration unavailable", warning);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RepeatedSharingErrors_BoundWarningsAndKeepEveryContentFindingPending(bool distinctErrors)
    {
        var inspections = 0;
        var rest = Rest(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/lists")) return Json(new { value = new[] { new { Id = "list", Title = "Test", BaseType = 0 } } });
            if (path.EndsWith("/items")) return Json(new { value = Enumerable.Range(1, 15).Select(id => new { Id = id, Notes = "secret" }).ToArray() });
            inspections++;
            return Response(HttpStatusCode.Forbidden, $"Permission denied{(distinctErrors ? inspections.ToString() : "")}.");
        });
        var drive = new Microsoft365SiteDataDrive(null, rest, "tenant", "site", new(SiteUrl), Sharing with { ScanListsAndPages = true });
        var logger = new RecordingLogger<RemoteDriveScanner>();
        var result = await ScanAsync(drive, extension: ".json", logger: logger);
        Assert.True(result.Incomplete);
        Assert.Equal(15, inspections);
        Assert.Equal(15, result.Findings.Count);
        Assert.Equal(15, result.Scanned);
        Assert.All(result.Findings, finding => Assert.Equal("Unknown", finding.Exposure));
        Assert.Equal(0, result.Processed);
        Assert.Null(result.FinalToken);
        var warnings = logger.Entries.Where(entry => entry.Level == LogLevel.Warning).ToList();
        Assert.Empty(warnings);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information
            && entry.Message.Contains("15 metadata/sharing inspections"));
        Assert.Equal(15, logger.Entries.Count(entry => entry.Level == LogLevel.Debug && entry.Exception != null));
    }

    [Theory]
    [InlineData("", "Alice", "Alice")]
    [InlineData(" ", "Alice", "Alice")]
    [InlineData(null, null, "Cloud")]
    public async Task EmptyAuthorEmail_UsesAvailableTitle(string? email, string? title, string expected)
    {
        var rest = Rest(request => request.RequestUri!.AbsolutePath.EndsWith("/RoleAssignments") ? Roles()
            : Json(new { Author = new { EMail = email, Title = title }, HasUniqueRoleAssignments = false }));
        var access = await Microsoft365NativeAccessReader.ReadAsync(rest, new(SiteUrl), "web/list/item", Sharing, CancellationToken.None);
        Assert.Equal(expected, access.Owner);
    }

    [Fact]
    public async Task MissingPermissionInheritance_RemainsAnInspectionFailure()
    {
        var rest = Rest(_ => Json(new { Author = new { EMail = "alice@stratus.security" } }));
        await Assert.ThrowsAsync<InvalidDataException>(() => Microsoft365NativeAccessReader.ReadAsync(rest, new(SiteUrl),
            "web/list/item", Sharing, CancellationToken.None));
    }

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly ConcurrentQueue<(LogLevel Level, string Message, Exception? Exception)> _entries = new();
        internal IReadOnlyCollection<(LogLevel Level, string Message, Exception? Exception)> Entries => _entries.ToArray();
        public bool IsEnabled(LogLevel level) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => _entries.Enqueue((level, formatter(state, exception), exception));
    }

    private static HttpResponseMessage JsonError(string message) => Response(HttpStatusCode.BadRequest,
        JsonSerializer.Serialize(new Dictionary<string, object> { ["odata.error"] = new
        { code = "-1, Microsoft.SharePoint.SPException", message = new { value = message } } }));
}
