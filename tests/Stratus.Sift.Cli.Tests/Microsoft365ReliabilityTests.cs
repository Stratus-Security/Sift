using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Abstractions;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Models;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli.Tests;

public sealed class Microsoft365ReliabilityTests
{
    [Theory]
    [InlineData(RuleTarget.FileName, "id_rsa", "query", false)]
    [InlineData(RuleTarget.FileName, "credentials.txt", "query", true)]
    [InlineData(RuleTarget.FileName, "credentials.txt", "fragment", true)]
    [InlineData(RuleTarget.FileName, "credentials #100%.txt", "encoded", false)]
    [InlineData(RuleTarget.FileName, "credentials.xlsx", "viewer", true)]
    [InlineData(RuleTarget.FileExtension, "credentials.xlsx", "viewer", false)]
    [InlineData(RuleTarget.FileExtension, "credentials.xlsx", "viewer", true)]
    public async Task BrowserUrls_UseItemNameForMetadataWithAndWithoutContentRules(
        RuleTarget target, string name, string urlKind, bool includeContent)
    {
        var item = Item("item", name, "v1");
        item.WebUrl = urlKind switch
        {
            "viewer" => "https://contoso.sharepoint.com/sites/Test/_layouts/15/Doc.aspx?sourcedoc=item&file=" + name + "&action=default",
            "encoded" => "https://contoso.sharepoint.com/sites/Test/Documents/" + Uri.EscapeDataString(name),
            "fragment" => item.WebUrl + "#bookmark",
            _ => item.WebUrl + "?web=1"
        };
        var bytes = name.EndsWith(".xlsx", StringComparison.Ordinal)
            ? ContentExtractorTests.InlineWorkbook(false) : Encoding.UTF8.GetBytes("secret");
        item.Size = bytes.Length;
        var downloads = 0;
        var graph = Graph(_ =>
        {
            downloads++;
            return new(HttpStatusCode.OK) { Content = new StreamContent(new MemoryStream(bytes)) };
        });
        var classifiers = new List<Classifier> { MetadataRule(target, target == RuleTarget.FileName ? name : ".xlsx") };
        if (includeContent) classifiers.Add(ContentRule(Path.GetExtension(name)));

        var result = await ScanAsync(new SingleFileDrive(new SharePointFile(graph, "drive", item, "tenant")),
            classifiers: classifiers, options: new ScanOptions { EnableBinaryDocuments = name.EndsWith(".xlsx", StringComparison.Ordinal) },
            policy: new Policy
            {
                Name = "URL scoped",
                Configuration = new PolicyConfiguration
                { IncludePaths = ["https://contoso.sharepoint.com/sites/Test/*"] }
            });

        Assert.Equal(item.WebUrl, Assert.Single(result.Findings, f => f.ClassifierName == "Metadata rule").ResourcePath);
        Assert.Equal(includeContent ? 2 : 1, result.Findings.Count);
        Assert.Equal(includeContent ? 1 : 0, downloads);
        Assert.Equal(1, result.Scanned);
        Assert.Equal(1, result.Processed);
        Assert.Equal("final", result.FinalToken);
        Assert.False(result.Incomplete);
    }

    [Fact]
    public async Task LargeFileHead_UsesItemNameForMetadataAndContentRules()
    {
        var item = Item("item", "credentials.txt", "v1");
        item.Size = 128;
        item.WebUrl += "?web=1";
        var graph = Graph(_ => new(HttpStatusCode.OK) { Content = new StringContent("secret " + new string('x', 128)) });

        var result = await ScanAsync(new SingleFileDrive(new SharePointFile(graph, "drive", item, "tenant")),
            classifiers: [MetadataRule(RuleTarget.FileName, item.Name!), ContentRule(".txt")],
            options: new ScanOptions { MaxFileSize = 64, HeadSize = 32 });

        Assert.Equal(2, result.Findings.Count);
        Assert.All(result.Findings, finding => Assert.Equal(item.WebUrl, finding.ResourcePath));
        Assert.False(result.Incomplete);
        Assert.Equal("final", result.FinalToken);
    }

    [Theory]
    [InlineData(".docx", false)]
    [InlineData(".docx", true)]
    [InlineData(".xlsx", false)]
    [InlineData(".xlsx", true)]
    [InlineData(".pdf", false)]
    [InlineData(".pdf", true)]
    public async Task OversizedDocument_ReportsMetadataWithoutDownloadingContent(string extension, bool includeContent)
    {
        var item = Item("item", "credentials" + extension, "v1");
        item.Size = 11 * 1024 * 1024;
        var downloads = 0;
        var graph = Graph(_ => { downloads++; throw new InvalidOperationException("Oversized document must not download."); });
        var classifiers = new List<Classifier> { MetadataRule(RuleTarget.FileName, item.Name!) };
        if (includeContent) classifiers.Add(ContentRule(extension));

        var result = await ScanAsync(new SingleFileDrive(new SharePointFile(graph, "drive", item, "tenant")),
            classifiers: classifiers, options: new ScanOptions { EnableBinaryDocuments = true });

        Assert.Equal("Metadata rule", Assert.Single(result.Findings).ClassifierName);
        Assert.Equal(0, downloads);
        Assert.Equal(includeContent ? 0 : 1, result.Scanned);
        Assert.Equal(includeContent ? 0 : 1, result.Processed);
        Assert.Equal(includeContent ? null : "final", result.FinalToken);
        Assert.Equal(includeContent, result.Incomplete);
    }

    [Theory]
    [InlineData(".txt", "?web=1")]
    [InlineData(".txt", "#bookmark")]
    [InlineData(".docx", "viewer")]
    [InlineData(".xlsx", "viewer")]
    public async Task BrowserUrls_UseItemNameForContentRulesAndRetainUrlForPolicyScope(string extension, string urlSuffix)
    {
        byte[] bytes;
        if (extension == ".xlsx") bytes = ContentExtractorTests.InlineWorkbook(false);
        else if (extension == ".docx")
        {
            using var content = new MemoryStream();
            using (var document = WordprocessingDocument.Create(content, WordprocessingDocumentType.Document))
                document.AddMainDocumentPart().Document = new DocumentFormat.OpenXml.Wordprocessing.Document(
                    new DocumentFormat.OpenXml.Wordprocessing.Body(new DocumentFormat.OpenXml.Wordprocessing.Paragraph(
                        new DocumentFormat.OpenXml.Wordprocessing.Run(new DocumentFormat.OpenXml.Wordprocessing.Text("secret")))));
            bytes = content.ToArray();
        }
        else bytes = Encoding.UTF8.GetBytes("secret");
        var item = Item("item", "test" + extension, "v1");
        item.Size = bytes.Length;
        item.WebUrl = urlSuffix == "viewer"
            ? "https://contoso.sharepoint.com/sites/Test/_layouts/15/Doc.aspx?sourcedoc=item&file=" + item.Name + "&action=default"
            : item.WebUrl + urlSuffix;
        var graph = Graph(_ => new(HttpStatusCode.OK) { Content = new StreamContent(new MemoryStream(bytes)) });

        var result = await ScanAsync(new SingleFileDrive(new SharePointFile(graph, "drive", item, "tenant")),
            options: new ScanOptions { EnableBinaryDocuments = extension != ".txt" }, extension: extension,
            policy: new Policy
            {
                Name = "URL scoped",
                Configuration = new PolicyConfiguration
                { IncludePaths = ["https://contoso.sharepoint.com/sites/Test/*"] }
            });

        Assert.Equal(item.WebUrl, Assert.Single(result.Findings).ResourcePath);
        Assert.Equal(1, result.Scanned);
        Assert.False(result.Incomplete);
        Assert.Equal("final", result.FinalToken);
    }

    [Fact]
    public async Task LargeFileHead_BrowserUrlUsesItemExtension()
    {
        var bytes = Encoding.UTF8.GetBytes("secret " + new string('x', 128));
        var item = Item("item", "test.txt", "v1");
        item.Size = bytes.Length;
        item.WebUrl += "?web=1";
        var graph = Graph(_ => new(HttpStatusCode.OK) { Content = new StreamContent(new MemoryStream(bytes)) });

        var result = await ScanAsync(new SingleFileDrive(new SharePointFile(graph, "drive", item, "tenant")),
            options: new ScanOptions { MaxFileSize = 64, HeadSize = 32 });

        Assert.Equal(item.WebUrl, Assert.Single(result.Findings).ResourcePath);
        Assert.False(result.Incomplete);
    }

    [Theory]
    [InlineData("")]
    [InlineData("/Reports")]
    public async Task RootSiteLibraryTarget_ResolvesThroughTenantRoot(string folder)
    {
        var rootRequests = 0;
        var graph = Graph(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            if (url.Contains("/sites/contoso.sharepoint.com?", StringComparison.Ordinal))
            {
                rootRequests++;
                return Response(HttpStatusCode.OK, """{"id":"root-site","name":"Root","webUrl":"https://contoso.sharepoint.com"}""");
            }
            if (url.Contains("/sites/root-site/drives", StringComparison.Ordinal)) return Response(HttpStatusCode.OK,
                """{"value":[{"id":"drive","name":"Documents","webUrl":"https://contoso.sharepoint.com/Shared%20Documents"}]}""");
            return Response(HttpStatusCode.NotFound, "{}");
        });
        var connector = new SharePointConnector(graph, "tenant", useConfiguredTargets: true,
            configuredSiteTargets: [new Uri("https://contoso.sharepoint.com/Shared%20Documents" + folder)]);

        Assert.Equal("drive", Assert.Single(await connector.GetDrivesAsync()).Id);
        Assert.Equal(1, rootRequests);
        Assert.True(connector.DiscoveryReport.IsComplete);
    }

    [Theory]
    [InlineData("tenant")]
    [InlineData("search")]
    [InlineData("libraries")]
    [InlineData("teams")]
    [InlineData("channels")]
    [InlineData("followed")]
    public async Task RepeatedDiscoveryContinuation_StopsAndReportsIncomplete(string source)
    {
        var site = new { id = "site", name = "Test", webUrl = "https://contoso.sharepoint.com/sites/Test" };
        var drive = new { id = "drive", name = "Documents", webUrl = "https://contoso.sharepoint.com/sites/Test/Documents" };
        var repeatedRequests = 0;
        var graph = Graph(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            var repeatedSource = source switch
            {
                "tenant" => url.Contains("/sites/getAllSites", StringComparison.Ordinal),
                "search" => url.Contains("/sites?", StringComparison.Ordinal),
                "libraries" => url.Contains("/sites/site/drives", StringComparison.Ordinal),
                "teams" => url.Contains("/teams?", StringComparison.Ordinal),
                "channels" => url.Contains("/allChannels", StringComparison.Ordinal),
                _ => url.Contains("/me/followedSites", StringComparison.Ordinal)
            };
            if (repeatedSource)
            {
                if (++repeatedRequests > 4) throw new InvalidOperationException("Pagination failed to stop.");
                object[] items = source is "tenant" or "search" or "followed" ? [site]
                    : source == "libraries" ? [drive] : [];
                var path = source switch
                {
                    "tenant" => "/sites/getAllSites?page=2",
                    "search" => "/sites?search=*&page=2",
                    "libraries" => "/sites/site/drives?page=2",
                    "teams" => "/teams?page=2",
                    "channels" => "/teams/team/allChannels?page=2",
                    _ => "/me/followedSites?page=2"
                };
                return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new Dictionary<string, object>
                { ["value"] = items, ["@odata.nextLink"] = "https://graph.microsoft.com/v1.0" + path }));
            }
            if (url.Contains("/teams?", StringComparison.Ordinal)) return Response(HttpStatusCode.OK, """{"value":[{"id":"team","displayName":"Test"}]}""");
            if (url.Contains("/sites/site/drives", StringComparison.Ordinal)) return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { value = new[] { drive } }));
            return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { value = source == "libraries" ? new object[] { site } : [] }));
        });
        var connector = new SharePointConnector(graph, "tenant", useConfiguredTargets: source is "search" or "followed",
            discoverTeamsChannels: source is "teams" or "channels", discoverFollowedLocations: source == "followed");

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Equal(2, repeatedRequests);
        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.NotEmpty(connector.DiscoveryReport.Warnings);
        if (source is "tenant" or "search" or "libraries" or "followed") Assert.Single(drives);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingConfiguredLibrary_MarksDiscoveryIncomplete(bool includeValidTarget)
    {
        var graph = Graph(request =>
        {
            var url = Uri.UnescapeDataString(request.RequestUri!.AbsoluteUri);
            if (url.Contains("/Missing?", StringComparison.Ordinal)) return Response(HttpStatusCode.NotFound, "{}");
            if (url.Contains("/drives", StringComparison.Ordinal)) return Response(HttpStatusCode.OK,
                """{"value":[{"id":"drive","name":"Documents","webUrl":"https://contoso.sharepoint.com/sites/Test/Documents"}]}""");
            return Response(HttpStatusCode.OK,
                """{"id":"site","name":"Test","webUrl":"https://contoso.sharepoint.com/sites/Test"}""");
        });
        var targets = new List<Uri> { new("https://contoso.sharepoint.com/sites/Test/Missing") };
        if (includeValidTarget) targets.Add(new("https://contoso.sharepoint.com/sites/Test"));
        var connector = new SharePointConnector(graph, "tenant", null, useConfiguredTargets: true, configuredSiteTargets: targets);

        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Equal(includeValidTarget ? 1 : 0, drives.Count);
        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Contains("No document library matches", Assert.Single(connector.DiscoveryReport.Warnings), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(8)]
    public async Task FailedCompletionCallback_CancelsCheckpointBarrierAndBoundedProducer(int fileCount)
    {
        var outcome = new ScanOutcome();
        using var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var expected = new IOException("Mock journal failure");

        var actual = await Assert.ThrowsAsync<IOException>(() => ScanAsync(
            new SingleFileDrive(new TestFile(() => new MemoryStream(Encoding.UTF8.GetBytes("public"))), fileCount),
            processed: async (_, ct) => { await Task.Delay(50, ct); throw expected; },
            executionOptions: new RemoteDriveScanExecutionOptions(WorkerCount: 1, QueueCapacity: 1),
            cancellationToken: watchdog.Token, outcome: outcome).WaitAsync(TimeSpan.FromSeconds(3)));

        Assert.Same(expected, actual);
        Assert.False(watchdog.IsCancellationRequested);
        Assert.True(outcome.Incomplete);
        Assert.Equal(0, outcome.Scanned);
        Assert.Empty(outcome.Checkpoints);
        Assert.Null(outcome.FinalToken);
    }

    [Fact]
    public async Task CallerCancellation_StillPropagatesFromThePipeline()
    {
        using var cancellation = new CancellationTokenSource();
        var outcome = new ScanOutcome();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ScanAsync(
            new SingleFileDrive(new TestFile(() => new MemoryStream(Encoding.UTF8.GetBytes("public")))),
            processed: (_, _) => { cancellation.Cancel(); return ValueTask.CompletedTask; },
            cancellationToken: cancellation.Token, outcome: outcome));
        Assert.Empty(outcome.Checkpoints);
        Assert.Null(outcome.FinalToken);
    }

    [Theory]
    [InlineData(".docx")]
    [InlineData(".xlsx")]
    [InlineData(".pdf")]
    public async Task CorruptDocument_RemainsPendingWithoutAdvancingCheckpoints(string extension)
    {
        var result = await ScanAsync(new SingleFileDrive(new TestFile(
            () => new MemoryStream(Encoding.UTF8.GetBytes("not a document")), "test" + extension)),
            options: new ScanOptions { EnableBinaryDocuments = true }, extension: extension);

        Assert.True(result.Incomplete);
        Assert.Equal(0, result.Scanned);
        Assert.Equal(0, result.Processed);
        Assert.Empty(result.Checkpoints);
        Assert.Null(result.FinalToken);
    }

    [Fact]
    public async Task ValidEmptyDocument_CompletesSuccessfully()
    {
        using var content = new MemoryStream();
        using (var document = WordprocessingDocument.Create(content, WordprocessingDocumentType.Document))
        {
            document.AddMainDocumentPart().Document = new DocumentFormat.OpenXml.Wordprocessing.Document(
                new DocumentFormat.OpenXml.Wordprocessing.Body());
        }
        var bytes = content.ToArray();
        var result = await ScanAsync(new SingleFileDrive(new TestFile(() => new MemoryStream(bytes), "empty.docx")),
            options: new ScanOptions { EnableBinaryDocuments = true }, extension: ".docx");

        Assert.False(result.Incomplete);
        Assert.Equal(1, result.Scanned);
        Assert.Equal(1, result.Processed);
        Assert.Equal("final", result.FinalToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WorkbookInlineStrings_AreScannedForFindings(bool richText)
    {
        var bytes = ContentExtractorTests.InlineWorkbook(richText);
        var result = await ScanAsync(new SingleFileDrive(new TestFile(() => new MemoryStream(bytes), "test.xlsx")),
            options: new ScanOptions { EnableBinaryDocuments = true }, extension: ".xlsx");

        Assert.Single(result.Findings);
        Assert.False(result.Incomplete);
        Assert.Equal(1, result.Scanned);
        Assert.Equal("final", result.FinalToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LargeFileHead_IsBoundedWhenRangeResponseReturnsEntireFile(bool rest)
    {
        var content = new TrackingReadStream(Encoding.UTF8.GetBytes(new string('x', 128) + "secret"));
        HttpResponseMessage Download(HttpRequestMessage request)
        {
            Assert.Equal("bytes=0-31", request.Headers.Range!.ToString());
            return new(HttpStatusCode.OK) { Content = new StreamContent(content) };
        }
        var item = Item("item", "test.txt", "v1");
        item.Size = 134;
        IRemoteFile file;
        if (rest)
        {
            var client = new SharePointRestClient(new StubCredential(), "Tests", new HttpClient(new Handler(Download)));
            file = new SharePointRestFile(client, new Uri("https://contoso.sharepoint.com/sites/Test"),
                new SharePointRestClient.RestFileItem("item", "test.txt", "/sites/Test/Documents/test.txt",
                    new Uri(item.WebUrl!), false, false, 134));
        }
        else file = new SharePointFile(Graph(Download), "drive", item, "tenant");

        var result = await ScanAsync(new SingleFileDrive(file), options: new ScanOptions { MaxFileSize = 64, HeadSize = 32 });

        Assert.Equal(32, content.BytesRead);
        Assert.True(content.Disposed);
        Assert.Empty(result.Findings);
        Assert.Equal(1, result.Scanned);
        Assert.False(result.Incomplete);
    }

    [Fact]
    public async Task ConcurrentLibraryFailures_AreAllRecordedInDiscoveryReport()
    {
        var sites = Enumerable.Range(0, 24).Select(index => new
        {
            id = $"site-{index}",
            name = $"Site {index}",
            webUrl = $"https://contoso.sharepoint.com/sites/Site{index}"
        });
        var graph = Graph(request => request.RequestUri!.AbsoluteUri.Contains("getAllSites")
            ? Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { value = sites }))
            : Response(HttpStatusCode.Forbidden, """{"error":{"message":"Mock denial"}}"""));
        var connector = new SharePointConnector(graph, "tenant");

        Assert.Empty(await connector.GetDrivesAsync());

        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Equal(24, connector.DiscoveryReport.SourceCounts["discovery failures"]);
        Assert.Equal(24, connector.DiscoveryReport.Warnings.Count);
    }

    [Fact]
    public async Task FailedSecondLibraryPage_PreservesFirstPageAndReportsIncomplete()
    {
        var graph = Graph(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            if (url.Contains("page=2")) return Response(HttpStatusCode.Forbidden, """{"error":{"message":"Mock denial"}}""");
            if (url.Contains("getAllSites")) return Response(HttpStatusCode.OK,
                """{"value":[{"id":"site","name":"Test","webUrl":"https://contoso.sharepoint.com/sites/Test"}]}""");
            return Response(HttpStatusCode.OK,
                """{"value":[{"id":"drive","name":"Documents","webUrl":"https://contoso.sharepoint.com/sites/Test/Documents"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/sites/site/drives?page=2"}""");
        });
        var connector = new SharePointConnector(graph, "tenant");

        Assert.Single(await connector.GetDrivesAsync());

        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Single(connector.DiscoveryReport.Warnings);
    }

    [Fact]
    public async Task CancelledSiteDiscovery_PropagatesCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var graph = Graph(_ =>
        {
            cancellation.Cancel();
            throw new OperationCanceledException(cancellation.Token);
        });
        var connector = new SharePointConnector(graph, "tenant");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connector.GetDrivesAsync(cancellation.Token));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IncompleteDiscovery_ReturnsPartialExitAndRecordsAnError(bool enumerateOnly)
    {
        var output = Path.GetTempFileName();
        try
        {
            var exit = await CliScanRunner.RunConnectorScanAsync("Microsoft365", [], false, enumerateOnly, null,
                outputOptions: new CliOutputOptions(output, CliOutputFormat.Json, CliOutputStyle.Default),
                connectorOverride: new IncompleteConnector(), showBanner: false);

            Assert.Equal(CliExitCodes.Partial, exit);
            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(output));
            Assert.Equal(1, document.RootElement.GetProperty("Errors").GetInt32());
            Assert.Equal(0, document.RootElement.GetProperty("FilesScanned").GetInt32());
        }
        finally
        {
            File.Delete(output);
        }
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(500)]
    public async Task FailedContent_DoesNotCountScanOrAdvanceEitherCheckpoint(int status)
    {
        var graph = Graph(_ => Response((HttpStatusCode)status, """{"error":{"code":"accessDenied","message":"Mock failure"}}"""));
        var file = new SharePointFile(graph, "drive", Item("item", "test.txt", "v1"), "tenant");
        var result = await ScanAsync(new SingleFileDrive(file));

        Assert.Equal(0, result.Scanned);
        Assert.Equal(0, result.Processed);
        Assert.Empty(result.Checkpoints);
        Assert.Null(result.FinalToken);
        Assert.True(result.Incomplete);
    }

    [Fact]
    public async Task NullContent_AndUnexpectedExceptions_RemainPending()
    {
        foreach (var file in new IRemoteFile[]
                 {
                     new TestFile(() => null),
                     new TestFile(() => throw new InvalidOperationException("Mock failure"))
                 })
        {
            var result = await ScanAsync(new SingleFileDrive(file));
            Assert.True(result.Incomplete);
            Assert.Equal(0, result.Scanned);
            Assert.Equal(0, result.Processed);
            Assert.Null(result.FinalToken);
            Assert.Empty(result.Checkpoints);
        }
    }

    [Fact]
    public async Task SuccessfulContent_CommitsBothCheckpointsAfterProcessing()
    {
        var result = await ScanAsync(new SingleFileDrive(new TestFile(() => new MemoryStream(Encoding.UTF8.GetBytes("public")))));

        Assert.Equal(1, result.Scanned);
        Assert.Equal(1, result.Processed);
        Assert.Equal(["next"], result.Checkpoints);
        Assert.Equal("final", result.FinalToken);
        Assert.False(result.Incomplete);
    }

    [Fact]
    public async Task ResumedMicrosoft365File_WithSameSizeNewVersion_IsScannedAgain()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ContentScanner:ResumeDirectory"] = directory
        }).Build();
        var store = new CliResumeStore(configuration, NullLogger<CliResumeStore>.Instance);
        var content = "public";
        var graph = Graph(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(content)))
        });
        var drive = new SharePointDrive(graph, new Drive { Id = "drive", Name = "Documents" }, "tenant");
        var original = new SharePointFile(graph, "drive", Item("item", "test.txt", "v1"), "tenant");

        try
        {
            await using (var session = store.OpenSession("version-test", resume: false))
            {
                await session.MarkRemoteCompletedAsync(drive.ConnectionId, original.ResumeIdentity, original.Path, original.Size,
                    _ => Task.CompletedTask, CancellationToken.None, original.Version);
                await session.CommitAsync(_ => Task.CompletedTask, CancellationToken.None);
            }

            await using var resumed = store.OpenSession("version-test", resume: true);
            Assert.True(CliScanRunner.IsRemoteItemCompleted(resumed, drive, original));
            content = "secret";
            var edited = new SharePointFile(graph, "drive", Item("item", "test.txt", "v2"), "tenant");
            Assert.Equal(original.Size, edited.Size);
            var result = await ScanAsync(new SingleFileDrive(edited),
                item => CliScanRunner.IsRemoteItemCompleted(resumed, drive, item));

            Assert.Equal(1, result.Scanned);
            Assert.Single(result.Findings);
            var unversioned = new SharePointFile(graph, "drive", Item("item", "test.txt", null), "tenant");
            Assert.False(CliScanRunner.IsRemoteItemCompleted(resumed, drive, unversioned));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExpiredDelta_RestartsOnceAndInvalidatesOldCheckpoint(bool expireAfterFirstPage)
    {
        var requests = new List<string>();
        var graph = Graph(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            requests.Add(url);
            if (url.Contains("token=expired-page")) return ExpiredResponse();
            if (url.Contains("token=expired"))
            {
                return expireAfterFirstPage
                    ? Response(HttpStatusCode.OK, """{"value":[],"@odata.nextLink":"https://graph.microsoft.com/v1.0/drives/drive/root/delta?token=expired-page"}""")
                    : ExpiredResponse();
            }
            return Response(HttpStatusCode.OK, """{"value":[{"id":"file","name":"test.txt","webUrl":"https://contoso.sharepoint.com/test.txt","size":6,"file":{},"eTag":"v2"}],"@odata.deltaLink":"https://graph.microsoft.com/v1.0/drives/drive/root/delta?token=fresh"}""");
        });
        var drive = new SharePointDrive(graph, new Drive { Id = "drive" }, "tenant");
        var files = new List<IRemoteFile>();
        var checkpoints = new List<string>();

        var token = await drive.ProcessChangesAsync("https://graph.microsoft.com/v1.0/drives/drive/root/delta?token=expired",
            item => { files.Add(item); return Task.CompletedTask; },
            value => { checkpoints.Add(value); return Task.CompletedTask; });

        Assert.EndsWith("token=fresh", token, StringComparison.Ordinal);
        Assert.Single(files);
        Assert.Equal("v2", files[0].Version);
        Assert.Contains(string.Empty, checkpoints);
        Assert.Equal(expireAfterFirstPage ? 3 : 2, requests.Count);
        Assert.DoesNotContain("token=", requests.Last(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RepeatedDeltaExpiration_PropagatesAfterOneRecoveryAttempt()
    {
        var requests = 0;
        var graph = Graph(_ => { requests++; return ExpiredResponse(); });
        var drive = new SharePointDrive(graph, new Drive { Id = "drive" }, "tenant");

        await Assert.ThrowsAnyAsync<ApiException>(() => drive.ProcessChangesAsync(
            "https://graph.microsoft.com/v1.0/drives/drive/root/delta?token=expired", _ => Task.CompletedTask));

        Assert.Equal(2, requests);
    }

    [Fact]
    public async Task DeltaWithoutFinalToken_CannotCompleteTheScan()
    {
        var drive = new SharePointDrive(Graph(_ => Response(HttpStatusCode.OK, """{"value":[]}""")),
            new Drive { Id = "drive" }, "tenant");

        await Assert.ThrowsAsync<InvalidDataException>(() => drive.ProcessChangesAsync(null, _ => Task.CompletedTask));
    }

    [Fact]
    public async Task Scanner_ForwardsCheckpointInvalidationBeforeFreshEnumeration()
    {
        var expired = true;
        var graph = Graph(_ =>
        {
            if (expired) { expired = false; return ExpiredResponse(); }
            return Response(HttpStatusCode.OK, """{"value":[],"@odata.deltaLink":"fresh"}""");
        });
        var result = await ScanAsync(new SharePointDrive(graph, new Drive { Id = "drive" }, "tenant"));

        Assert.Equal([string.Empty], result.Checkpoints);
        Assert.Equal("fresh", result.FinalToken);
        Assert.False(result.Incomplete);
    }

    [Theory]
    [InlineData(403, true, false)]
    [InlineData(429, true, false)]
    [InlineData(403, false, false)]
    [InlineData(429, false, false)]
    [InlineData(403, true, true)]
    public async Task ExpiredDelta_CompletenessUsesFreshCrawlAfterAbandonedContentFailures(
        int abandonedStatus, bool checkpointCallback, bool freshFailure)
    {
        var downloads = 0;
        var graph = Graph(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            if (url.Contains("/content", StringComparison.Ordinal))
            {
                var first = ++downloads == 1;
                if (first || freshFailure) return Response(first ? (HttpStatusCode)abandonedStatus : HttpStatusCode.Forbidden,
                    """{"error":{"code":"accessDenied","message":"Mock failure"}}""");
                return new(HttpStatusCode.OK) { Content = new StringContent("secret") };
            }
            if (url.Contains("token=expired-page", StringComparison.Ordinal)) return ExpiredResponse();
            if (url.Contains("token=fresh-next", StringComparison.Ordinal)) return Response(HttpStatusCode.OK,
                """{"value":[],"@odata.deltaLink":"https://graph.microsoft.com/v1.0/drives/drive/root/delta?token=fresh"}""");
            var abandoned = url.Contains("token=old", StringComparison.Ordinal);
            var row = new
            {
                id = "file",
                name = "test.txt",
                size = 6,
                file = new { },
                eTag = abandoned ? "v1" : "v2",
                webUrl = "https://contoso.sharepoint.com/sites/Test/Documents/test.txt"
            };
            return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["value"] = new[] { row },
                ["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/drives/drive/root/delta?token=" + (abandoned ? "expired-page" : "fresh-next")
            }));
        });

        var result = await ScanAsync(new SharePointDrive(graph, new Drive { Id = "drive" }, "tenant"),
            deltaToken: "https://graph.microsoft.com/v1.0/drives/drive/root/delta?token=old", checkpointCallback: checkpointCallback);

        Assert.Equal(2, downloads);
        Assert.Equal(freshFailure, result.Incomplete);
        Assert.Equal(freshFailure ? 0 : 1, result.Scanned);
        Assert.Equal(freshFailure ? 0 : 1, result.Processed);
        Assert.Equal(freshFailure ? 0 : 1, result.Findings.Count);
        if (checkpointCallback)
        {
            Assert.Contains(string.Empty, result.Checkpoints);
            Assert.Equal(freshFailure ? 1 : 2, result.Checkpoints.Count);
            if (!freshFailure) Assert.EndsWith("token=fresh-next", result.Checkpoints.Last(), StringComparison.Ordinal);
        }
        else Assert.Empty(result.Checkpoints);
        if (freshFailure) Assert.Null(result.FinalToken);
        else Assert.EndsWith("token=fresh", result.FinalToken!, StringComparison.Ordinal);
    }

    private static Classifier MetadataRule(RuleTarget target, string pattern) => new()
    {
        Name = "Metadata rule",
        EnableLlmValidation = false,
        Matches = [new ClassifierMatch { Target = target, Patterns = [pattern], IsLiteral = true }]
    };

    private static Classifier ContentRule(string extension) => new()
    {
        Name = "Test content rule",
        EnableLlmValidation = false,
        Matches = [new ClassifierMatch { Target = RuleTarget.Content, Patterns = ["secret"], IncludedExtensions = [extension] }]
    };

    internal static async Task<ScanOutcome> ScanAsync(IRemoteDrive drive, Func<IRemoteFile, bool>? skip = null,
        ScanOptions? options = null, string extension = ".txt",
        Func<IRemoteFile, CancellationToken, ValueTask>? processed = null,
        RemoteDriveScanExecutionOptions? executionOptions = null, CancellationToken cancellationToken = default,
        ScanOutcome? outcome = null, Policy? policy = null, IReadOnlyList<Classifier>? classifiers = null,
        string? deltaToken = null, bool checkpointCallback = true, ILogger<RemoteDriveScanner>? logger = null)
    {
        outcome ??= new ScanOutcome();
        var extractor = new ContentExtractor();
        var scanner = new RemoteDriveScanner(logger ?? NullLogger<RemoteDriveScanner>.Instance,
            new FileScanner(NullLogger<FileScanner>.Instance, extractor, new ValidatorFactory([])), extractor);
        classifiers ??= [ContentRule(extension)];
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);
        await scanner.ScanDriveChangesAsync(drive, deltaToken, optimizer,
            classifiers.ToDictionary(classifier => classifier.Id, _ => new List<Policy> { policy ?? new Policy { Name = "Test policy" } }), [], options ?? new ScanOptions(),
            onIssueFound: finding => { outcome.Findings.Add(finding); return Task.CompletedTask; },
            onCheckpointToken: checkpointCallback ? token => { outcome.Checkpoints.Add(token); return Task.CompletedTask; }
        : null,
            onNewDeltaToken: token => { outcome.FinalToken = token; return Task.CompletedTask; },
            onFilesDiscovered: null, onFilesScanned: count => outcome.Scanned += count,
            onQueueDepth: null, onCurrentPath: null, ensureScanActive: null, cancellationToken: cancellationToken,
            executionOptions: executionOptions ?? new RemoteDriveScanExecutionOptions(WorkerCount: 1), shouldSkipItem: skip,
            onItemProcessed: processed ?? ((_, _) => { outcome.Processed++; return ValueTask.CompletedTask; }),
            onScanIncomplete: () => outcome.Incomplete = true);
        return outcome;
    }

    internal static DriveItem Item(string id, string name, string? version) => new()
    {
        Id = id,
        Name = name,
        WebUrl = "https://contoso.sharepoint.com/sites/Test/Documents/" + name,
        Size = 6,
        File = new FileObject { MimeType = "text/plain" },
        ETag = version
    };

    internal static GraphServiceClient Graph(Func<HttpRequestMessage, HttpResponseMessage> callback)
        => new(new HttpClient(new Handler(callback)), new StubCredential(), ["https://graph.microsoft.com/.default"]);

    internal static HttpResponseMessage Response(HttpStatusCode status, string body)
        => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage ExpiredResponse() => Response(HttpStatusCode.Gone,
        """{"error":{"code":"resyncChangesApplyDifferences","message":"Mock expired delta"}}""");

    internal sealed class StubCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken)
            => new("mock-token", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult(GetToken(context, cancellationToken));
    }

    internal sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(callback(request));
        }
    }

    private sealed class SingleFileDrive(IRemoteFile file, int count = 1) : IRemoteDrive
    {
        public string Id => "drive";
        public string Name => "Documents";
        public string ConnectionId => "sharepoint://tenant/drive";
        public string WebUrl => "https://contoso.sharepoint.com/sites/Test/Documents";
        public DatastoreType DriveType => DatastoreType.SharePoint;
        public long? TotalSize => null;
        public long? UsedSize => null;
        public Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken ct = default)
            => Task.FromResult(((IEnumerable<IRemoteFile>)[file], "final"));
        public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
            Func<string, Task>? onCheckpoint = null, CancellationToken ct = default)
        {
            for (var index = 0; index < count; index++)
            {
                ct.ThrowIfCancellationRequested();
                await onChange(file);
            }
            if (onCheckpoint != null) await onCheckpoint("next");
            return "final";
        }
    }

    private sealed class TestFile(Func<Stream?> content, string name = "test.txt") : IRemoteFile
    {
        public string Id => "item";
        public string Name => name;
        public string Path => "https://contoso.sharepoint.com/sites/Test/Documents/" + name;
        public string WebUrl => Path;
        public long? Size => 6;
        public string? ContentType => "text/plain";
        public bool IsDeleted => false;
        public bool IsDirectory => false;
        public bool IsLink => false;
        public bool IsExternal => false;
        public Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default) => Task.FromResult(content());
        public Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default) => GetContentAsync(cancellationToken);
    }

    private sealed class TrackingReadStream(byte[] bytes) : Stream
    {
        private readonly MemoryStream _inner = new(bytes);
        public int BytesRead { get; private set; }
        public bool Disposed { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _inner.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await _inner.ReadAsync(buffer, cancellationToken);
            BytesRead += read;
            return read;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) { Disposed = true; _inner.Dispose(); }
            base.Dispose(disposing);
        }
    }

    private sealed class IncompleteConnector : IConnector, IConnectorDiscoveryReportProvider
    {
        public string ProviderName => "Microsoft365";
        public ConnectorDiscoveryReport DiscoveryReport => new("app-only tenant inventory (incomplete)",
            new Dictionary<string, int>(), ["Mock discovery failure"])
        { IsComplete = false };
        public Task InitializeAsync(Dictionary<string, string> config, CancellationToken ct = default) => Task.CompletedTask;
        public Task<IEnumerable<IRemoteDrive>> GetDrivesAsync(CancellationToken ct = default) => Task.FromResult<IEnumerable<IRemoteDrive>>([]);
    }

    internal sealed class ScanOutcome
    {
        public int Scanned;
        public int Processed;
        public bool Incomplete;
        public string? FinalToken;
        public List<string> Checkpoints { get; } = [];
        public List<ScanFinding> Findings { get; } = [];
    }
}
