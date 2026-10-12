using System.IO.Compression;
using System.Formats.Tar;
using System.Net;
using System.Text;
using System.Text.Json;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using Microsoft.Extensions.Configuration;
using Microsoft.Graph.Models;
using OfficeIMO.OneNote;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Models;
using Stratus.Sift.Scanner.Services;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class Microsoft365ExpandedCoverageTests
{
    private const string SiteUrl = "https://contoso.sharepoint.com/sites/Test";
    private static readonly Microsoft365CoverageOptions Enabled = new();
    private static HttpResponseMessage Json(object value) => Response(HttpStatusCode.OK, JsonSerializer.Serialize(value));
    private static HttpResponseMessage Content(string value = "secret") => new(HttpStatusCode.OK) { Content = new StringContent(value) };
    private static SharePointRestClient Rest(Func<HttpRequestMessage, HttpResponseMessage> action) => new(new StubCredential(), "Tests", new HttpClient(new Handler(action)));
    private static Microsoft365CoverageOptions Only(bool lists = false, bool versions = false, bool fields = false,
        bool sharing = false, bool recycle = false, bool subsites = false, bool personal = false)
        => Microsoft365CoverageOptions.Disabled with
        {
            ScanListsAndPages = lists,
            ScanVersions = versions,
            ScanLibraryFields = fields,
            ReadSharing = sharing,
            ScanRecycleBin = recycle,
            RecurseSubsites = subsites,
            DiscoverPersonalDrives = personal
        };

    [Theory]
    [InlineData("Worldwide", "graph.microsoft.com")]
    [InlineData("GccHigh", "graph.microsoft.us")]
    [InlineData("DoD", "dod-graph.microsoft.us")]
    [InlineData("China", "microsoftgraph.chinacloudapi.cn")]
    public void Clouds_UseMatchingServiceAndAuthority(string cloud, string host)
    {
        Assert.Equal(host, Microsoft365Cloud.Resolve(cloud).GraphRoot.Host);
        Assert.Equal(cloud == "Worldwide" ? "login.microsoftonline.com" : cloud == "China" ? "login.chinacloudapi.cn" : "login.microsoftonline.us",
            Microsoft365Cloud.Resolve(cloud).Authority.Host);
    }

    [Fact]
    public void CoverageConfiguration_RejectsInvalidLimitsAndBooleans()
    {
        Assert.True(Microsoft365CoverageOptions.FromConfiguration(new Dictionary<string, string>()).ScanVersions);
        Assert.Throws<ArgumentException>(() => Microsoft365CoverageOptions.FromConfiguration(new Dictionary<string, string> { ["MaxVersionsPerFile"] = "0" }));
        Assert.Throws<ArgumentException>(() => Microsoft365CoverageOptions.FromConfiguration(new Dictionary<string, string> { ["ReadSharing"] = "yes" }));
        Assert.Throws<ArgumentException>(() => Microsoft365Cloud.Resolve("made-up"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Subsites_StopCyclesAndKeepExplicitLibraryTargetsNarrow(bool libraryTarget)
    {
        var expanded = new List<string>();
        var graph = Graph(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/sites/contoso.sharepoint.com:/sites/Test")) return Json(new { id = "root", webUrl = SiteUrl });
            if (path.EndsWith("/drives")) return Json(new { value = new[] { new { id = path.Contains("child") ? "child-drive" : "root-drive", name = "Documents", webUrl = SiteUrl + "/Documents" } } });
            if (path.EndsWith("/sites")) { expanded.Add(path); return Json(new { value = new[] { new { id = path.Contains("root") ? "child" : "root", webUrl = SiteUrl + "/sub" } } }); }
            return new(HttpStatusCode.NotFound);
        });
        var connector = new SharePointConnector(graph, "tenant", useConfiguredTargets: true,
            configuredSiteTargets: [new(SiteUrl + (libraryTarget ? "/Documents" : ""))], coverage: Only(subsites: true));
        var drives = (await connector.GetDrivesAsync()).ToList();
        Assert.True(connector.DiscoveryReport.IsComplete);
        Assert.Equal(libraryTarget ? 1 : 2, drives.Count);
        Assert.Equal(libraryTarget ? 0 : 2, expanded.Count);
    }

    [Fact]
    public async Task ListFields_PageCanvasAndAttachments_AreSeparateSearchableItems()
    {
        var graph = Graph(request => request.RequestUri!.AbsolutePath switch
        {
            "/v1.0/sites/site/lists" => Json(new { value = new[] { new { id = "list", webUrl = SiteUrl + "/Lists/Contacts", list = new { template = "genericList" } } } }),
            "/v1.0/sites/site/lists/list/items" => Json(new { value = new[] { new { id = "1", fields = new { Notes = "sec\u0072et", Attachments = true } } } }),
            "/v1.0/sites/site/pages/microsoft.graph.sitePage" => Json(new { value = new[] { new { id = "page", name = "Home.aspx", webUrl = SiteUrl + "/SitePages/Home.aspx" } } }),
            _ => Json(new { canvasLayout = new { text = "<p>sec<b>re</b>t</p>" } })
        });
        var rest = Rest(request => request.RequestUri!.AbsolutePath.Contains("AttachmentFiles")
            ? Json(new { value = new[] { new { FileName = "secret #100%.txt", ServerRelativeUrl = "/sites/Test/Lists/Contacts/Attachments/1/secret #100%.txt" } } }) : Content());
        var drive = new Microsoft365SiteDataDrive(new(graph), rest, "tenant", "site", new(SiteUrl), Only(lists: true));
        var jsonRule = new Classifier { Name = "Structured", Matches = [new ClassifierMatch { Target = RuleTarget.Content, Patterns = ["secret"], IncludedExtensions = [".json", ".txt"] }] };
        var result = await ScanAsync(drive, classifiers: [jsonRule]);
        Assert.False(result.Incomplete);
        Assert.Equal(3, result.Processed);
        Assert.Equal(3, result.Findings.Count);
        Assert.Contains(result.Findings, finding => finding.ResourcePath.EndsWith("secret%20%23100%25.txt"));
    }

    [Fact]
    public async Task GraphAndNativeVersions_ScanHistoryAndCustomColumns()
    {
        foreach (var native in new[] { false, true })
        {
            IRemoteFile file;
            if (native)
            {
                var rest = Rest(request => request.RequestUri!.AbsolutePath.EndsWith("/Versions")
                    ? Json(new { value = new[] { new { ID = 512, Url = "/_vti_history/512/sites/Test/Documents/test.txt", Size = 6 } } })
                    : request.RequestUri.AbsolutePath.EndsWith("/ListItemAllFields") ? Json(new { Custom = "secret" }) : Content());
                file = new SharePointRestFile(rest, new(SiteUrl), new("file", "test.txt", "/sites/Test/Documents/test.txt",
                    new(SiteUrl + "/Documents/test.txt"), false, false, 6, "v1"), Only(versions: true, fields: true));
            }
            else
            {
                var graph = Graph(request => request.RequestUri!.AbsolutePath.EndsWith("/versions")
                    ? Json(new { value = new[] { new { id = "1.0", size = 6 } } })
                    : request.RequestUri.AbsolutePath.EndsWith("/listItem") ? Json(new { fields = new { Custom = "secret" } }) : Content());
                file = new SharePointFile(graph, "drive", Item("file", "test.txt", "v1"), "tenant", false, Only(versions: true, fields: true));
            }
            var rule = new Classifier { Name = "Content", Matches = [new ClassifierMatch { Target = RuleTarget.Content, Patterns = ["secret"], IncludedExtensions = [".txt", ".json"] }] };
            var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), classifiers: [rule]);
            Assert.False(result.Incomplete);
            Assert.Equal(3, result.Processed);
            Assert.Equal(3, result.Findings.Count);
            Assert.Contains(result.Findings, finding => finding.ResourcePath.Contains("#sift-version="));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SharingFailure_PreservesContentAndCannotUseOldResumeRecord(bool denied)
    {
        var graph = Graph(request => request.RequestUri!.AbsolutePath.EndsWith("/permissions")
            ? denied ? Response(HttpStatusCode.Forbidden, "{}") : Json(new { value = new[] { new { id = "p", roles = new[] { "read" }, link = new { scope = "anonymous" } } } })
            : Content());
        var file = new SharePointFile(graph, "drive", Item("file", "test.txt", "v1"), "tenant", false, Only(sharing: true));
        var skipCalls = 0;
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), skip: _ => { skipCalls++; return denied; });
        Assert.Equal(denied, result.Incomplete);
        Assert.Equal(denied ? 0 : 1, skipCalls);
        Assert.Equal(denied ? "Unknown" : "Public", Assert.Single(result.Findings).Exposure);
        Assert.Equal(denied ? 0 : 1, result.Processed);
    }

    [Fact]
    public async Task HistoricalEnumerationFailure_PreservesCurrentFileAndLeavesSourcePending()
    {
        var graph = Graph(request => request.RequestUri!.AbsolutePath.EndsWith("/versions") ? Response(HttpStatusCode.Forbidden, "{}") : Content());
        var file = new SharePointFile(graph, "drive", Item("file", "test.txt", "v1"), "tenant", false, Only(versions: true));
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file));
        Assert.True(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.Null(result.FinalToken);
    }

    [Fact]
    public async Task RecycleBin_ReportsMetadataOnlyInsteadOfClaimingContentWasScanned()
    {
        var rest = Rest(_ => Json(new { value = new[] { new { Id = "deleted", DirName = "sites/Test/Documents", LeafName = "secret.txt" } } }));
        var drive = new Microsoft365SiteDataDrive(null, rest, "tenant", "site", new(SiteUrl), Only(recycle: true));
        var result = await ScanAsync(drive, extension: ".json");
        Assert.True(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.Equal(0, result.Processed);
    }

    [Theory]
    [InlineData(".tar")]
    [InlineData(".gz")]
    [InlineData(".tgz")]
    public async Task NonZipArchives_InspectTextIncludingMixedNestedContainers(string extension)
    {
        var content = Encoding.UTF8.GetBytes("secret");
        byte[] tar;
        using (var buffer = new MemoryStream())
        {
            using (var writer = new TarWriter(buffer, leaveOpen: true)) writer.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "test.txt") { DataStream = new MemoryStream(content) });
            tar = buffer.ToArray();
        }
        byte[] bytes = tar;
        if (extension != ".tar")
        {
            using var buffer = new MemoryStream();
            using (var writer = new GZipStream(buffer, CompressionLevel.Fastest, true)) writer.Write(extension == ".gz" ? content : tar);
            bytes = buffer.ToArray();
        }
        var name = extension == ".gz" ? "test.txt.gz" : "test" + extension;
        var file = Microsoft365ContentFile.Text("placeholder", name, SiteUrl + "/" + name, "unused");
        file = new("archive", name, SiteUrl + "/" + name, "v1", bytes.Length, (_, _) => Task.FromResult<Stream?>(new MemoryStream(bytes)));
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), options: new ScanOptions { EnableZipArchives = true });
        Assert.False(result.Incomplete);
        Assert.Contains("!/", Assert.Single(result.Findings).ResourcePath);
    }

    [Theory]
    [InlineData("7Zip.Copy.7z")]
    [InlineData("Rar.rar")]
    public async Task IndependentArchiveFixtures_AreReadable(string name)
    {
        var bytes = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "Coverage", name));
        var file = new Microsoft365ContentFile("archive", name, SiteUrl + "/" + name, "v1", bytes.Length,
            (_, _) => Task.FromResult<Stream?>(new MemoryStream(bytes)));
        var rule = new Classifier { Name = "Entry", Matches = [new ClassifierMatch { Target = RuleTarget.FileName, Patterns = [".*"] }] };
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), options: new ScanOptions { EnableZipArchives = true }, classifiers: [rule]);
        Assert.False(result.Incomplete);
        Assert.Contains(result.Findings, finding => finding.ResourcePath.Contains("!/"));
    }

    [Theory]
    [InlineData(".tar")]
    [InlineData(".rar")]
    [InlineData(".7z")]
    [InlineData(".gz")]
    public async Task CorruptArchives_NeverComplete(string extension)
    {
        var file = Microsoft365ContentFile.Text("file", "file" + extension, SiteUrl + "/file" + extension, "invalid");
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), options: new ScanOptions { EnableZipArchives = true });
        Assert.True(result.Incomplete);
        Assert.Equal(0, result.Processed);
    }

    [Theory]
    [InlineData("10x10.xlsb", true)]
    [InlineData("BoolFormula.xlsb", false)]
    public void IndependentXlsbFixtures_ExtractCellsAndReportUninspectedFormulaExpressions(string name, bool complete)
    {
        var result = new ContentExtractor().ExtractWithResult(Path.Combine(AppContext.BaseDirectory, "Fixtures", "Coverage", name));
        Assert.Equal(complete, result.IsComplete);
        Assert.NotEmpty(result.Text);
    }

    [Fact]
    public void OfficeAndOneNote_InspectEmbeddedTextWithSharedLimits()
    {
        using var word = new MemoryStream();
        using (var document = WordprocessingDocument.Create(word, WordprocessingDocumentType.Document))
        {
            var main = document.AddMainDocumentPart();
            main.Document = new DocumentFormat.OpenXml.Wordprocessing.Document(new DocumentFormat.OpenXml.Wordprocessing.Body());
            var part = main.AddEmbeddedPackagePart("text/plain");
            part.FeedData(new MemoryStream(Encoding.UTF8.GetBytes("embedded-secret")));
        }
        word.Position = 0;
        var result = new ContentExtractor().ExtractWithResult(word, ".docx");
        Assert.True(result.IsComplete, result.Error);
        Assert.Contains("embedded-secret", result.Text);
        var section = new OneNoteSection { Name = "Test" };
        var page = new OneNotePage { Title = "Page" };
        page.DirectContent.Add(new OneNoteEmbeddedFile { FileName = "test.txt", Payload = OneNoteBinaryPayload.FromBytes(Encoding.UTF8.GetBytes("embedded-secret")) });
        section.Pages.Add(page);
        using var bytes = new MemoryStream(section.ToByteArray());
        result = new ContentExtractor().ExtractWithResult(bytes, ".one");
        Assert.True(result.IsComplete, result.Error);
        Assert.Contains("embedded-secret", result.Text);
    }

    [Fact]
    public void OcrMissingRuntime_IsPartialAndConfigurationChangesInvalidateResume()
    {
        var settings = new ConfigurationBuilder().Build();
        var options = new ScanOptions { EnableBinaryDocuments = true };
        CliContentOptions.Apply(options, settings, new Dictionary<string, string> { ["TesseractPath"] = "missing-sift-ocr-runtime", ["MaxDocumentMiB"] = "30" });
        using var image = new MemoryStream([1, 2, 3]);
        var result = new ContentExtractor().ExtractWithResult(image, ".png", options);
        Assert.False(result.IsComplete);
        Assert.Contains("OCR", result.Error!);
        var first = CliResumeIdentity.CreateConnectorScope("Microsoft365", new Dictionary<string, string>(), "tenant", "rules", true, null, options);
        options.MaxExtractedCharacters++;
        Assert.NotEqual(first, CliResumeIdentity.CreateConnectorScope("Microsoft365", new Dictionary<string, string>(), "tenant", "rules", true, null, options));
    }

    [Fact]
    public async Task Reader_StopsRepeatedAndForeignOriginContinuationLinks()
    {
        foreach (var url in new[] { "https://graph.microsoft.com/v1.0/items", "https://other.example/items" })
        {
            var calls = 0;
            var reader = new Microsoft365GraphReader(Graph(_ => { calls++; return Response(HttpStatusCode.OK, "{\"value\":[],\"@odata.nextLink\":\"" + url + "\"}"); }));
            await Assert.ThrowsAsync<InvalidDataException>(async () => { await foreach (var _ in reader.EnumerateAsync("items", CancellationToken.None)) { } });
            Assert.Equal(1, calls);
        }
    }

    [Theory]
    [InlineData(true, 404, true)]
    [InlineData(true, 403, false)]
    [InlineData(false, 200, true)]
    public async Task PersonalDrives_DiscoverOwnOrReconcileUsersAndReportFailures(bool delegated, int status, bool complete)
    {
        var requests = new List<string>();
        var graph = Graph(request =>
        {
            var path = request.RequestUri!.AbsolutePath; requests.Add(path);
            if (path.EndsWith("/drive")) return status == 200 ? Json(new { id = "personal", name = "OneDrive", webUrl = "https://contoso-my.sharepoint.com/personal/user/Documents" }) : Response((HttpStatusCode)status, "{}");
            if (path.EndsWith("/users")) return Json(new { value = new[] { new { id = "user" }, new { id = "user" } } });
            return Json(new { value = Array.Empty<object>() });
        });
        var connector = new SharePointConnector(graph, "tenant", useConfiguredTargets: delegated, coverage: Only(personal: true));
        var drives = (await connector.GetDrivesAsync()).ToList();
        Assert.Equal(complete, connector.DiscoveryReport.IsComplete);
        Assert.Equal(1, requests.Count(path => path.EndsWith("/drive")));
        if (status == 200) Assert.Equal(DatastoreType.OneDrive, Assert.Single(drives).DriveType);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DelegatedPermissionSubset_CannotClaimCompleteExposureWithoutNativeReconciliation(bool native)
    {
        var rest = Rest(request => request.RequestUri!.AbsolutePath.EndsWith("/RoleAssignments")
            ? Json(new { value = new[] { new { Member = new { Id = 8, LoginName = "SharingLinks.file.AnonymousView", PrincipalType = 8 }, RoleDefinitionBindings = new[] { new { Name = "Read" } } } } })
            : request.RequestUri.AbsolutePath.EndsWith("/users") ? Json(new { value = Array.Empty<object>() }) : Json(new { Author = new { Title = "Alice", EMail = "alice@stratus.security" }, HasUniqueRoleAssignments = false }));
        var graph = Graph(request => request.RequestUri!.AbsolutePath.EndsWith("/permissions") ? Json(new { value = Array.Empty<object>() }) : Content());
        var coverage = Only(sharing: true) with { GraphPermissionsAreComplete = false, NativeClient = native ? rest : null, NativeSiteUrl = new(SiteUrl) };
        var file = new SharePointFile(graph, "drive", Item("file", "test.txt", "v1"), "tenant", false, coverage);
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file));
        Assert.Equal(!native, result.Incomplete);
        Assert.Equal(native ? "Public" : "Unknown", Assert.Single(result.Findings).Exposure);
        if (native) Assert.Equal("alice@stratus.security", result.Findings[0].Owner);
    }

    [Fact]
    public async Task NativeSharingGroups_AreClassifiedOnceAndGuestAccessChangesVersion()
    {
        var reads = 0; var guest = false;
        var rest = Rest(request => request.RequestUri!.AbsolutePath.EndsWith("/RoleAssignments")
            ? Json(new { value = new[] { new { Member = new { Id = 8, LoginName = "Members", PrincipalType = 8 }, RoleDefinitionBindings = new[] { new { Name = "Read" } } } } })
            : request.RequestUri.AbsolutePath.EndsWith("/users") ? Group() : Json(new { Author = new { Title = "Alice" }, HasUniqueRoleAssignments = false }));
        HttpResponseMessage Group() { reads++; return Json(new { value = new[] { new { LoginName = guest ? "guest#EXT#" : "member", IsEmailAuthenticationGuestUser = guest, IsShareByEmailGuestUser = false } } }); }
        var first = await Microsoft365NativeAccessReader.ReadAsync(rest, new(SiteUrl), "web/list", Only(sharing: true), CancellationToken.None);
        var second = await Microsoft365NativeAccessReader.ReadAsync(rest, new(SiteUrl), "web/list", Only(sharing: true), CancellationToken.None);
        Assert.Equal(1, reads);
        Assert.Equal("Restricted", first.Exposure);
        Assert.Equal(first.Fingerprint, second.Fingerprint);
        guest = true; Microsoft365NativeAccessReader.Reset(rest);
        var changed = await Microsoft365NativeAccessReader.ReadAsync(rest, new(SiteUrl), "web/list", Only(sharing: true), CancellationToken.None);
        Assert.Equal("External", changed.Exposure);
        Assert.NotEqual(first.Fingerprint, changed.Fingerprint);
        Assert.True(Assert.Single(changed.Acls).IsInherited);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SharedSearch_RepeatedHitsStopAndFailedHitsPreserveOtherFiles(bool denyFirst)
    {
        var pages = 0;
        var graph = Graph(request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                pages++;
                return Json(new
                {
                    value = new[] { new { hitsContainers = new[] { new { moreResultsAvailable = !denyFirst,
                    hits = new[] { new { resource = new { id = "first", parentReference = new { driveId = "drive" } } }, new { resource = new { id = "second", parentReference = new { driveId = "drive" } } } } } } } }
                });
            }
            if (request.RequestUri!.AbsolutePath.EndsWith("/first") && denyFirst) return Response(HttpStatusCode.Forbidden, "{}");
            if (request.RequestUri.AbsolutePath.EndsWith("/content")) return Content();
            var id = request.RequestUri.Segments.Last();
            return Json(new { id, name = id + ".txt", size = 6, eTag = "actual", webUrl = SiteUrl + "/" + id + ".txt", file = new { } });
        });
        var result = new ScanOutcome();
        await Assert.ThrowsAnyAsync<Exception>(() => ScanAsync(new Microsoft365SharedSearchDrive(graph, "tenant", Microsoft365CoverageOptions.Disabled), outcome: result));
        Assert.Equal(denyFirst ? 1 : 2, result.Findings.Count);
        Assert.Equal(denyFirst ? 1 : 2, pages);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SupplementalFailure_StillInspectsOtherContentAndDoesNotCommitSource(bool fieldsFail)
    {
        var graph = Graph(request => request.RequestUri!.AbsolutePath.EndsWith("/listItem")
            ? fieldsFail ? Response(HttpStatusCode.Forbidden, "{}") : Json(new { fields = new { Custom = "secret" } })
            : request.RequestUri.AbsolutePath.EndsWith("/versions") ? Json(new { value = new[] { new { id = "1" }, new { id = "2" } } }) : Content());
        var file = new SharePointFile(graph, "drive", Item("file", "test.txt", "v1"), "tenant", false,
            Only(fields: true, versions: true) with { MaxVersionsPerFile = 1 });
        var rule = new Classifier { Name = "Content", Matches = [new ClassifierMatch { Target = RuleTarget.Content, Patterns = ["secret"], IncludedExtensions = [".txt", ".json"] }] };
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), classifiers: [rule]);
        Assert.True(result.Incomplete);
        Assert.Equal(fieldsFail ? 2 : 3, result.Findings.Count);
        Assert.Null(result.FinalToken);
    }

    [Fact]
    public async Task StructuredFields_AreFullyScannedDespiteOrdinaryTextHeadLimit()
    {
        var file = Microsoft365ContentFile.Text("fields", "list.json", SiteUrl + "/list", new string('x', 4096) + " secret");
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), extension: ".json",
            options: new ScanOptions { MaxFileSize = 16, HeadSize = 16 });
        Assert.False(result.Incomplete);
        Assert.Single(result.Findings);
    }

    [Theory]
    [InlineData("GccHigh")]
    [InlineData("DoD")]
    [InlineData("China")]
    public async Task SovereignDiscovery_UsesConfiguredServiceRootForEveryRequest(string cloud)
    {
        var root = Microsoft365Cloud.Resolve(cloud).GraphRoot;
        var requests = new List<Uri>();
        var graph = Stratus.Sift.Connectors.Services.MicrosoftGraphClientBuilder.Create(new StubCredential(), "Tests", null,
            new Handler(request => { requests.Add(request.RequestUri!); Assert.NotNull(request.Headers.Authorization); return Json(new { value = Array.Empty<object>() }); }),
            null, null, root);
        var connector = new SharePointConnector(graph, "tenant");
        Assert.Empty(await connector.GetDrivesAsync());
        Assert.All(requests, request => Assert.Equal(root.Host, request.Host));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MalformedEmbeddedContainers_PreserveOuterDocumentText(bool compound)
    {
        using var bytes = new MemoryStream();
        using (var document = WordprocessingDocument.Create(bytes, WordprocessingDocumentType.Document))
        {
            var main = document.AddMainDocumentPart();
            main.Document = new DocumentFormat.OpenXml.Wordprocessing.Document(new DocumentFormat.OpenXml.Wordprocessing.Body(
                new DocumentFormat.OpenXml.Wordprocessing.Paragraph(new DocumentFormat.OpenXml.Wordprocessing.Run(new DocumentFormat.OpenXml.Wordprocessing.Text("outer-secret")))));
            var part = main.AddEmbeddedObjectPart("application/octet-stream");
            part.FeedData(new MemoryStream(compound ? new byte[] { 208, 207, 17, 224, 161, 177, 26, 225 } : "PKbroken"u8.ToArray()));
        }
        var result = new ContentExtractor().ExtractWithResult(bytes, ".docx");
        Assert.False(result.IsComplete);
        Assert.Contains("outer-secret", result.Text);
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(3, true)]
    public void NestedOneNoteArchive_AttachmentsShareDepthLimits(int maximumDepth, bool complete)
    {
        using var zip = new MemoryStream();
        using (var archive = new ZipArchive(zip, ZipArchiveMode.Create, true))
        using (var entry = archive.CreateEntry("test.txt").Open()) entry.Write("embedded-secret"u8);
        var section = new OneNoteSection { Name = "Test" };
        var page = new OneNotePage { Title = "Page" };
        page.DirectContent.Add(new OneNoteEmbeddedFile { FileName = "test.zip", Payload = OneNoteBinaryPayload.FromBytes(zip.ToArray()) });
        section.Pages.Add(page);
        using var source = new MemoryStream(section.ToByteArray());
        var result = new ContentExtractor().ExtractWithResult(source, ".one", new ScanOptions { MaxEmbeddedDocumentDepth = maximumDepth });
        Assert.Equal(complete, result.IsComplete);
        if (complete) Assert.Contains("embedded-secret", result.Text);
    }

    [Theory]
    [InlineData("_vti_history/512/Documents/file%20%23100%25.txt", "/sites/Test/_vti_history/512/Documents/file%20%23100%25.txt")]
    [InlineData("/_vti_history/512/Documents/file #100%.txt", "/_vti_history/512/Documents/file%20%23100%25.txt")]
    public async Task NativeHistory_ResolvesWebRelativeUrlsAndPreservesFilenameCharacters(string path, string expected)
    {
        var client = Rest(request => { Assert.Equal(expected, request.RequestUri!.AbsolutePath); Assert.Empty(request.RequestUri.Fragment); return Content(); });
        using var stream = await client.OpenHistoricalContentAsync(new(SiteUrl), path, null, CancellationToken.None);
        Assert.NotNull(stream);
        await Assert.ThrowsAsync<InvalidDataException>(() => client.OpenHistoricalContentAsync(new(SiteUrl), "https://other.example/file", null, CancellationToken.None));
    }

    [Theory]
    [InlineData("read")]
    [InlineData("owner")]
    public async Task GuestPrincipals_IncludeGuestOwners(string role)
    {
        var graph = Graph(request => request.RequestUri!.AbsolutePath.EndsWith("/permissions")
            ? Json(new { value = new[] { new { id = "grant", roles = new[] { role }, grantedToV2 = new { user = new { id = "guest", displayName = "Guest" } } } } })
            : request.RequestUri.AbsolutePath.EndsWith("/guest") ? Json(new { id = "guest", userType = "Guest" }) : Content());
        var file = new SharePointFile(graph, "drive", Item("file", "test.txt", "v1"), "tenant", false, Only(sharing: true));
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file));
        Assert.False(result.Incomplete);
        Assert.Equal("External", Assert.Single(result.Findings).Exposure);
    }

    [Fact]
    public void XlsbBinaryComments_KeepCellFindingsAndReportIncompleteContent()
    {
        using var source = new MemoryStream();
        source.Write(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "Coverage", "10x10.xlsb")));
        using (var archive = new ZipArchive(source, ZipArchiveMode.Update, true))
            using (var comments = archive.CreateEntry("xl/comments1.bin").Open()) comments.Write("opaque-comment"u8);
        var result = new ContentExtractor().ExtractWithResult(source, ".xlsb");
        Assert.False(result.IsComplete);
        Assert.NotEmpty(result.Text);
        Assert.Contains("binary comments", result.Error!);
    }

    [Fact]
    public async Task Microsoft365OwnerGroupClaims_InspectOwnersInsteadOfAllMembers()
    {
        var graph = Graph(request =>
        {
            Assert.Contains("/owners/microsoft.graph.user", request.RequestUri!.AbsolutePath);
            return Json(new { value = new[] { new { id = "guest", userType = "Guest" } } });
        });
        using var principal = JsonDocument.Parse("{\"PrincipalType\":4,\"LoginName\":\"c:0o.c|federateddirectoryclaimprovider|11111111-1111-1111-1111-111111111111_o\"}");
        Assert.True(await Microsoft365NativeAccessReader.IsGuestAsync(principal.RootElement,
            Only(sharing: true) with { GraphClient = graph }, CancellationToken.None));
    }
}
