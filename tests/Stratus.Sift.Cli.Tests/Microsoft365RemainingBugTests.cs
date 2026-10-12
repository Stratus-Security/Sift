using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Graph.Models;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Models;
using Stratus.Sift.Scanner.Services;
using W = DocumentFormat.OpenXml.Wordprocessing;
using S = DocumentFormat.OpenXml.Spreadsheet;
using P = DocumentFormat.OpenXml.Presentation;
using A = DocumentFormat.OpenXml.Drawing;

namespace Stratus.Sift.Cli.Tests;

public sealed class Microsoft365RemainingBugTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InternalShortcut_ResolvesTargetAndUsesItsIdentityAndVersion(bool missingDeclaredTenant)
    {
        var contentRequests = 0;
        var targetRequests = 0;
        var drive = GraphDrive(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.Contains("/delta", StringComparison.Ordinal)) return Delta([Link("link", "target", "backing", missingDeclaredTenant ? null : "tenant")]);
            if (path.EndsWith("/content")) { contentRequests++; Assert.Contains("/backing/items/target/", path); return Text(); }
            targetRequests++;
            return Json(File("target", "secret.txt", "v2", "tenant"));
        });
        IRemoteFile? processed = null;
        var result = await Microsoft365ReliabilityTests.ScanAsync(drive,
            processed: (file, _) => { processed = file; return ValueTask.CompletedTask; });

        Assert.False(result.Incomplete);
        Assert.Equal(1, targetRequests);
        Assert.Equal(1, contentRequests);
        Assert.Equal("v2", processed!.Version);
        Assert.Equal("7:backingtarget", processed.ResumeIdentity);
        Assert.Equal("Internal", Assert.Single(result.Findings).Exposure);
        Assert.Equal(string.Empty, result.FinalToken);
        Assert.Empty(result.Checkpoints);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExternalFolderShortcut_RequiresOptInAndTraversesTargetChildren(bool includeExternal)
    {
        var targetRequests = 0;
        var drive = GraphDrive(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.Contains("/delta", StringComparison.Ordinal)) return Delta([Link("link", "folder", "external", "other")]);
            targetRequests++;
            if (path.EndsWith("/children")) return Json(new { value = new[] { File("file", "secret.txt", "v1", "other") } });
            if (path.EndsWith("/content")) return Text();
            return Json(Folder("folder", "other"));
        });
        var result = await Microsoft365ReliabilityTests.ScanAsync(drive, options: new ScanOptions { ScanExternalFiles = includeExternal });

        Assert.False(result.Incomplete);
        if (includeExternal)
        {
            Assert.Equal(3, targetRequests);
            Assert.Equal("External", Assert.Single(result.Findings).Exposure);
            Assert.Equal(string.Empty, result.FinalToken);
        }
        else
        {
            Assert.Equal(0, targetRequests);
            Assert.Empty(result.Findings);
            Assert.Equal("final", result.FinalToken);
        }
    }

    [Theory]
    [InlineData("other")]
    [InlineData(null)]
    public async Task UnknownShortcutTenant_IsResolvedButDoesNotDownloadExternalOrUnclassifiedTargets(string? targetTenant)
    {
        var requests = 0;
        var drive = GraphDrive(request =>
        {
            if (request.RequestUri!.AbsolutePath.Contains("/delta", StringComparison.Ordinal)) return Delta([Link("link", "target", "backing", null)]);
            requests++;
            Assert.DoesNotContain("/content", request.RequestUri.AbsolutePath);
            return Json(File("target", "secret.txt", "v1", targetTenant));
        });
        var result = await Microsoft365ReliabilityTests.ScanAsync(drive);
        Assert.Equal(1, requests);
        Assert.Empty(result.Findings);
        Assert.False(result.Incomplete);
        Assert.Equal("final", result.FinalToken);
    }

    [Fact]
    public async Task FolderShortcuts_DeduplicateTargetsAndStopCyclesAcrossPagedNestedChildren()
    {
        var folderPages = 0;
        var downloads = 0;
        var drive = GraphDrive(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.Contains("/delta", StringComparison.Ordinal)) return Delta([Link("first", "folder", "backing"), Link("second", "folder", "backing")]);
            if (path.EndsWith("/content")) { downloads++; return Text(); }
            if (path.EndsWith("/folder/children"))
            {
                folderPages++;
                return request.RequestUri.Query.Contains("page=2", StringComparison.Ordinal)
                    ? Json(new { value = new object[] { Link("cycle", "folder", "backing"), Folder("nested") } })
                    : Json(new Dictionary<string, object>
                    {
                        ["value"] = new[] { File("file", "secret.txt", "v1") },
                        ["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/drives/backing/items/folder/children?page=2"
                    });
            }
            if (path.EndsWith("/nested/children")) return Json(new { value = new[] { File("file", "secret.txt", "v1"), File("other", "second.txt", "v1") } });
            return Json(Folder("folder"));
        });
        var result = await Microsoft365ReliabilityTests.ScanAsync(drive);
        Assert.False(result.Incomplete);
        Assert.Equal(2, folderPages);
        Assert.Equal(2, downloads);
        Assert.Equal(2, result.Findings.Count);
        Assert.Equal(string.Empty, result.FinalToken);
    }

    [Fact]
    public async Task Resume_RevisitsUnchangedShortcutsAndSkipsOnlyUnchangedTargetVersions()
    {
        var version = "v1";
        var downloads = 0;
        var lookups = 0;
        var drive = GraphDrive(request =>
        {
            if (request.RequestUri!.AbsolutePath.Contains("/delta", StringComparison.Ordinal)) return Delta([Link("link", "target", "backing")]);
            if (request.RequestUri.AbsolutePath.EndsWith("/content")) { downloads++; return Text(); }
            lookups++;
            return Json(File("target", "secret.txt", version));
        });
        var completed = new HashSet<(string, string?)>();
        for (var run = 0; run < 3; run++)
        {
            if (run == 1) version = "v2";
            var result = await Microsoft365ReliabilityTests.ScanAsync(drive,
                skip: item => completed.Contains((item.ResumeIdentity, item.Version)),
                processed: (item, _) => { completed.Add((item.ResumeIdentity, item.Version)); return ValueTask.CompletedTask; });
            Assert.False(result.Incomplete);
            Assert.Equal(string.Empty, result.FinalToken);
            Assert.Equal(run == 2 ? 0 : 1, result.Findings.Count);
        }
        Assert.Equal(3, lookups);
        Assert.Equal(2, downloads);
    }

    [Fact]
    public async Task SameItemIdInDifferentBackingDrives_DoesNotCollideDuringResumeOrDeduplication()
    {
        var identities = new HashSet<string>();
        var drive = GraphDrive(request => request.RequestUri!.AbsolutePath.Contains("/delta", StringComparison.Ordinal)
            ? Delta([Link("a", "target", "first"), Link("b", "target", "second")])
            : request.RequestUri.AbsolutePath.EndsWith("/content") ? Text() : Json(File("target", "secret.txt", "v1")));
        var result = await Microsoft365ReliabilityTests.ScanAsync(drive,
            processed: (item, _) => { identities.Add(item.ResumeIdentity); return ValueTask.CompletedTask; });
        Assert.Equal(2, identities.Count);
        Assert.Equal(2, result.Findings.Count);
    }

    [Theory]
    [InlineData("forbidden")]
    [InlineData("malformed")]
    [InlineData("repeated")]
    [InlineData("foreign")]
    [InlineData("badTarget")]
    [InlineData("noFacet")]
    public async Task FailedShortcutTraversal_RetainsOtherFindingsAndBlocksCheckpoints(string failure)
    {
        var drive = GraphDrive(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.Contains("/delta", StringComparison.Ordinal)) return Delta([Link("link", "folder", "backing"), File("ordinary", "secret.txt", "v1")]);
            if (path.EndsWith("/content")) return Text();
            if (path.EndsWith("/children")) return failure switch
            {
                "forbidden" => Microsoft365ReliabilityTests.Response(HttpStatusCode.Forbidden, "{\"error\":{\"code\":\"accessDenied\"}}"),
                "malformed" => Json(new { value = new[] { new { name = "unidentified.txt" } } }),
                "noFacet" => Json(new { value = new[] { new { id = "child", name = "secret.txt" } } }),
                _ => Json(new Dictionary<string, object>
                {
                    ["value"] = Array.Empty<object>(),
                    ["@odata.nextLink"] = failure == "foreign"
                    ? "https://example.invalid/children" : "https://graph.microsoft.com/v1.0/drives/backing/items/folder/children?page=2"
                })
            };
            return failure == "badTarget" ? Json(new { id = "folder", folder = new { } }) : Json(Folder("folder"));
        });
        var result = await Microsoft365ReliabilityTests.ScanAsync(drive);
        Assert.True(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.Equal(1, result.Scanned);
        Assert.Null(result.FinalToken);
        Assert.Empty(result.Checkpoints);
    }

    [Fact]
    public async Task UnboundedShortcutChain_IsStoppedAndRemainsPending()
    {
        var requests = 0;
        var drive = GraphDrive(request =>
        {
            if (request.RequestUri!.AbsolutePath.Contains("/delta", StringComparison.Ordinal)) return Delta([Link("link", "target0", "backing")]);
            var id = request.RequestUri.AbsolutePath.Split('/').Last();
            var index = int.Parse(id[6..], System.Globalization.CultureInfo.InvariantCulture);
            requests++;
            return Json(Link(id, "target" + (index + 1), "backing"));
        });
        var result = await Microsoft365ReliabilityTests.ScanAsync(drive);
        Assert.True(result.Incomplete);
        Assert.InRange(requests, 1, 128);
        Assert.Null(result.FinalToken);
    }

    [Fact]
    public async Task ExcludedExternalShortcuts_DoNotConsumeTheFollowedLinkBudget()
    {
        var enumerated = 0;
        var drive = GraphDrive(request =>
        {
            Assert.Contains("/delta", request.RequestUri!.AbsolutePath);
            var count = Math.Min(999, 10_001 - enumerated);
            var links = Enumerable.Range(enumerated, count).Select(index => Link("link" + index, "target", "external", "other")).ToArray();
            enumerated += count;
            var response = new Dictionary<string, object> { ["value"] = links };
            response[enumerated == 10_001 ? "@odata.deltaLink" : "@odata.nextLink"] = enumerated == 10_001
                ? "final" : "https://graph.microsoft.com/v1.0/drives/source/root/delta?page=" + enumerated;
            return Json(response);
        });
        var result = await Microsoft365ReliabilityTests.ScanAsync(drive);
        Assert.Equal(10_001, enumerated);
        Assert.False(result.Incomplete);
        Assert.Equal("final", result.FinalToken);
    }

    [Fact]
    public async Task CancellationDuringShortcutTraversal_PropagatesWithoutCommitting()
    {
        using var cancellation = new CancellationTokenSource();
        var drive = GraphDrive(request =>
        {
            if (request.RequestUri!.AbsolutePath.Contains("/delta", StringComparison.Ordinal)) return Delta([Link("link", "folder", "backing")]);
            if (request.RequestUri.AbsolutePath.EndsWith("/children")) cancellation.Cancel();
            return Json(Folder("folder"));
        });
        var outcome = new Microsoft365ReliabilityTests.ScanOutcome();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Microsoft365ReliabilityTests.ScanAsync(
            drive, cancellationToken: cancellation.Token, outcome: outcome));
        Assert.Null(outcome.FinalToken);
        Assert.Empty(outcome.Checkpoints);
    }

    [Fact]
    public async Task ExpiredDelta_ResetsShortcutTraversalAndAbandonedFailuresBeforeFreshCrawl()
    {
        var rootRequests = 0;
        var targetRequests = 0;
        var drive = GraphDrive(request =>
        {
            if (request.RequestUri!.Query.Contains("expired", StringComparison.Ordinal))
                return Microsoft365ReliabilityTests.Response(HttpStatusCode.Gone,
                    "{\"error\":{\"code\":\"resyncChangesApplyDifferences\"}}");
            if (request.RequestUri.AbsolutePath.Contains("/delta", StringComparison.Ordinal))
            {
                rootRequests++;
                return rootRequests == 1 ? Json(new Dictionary<string, object>
                {
                    ["value"] = new[] { Link("link", "target", "backing") },
                    ["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/drives/source/root/delta?expired=true"
                })
                    : Delta([Link("link", "target", "backing")]);
            }
            if (request.RequestUri.AbsolutePath.EndsWith("/content")) return Text();
            return ++targetRequests == 1 ? Microsoft365ReliabilityTests.Response(HttpStatusCode.Forbidden,
                "{\"error\":{\"code\":\"accessDenied\"}}") : Json(File("target", "secret.txt", "v1"));
        });
        var result = await Microsoft365ReliabilityTests.ScanAsync(drive);
        Assert.Equal(2, rootRequests);
        Assert.Equal(2, targetRequests);
        Assert.False(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.Equal([string.Empty], result.Checkpoints);
        Assert.Equal(string.Empty, result.FinalToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RestSearch_LaterPageFailurePreservesPreviouslyDiscoveredLibraries(bool malformedContinuation)
    {
        var searches = 0;
        var libraries = 0;
        var client = RestClient(request =>
        {
            if (request.RequestUri!.AbsoluteUri.Contains("/search/query?", StringComparison.Ordinal))
            {
                searches++;
                return searches == 1 ? Search(1, 500) : malformedContinuation ? Json(new { })
                    : Microsoft365ReliabilityTests.Response(HttpStatusCode.BadRequest, "{\"error\":{\"message\":\"Mock failure\"}}");
            }
            Interlocked.Increment(ref libraries);
            var site = request.RequestUri.AbsolutePath.Split('/')[2];
            return Json(new
            {
                value = new[] { new { Id = site, Title = "Documents", BaseType = 1,
                RootFolder = new { ServerRelativeUrl = "/sites/" + site + "/Documents" } } }
            });
        });
        var connector = new SharePointConnector(client, "tenant", new Uri("https://contoso.sharepoint.com"));
        var drives = (await connector.GetDrivesAsync()).ToArray();
        Assert.Equal(2, searches);
        Assert.Equal(500, libraries);
        Assert.Equal(500, drives.Length);
        Assert.Equal(500, connector.DiscoveryReport.SourceCounts["SharePoint search sites"]);
        Assert.False(connector.DiscoveryReport.IsComplete);
    }

    [Fact]
    public async Task RestSearch_SeeksBeyondFiftyThousandResultsWithoutStartRow()
    {
        var requests = 0;
        var client = RestClient(request =>
        {
            var url = Uri.UnescapeDataString(request.RequestUri!.AbsoluteUri);
            Assert.DoesNotContain("startrow", url, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("sortlist='docid:ascending'", url);
            if (requests > 0) Assert.Contains("IndexDocId>" + (requests * 500) + " AND", url);
            var first = requests++ * 500 + 1;
            return Search(first, first <= 50_500 ? 500 : 1);
        });
        var sites = await client.SearchAccessibleSitesAsync(new Uri("https://contoso.sharepoint.com"), CancellationToken.None);
        Assert.Equal(50_501, sites.Count);
        Assert.Equal(102, requests);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("repeated")]
    [InlineData("descending")]
    public async Task RestSearch_InvalidCursorPreservesRowsAndStopsPaging(string invalid)
    {
        var requests = 0;
        var discovered = new List<SharePointRestClient.RestSite>();
        var client = RestClient(_ =>
        {
            requests++;
            return Search(1, 500, invalid);
        });
        await Assert.ThrowsAsync<InvalidDataException>(() => client.SearchAccessibleSitesAsync(
            new Uri("https://contoso.sharepoint.com"), CancellationToken.None, discovered.Add));
        Assert.Equal(500, discovered.Count);
        Assert.Equal(1, requests);
    }

    [Fact]
    public async Task RestSearch_FilteredPageStillAdvancesByRawDocId()
    {
        var requests = 0;
        var client = RestClient(request =>
        {
            if (requests++ == 0) return Search(1, 500, contentStorage: true);
            Assert.Contains("IndexDocId>500", Uri.UnescapeDataString(request.RequestUri!.AbsoluteUri));
            return Search(501, 1);
        });
        Assert.Single(await client.SearchAccessibleSitesAsync(new Uri("https://contoso.sharepoint.com"), CancellationToken.None));
    }

    [Theory]
    [InlineData(".docx", false)]
    [InlineData(".docx", true)]
    [InlineData(".xlsx", false)]
    [InlineData(".xlsx", true)]
    [InlineData(".pptx", false)]
    [InlineData(".pptx", true)]
    public async Task EmbeddedOfficeAttachments_PreserveOuterFindingsAndRemainPending(string extension, bool ole)
    {
        var bytes = EmbeddedDocument(extension, ole);
        using var input = new MemoryStream(bytes);
        var extraction = new ContentExtractor().ExtractWithResult(input, extension);
        Assert.False(extraction.IsComplete);
        Assert.Contains("secret", extraction.Text);
        Assert.Contains("embedded", extraction.Error);
        foreach (var rest in new[] { false, true })
        {
            var file = Microsoft365CoverageTests.RemoteFile(rest, "outer" + extension, bytes, true);
            var result = await Microsoft365ReliabilityTests.ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file),
                extension: extension, options: new ScanOptions { EnableBinaryDocuments = true });
            Assert.True(result.Incomplete);
            Assert.NotEmpty(result.Findings);
            Assert.Equal(0, result.Processed);
            Assert.Null(result.FinalToken);
            Assert.Empty(result.Checkpoints);
        }
    }

    [Theory]
    [InlineData(".docx")]
    [InlineData(".xlsx")]
    [InlineData(".pptx")]
    public async Task EmbeddedOfficeAttachments_LocalAndZipScansAlsoReportPartial(string extension)
    {
        var bytes = EmbeddedDocument(extension, false);
        var rule = new Classifier
        {
            Name = "Secret",
            EnableLlmValidation = false,
            Matches =
            [new ClassifierMatch { Target = RuleTarget.Content, Patterns = ["secret"], IncludedExtensions = [extension] }]
        };
        var policies = new List<Policy> { new() { Name = "Secret" } };
        var mapping = new PolicyClassifier
        {
            Classifier = rule,
            ClassifierId = rule.Id,
            Policy = policies[0],
            PolicyId = policies[0].Id
        };
        rule.PolicyClassifiers.Add(mapping);
        policies[0].PolicyClassifiers.Add(mapping);
        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory([]));
        var file = Path.Combine(Path.GetTempPath(), "sift-embedded-" + Guid.NewGuid().ToString("N") + extension);
        try
        {
            System.IO.File.WriteAllBytes(file, bytes);
            var local = scanner.ScanFileWithResult(file, [rule], policies, new ScanOptions { EnableBinaryDocuments = true });
            Assert.False(local.IsComplete);
            Assert.NotEmpty(local.Issues);
        }
        finally { System.IO.File.Delete(file); }
        using var archive = new MemoryStream();
        using (var zip = new ZipArchive(archive, ZipArchiveMode.Create, true))
        using (var entry = zip.CreateEntry("outer" + extension).Open()) entry.Write(bytes);
        archive.Position = 0;
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([rule]);
        var result = await scanner.ScanStreamAsync(archive, "backup.zip",
            ScannerExecutionPlan.Create(optimizer, new() { [rule.Id] = policies }),
            new ScanOptions { EnableBinaryDocuments = true, EnableZipArchives = true });
        Assert.False(result.IsComplete);
        Assert.Contains(result.Issues, finding => finding.ResourcePath == "backup.zip!/outer" + extension);
    }

    [Theory]
    [InlineData(".docx")]
    [InlineData(".xlsx")]
    [InlineData(".pptx")]
    public void OrdinaryImages_DoNotTurnStoredTextExtractionIntoPartial(string extension)
    {
        using var input = new MemoryStream(EmbeddedDocument(extension, false, image: true));
        var result = new ContentExtractor().ExtractWithResult(input, extension);
        Assert.True(result.IsComplete);
        Assert.Contains("secret", result.Text);
    }

    private static SharePointDrive GraphDrive(Func<HttpRequestMessage, HttpResponseMessage> handler)
        => new(Microsoft365ReliabilityTests.Graph(handler), new Drive { Id = "source", Name = "Documents" }, "tenant");
    private static SharePointRestClient RestClient(Func<HttpRequestMessage, HttpResponseMessage> handler)
        => new(new Microsoft365ReliabilityTests.StubCredential(), "Tests", new HttpClient(new Microsoft365ReliabilityTests.Handler(handler)));
    private static HttpResponseMessage Text() => new(HttpStatusCode.OK) { Content = new StringContent("secret") };
    private static HttpResponseMessage Json(object value) => Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, JsonSerializer.Serialize(value));
    private static HttpResponseMessage Delta(object[] items) => Json(new Dictionary<string, object> { ["value"] = items, ["@odata.deltaLink"] = "final" });
    private static object File(string id, string name, string version, string? tenant = "tenant")
        => new
        {
            id,
            name,
            eTag = version,
            size = 6,
            file = new { mimeType = "text/plain" },
            sharepointIds = new { tenantId = tenant },
            webUrl = "https://contoso.sharepoint.com/files/" + name
        };
    private static object Folder(string id, string tenant = "tenant")
        => new { id, name = id, eTag = "folder-v1", folder = new { }, sharepointIds = new { tenantId = tenant }, webUrl = "https://contoso.sharepoint.com/folders/" + id };
    private static object Link(string id, string target, string drive, string? tenant = "tenant")
        => new
        {
            id,
            name = id,
            eTag = "link-v1",
            webUrl = "https://contoso.sharepoint.com/links/" + id,
            remoteItem = new { id = target, parentReference = new { driveId = drive }, sharepointIds = new { tenantId = tenant } }
        };
    private static HttpResponseMessage Search(int first, int count, string? invalid = null, bool contentStorage = false)
        => Json(new
        {
            PrimaryQueryResult = new
            {
                RelevantResults = new
                {
                    Table = new
                    {
                        Rows = Enumerable.Range(first, count).Select(index => new
                        {
                            Cells = new[]
                        {
                new { Key = "Title", Value = "Site" + index },
                new { Key = "Path", Value = "https://contoso.sharepoint.com/" + (contentStorage ? "contentstorage/" : "sites/") + "site" + index },
                new { Key = invalid == "missing" ? "MissingDocId" : "DocId", Value = (invalid == "repeated" ? 1 : invalid == "descending" ? first + count - index : index).ToString(System.Globalization.CultureInfo.InvariantCulture) }
            }
                        }).ToArray()
                    }
                }
            }
        });

    private static byte[] EmbeddedDocument(string extension, bool ole, bool image = false)
    {
        using var output = new MemoryStream();
        using (OpenXmlPackage package = extension switch
        {
            ".docx" => WordprocessingDocument.Create(output, WordprocessingDocumentType.Document, true),
            ".xlsx" => SpreadsheetDocument.Create(output, SpreadsheetDocumentType.Workbook, true),
            _ => PresentationDocument.Create(output, PresentationDocumentType.Presentation, true)
        })
        {
            OpenXmlPartContainer owner;
            if (package is WordprocessingDocument word)
            {
                var main = word.AddMainDocumentPart();
                main.Document = new W.Document(new W.Body(new W.Paragraph(new W.Run(new W.Text("outer secret")))));
                owner = main;
            }
            else if (package is SpreadsheetDocument excel)
            {
                var workbook = excel.AddWorkbookPart();
                var worksheet = workbook.AddNewPart<WorksheetPart>();
                worksheet.Worksheet = new S.Worksheet(new S.SheetData(new S.Row(new S.Cell(new S.InlineString(new S.Text("outer secret"))) { DataType = S.CellValues.InlineString })));
                workbook.Workbook = new S.Workbook(new S.Sheets(new S.Sheet { Id = workbook.GetIdOfPart(worksheet), Name = "Sheet", SheetId = 1 }));
                owner = worksheet;
            }
            else
            {
                var presentation = ((PresentationDocument)package).AddPresentationPart();
                var slide = presentation.AddNewPart<SlidePart>();
                slide.Slide = new P.Slide(new P.CommonSlideData(new P.ShapeTree(new P.Shape(new P.TextBody(new A.BodyProperties(), new A.ListStyle(),
                    new A.Paragraph(new A.Run(new A.Text("outer secret"))))))));
                presentation.Presentation = new P.Presentation(new P.SlideIdList(new P.SlideId { RelationshipId = presentation.GetIdOfPart(slide), Id = 256 }));
                owner = slide;
            }
            OpenXmlPart attachment = image ? owner.AddNewPart<ImagePart>("image/png") : ole
                ? owner.AddNewPart<EmbeddedObjectPart>("application/vnd.openxmlformats-officedocument.oleObject")
                : owner.AddNewPart<EmbeddedPackagePart>("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
            using var payload = new MemoryStream(Encoding.UTF8.GetBytes("uninspected attachment content"));
            attachment.FeedData(payload);
        }
        return output.ToArray();
    }
}
