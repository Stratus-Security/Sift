using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Graph.Models;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Models;

namespace Stratus.Sift.Cli.Tests;

public sealed class Microsoft365CoverageTests
{
    private const string SiteUrl = "https://contoso.sharepoint.com/sites/Test";
    private sealed record LibraryCase(string Id, string Title, string Path, int Template = 101,
        bool Hidden = false, int BaseType = 1, int ItemCount = 1);
    private static readonly LibraryCase[] Libraries =
    [
        new("documents", "Documents", "Documents"),
        new("styles", "Style Library", "Style Library"),
        new("forms", "Form Templates", "Form Templates", 115),
        new("assets", "Site Assets", "SiteAssets", 851),
        new("hold", "Preservation Hold Library", "PreservationHoldLibrary", Hidden: true),
        new("pages", "Pages", "Pages", 850),
        new("sitepages", "Site Pages", "SitePages", 119),
        new("master", "Master Page Gallery", "_catalogs/masterpage", 116, true),
        new("cache", "PersonalCacheLibrary", "PersonalCacheLibrary", Hidden: true),
        new("pictures", "Pictures", "Pictures", 109),
        new("workflow", "Workflows", "Workflows", 117, true),
        new("webparts", "Web Part Gallery", "_catalogs/wp", 113, true),
        new("solutions", "Solution Gallery", "_catalogs/solutions", 121, true),
        new("custom", "Custom template", "Custom", 10001),
        new("localized", "Ressources du site", "SiteAssets/Custom", 851),
        new("empty", "Empty library", "Empty", ItemCount: 0),
        // Names are not types: a user-created document library must not be blacklisted.
        new("same-name", "TaxonomyHiddenList", "CustomFiles"),
        new("taxonomy", "TaxonomyHiddenList", "Lists/TaxonomyHiddenList", 100, true, 0),
        new("feed", "MicroFeed", "Lists/MicroFeed", 544, true, 0),
        new("contacts", "Contacts", "Lists/Contacts", 105, false, 0)
    ];

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task LibraryDiscovery_IncludesAllFileBackedTypesAndHiddenLibrariesAcrossPages(bool rest, bool explicitSite)
    {
        var connector = Connector(rest, explicitSite ? new Uri(SiteUrl) : null);
        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Equal(Libraries.Where(l => l.BaseType == 1).Select(l => l.Id).Order(), drives.Select(d => d.Id).Order());
        Assert.True(connector.DiscoveryReport.IsComplete);
        Assert.Equal(1, connector.DiscoveryReport.SourceCounts["retained-content libraries"]);
        Assert.Contains("retained historical copies", Assert.Single(connector.DiscoveryReport.Warnings), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, "SiteAssets", "assets")]
    [InlineData(true, "SiteAssets", "assets")]
    [InlineData(false, "_catalogs/masterpage", "master")]
    [InlineData(true, "_catalogs/masterpage", "master")]
    public async Task ExplicitLibraryTargets_CanSelectPreviouslyExcludedContent(bool rest, string path, string id)
    {
        var connector = Connector(rest, new Uri(SiteUrl + "/" + path));

        Assert.Equal(id, Assert.Single(await connector.GetDrivesAsync()).Id);
        Assert.True(connector.DiscoveryReport.IsComplete);
        Assert.Empty(connector.DiscoveryReport.Warnings);
        Assert.False(connector.DiscoveryReport.SourceCounts.ContainsKey("retained-content libraries"));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task RestoredLibraryFiles_AreScannedOrReportAccessFailure(bool rest, bool denyContent)
    {
        var connector = Connector(rest, new Uri(SiteUrl + "/SiteAssets"), includeFile: true, denyContent: denyContent);
        var drive = Assert.Single(await connector.GetDrivesAsync());

        var result = await Microsoft365ReliabilityTests.ScanAsync(drive);

        Assert.Equal(denyContent, result.Incomplete);
        Assert.Equal(denyContent ? 0 : 1, result.Scanned);
        if (denyContent)
        {
            Assert.Empty(result.Findings);
            Assert.Null(result.FinalToken);
        }
        else Assert.Equal(SiteUrl + "/SiteAssets/credentials.txt", Assert.Single(result.Findings).ResourcePath);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GraphLibrary_UsesIdForMissingNameAndReportsMissingId(bool missingId)
    {
        var graph = Microsoft365ReliabilityTests.Graph(request => request.RequestUri!.AbsolutePath.EndsWith("/drives", StringComparison.Ordinal)
            ? Json(new
            {
                value = new[] { new { id = missingId ? null : "assets", name = (string?)null,
                webUrl = SiteUrl + "/SiteAssets", system = new { } } }
            })
            : Json(new { value = new[] { new { id = "site", name = "Test", webUrl = SiteUrl } } }));
        var connector = new SharePointConnector(graph, "tenant");
        var drives = (await connector.GetDrivesAsync()).ToList();

        Assert.Equal(!missingId, connector.DiscoveryReport.IsComplete);
        if (missingId)
        {
            Assert.Empty(drives);
            Assert.Contains("without an ID", Assert.Single(connector.DiscoveryReport.Warnings), StringComparison.Ordinal);
        }
        else
        {
            var drive = Assert.Single(drives);
            Assert.Equal("assets", drive.Id);
            Assert.Equal("assets", drive.Name);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task RemoteZip_InspectsInnerRulesAndEntryScopesWithoutRangingTheContainer(bool rest, bool nonSeekable)
    {
        var bytes = Zip(("configs/credentials.txt", Encoding.UTF8.GetBytes("secret")),
            ("ignored.txt", Encoding.UTF8.GetBytes("secret")));
        var file = RemoteFile(rest, "backup.ZIP", bytes, nonSeekable, forbidRange: true);
        var result = await ScanZip(file, new ScanOptions { EnableZipArchives = true, MaxFileSize = 64, HeadSize = 16 },
            new Policy
            {
                Name = "Entry scope",
                Configuration = new PolicyConfiguration
                { IncludePaths = ["*credentials.txt"], ExcludePaths = ["*ignored.txt"] }
            });

        Assert.Equal(file.WebUrl + "!/configs/credentials.txt", Assert.Single(result.Findings).ResourcePath);
        Assert.Equal(1, result.Scanned);
        Assert.Equal(1, result.Processed);
        Assert.Equal("final", result.FinalToken);
        Assert.False(result.Incomplete);
    }

    [Fact]
    public async Task RemoteZip_CanDisableArchiveInspection()
    {
        var file = RemoteFile(false, "backup.zip", Zip(("credentials.txt", Encoding.UTF8.GetBytes("secret"))), false);
        var result = await ScanZip(file, new ScanOptions { EnableZipArchives = false });

        Assert.Empty(result.Findings);
        Assert.Equal(0, result.Scanned);
        Assert.Equal(1, result.Processed);
        Assert.False(result.Incomplete);
    }

    [Fact]
    public async Task RemoteZip_PreservesNestedEntryPaths()
    {
        var inner = Zip(("credentials.txt", Encoding.UTF8.GetBytes("secret")));
        var file = RemoteFile(false, "backup.zip", Zip(("nested.zip", inner)), false);
        var result = await ScanZip(file, new ScanOptions { EnableZipArchives = true });

        Assert.Equal(file.WebUrl + "!/nested.zip!/credentials.txt", Assert.Single(result.Findings).ResourcePath);
        Assert.False(result.Incomplete);
    }

    [Fact]
    public async Task RemoteZip_ReportsMetadataForEmptyEntries()
    {
        var file = RemoteFile(false, "backup.zip", Zip(("id_rsa", [])), false);
        var classifier = new Classifier
        {
            Name = "Private key filename",
            EnableLlmValidation = false,
            Matches = [new ClassifierMatch { Target = RuleTarget.FileName, IsLiteral = true, Patterns = ["id_rsa"] }]
        };
        var result = await Microsoft365ReliabilityTests.ScanAsync(new SingleFileDrive(file),
            classifiers: [classifier], options: new ScanOptions { EnableZipArchives = true });

        Assert.Equal(file.WebUrl + "!/id_rsa", Assert.Single(result.Findings).ResourcePath);
        Assert.False(result.Incomplete);
    }

    [Fact]
    public async Task RemoteZip_ValidEmptyArchiveCompletesWithoutFindings()
    {
        var file = RemoteFile(false, "backup.zip", Zip(), false);
        var result = await ScanZip(file, new ScanOptions { EnableZipArchives = true });

        Assert.Empty(result.Findings);
        Assert.Equal(1, result.Processed);
        Assert.False(result.Incomplete);
        Assert.Equal("final", result.FinalToken);
    }

    [Theory]
    [InlineData("credentials.txt")]
    [InlineData("credentials.docx")]
    public async Task RemoteZip_MetadataOnlyRulesDoNotRequireEntryContentOrExtraction(string name)
    {
        var file = RemoteFile(false, "backup.zip", Zip((name, Encoding.UTF8.GetBytes(new string('x', 128)))), false);
        var classifier = new Classifier
        {
            Name = "Filename",
            EnableLlmValidation = false,
            Matches = [new ClassifierMatch { Target = RuleTarget.FileName, IsLiteral = true, Patterns = [name] }]
        };
        var result = await Microsoft365ReliabilityTests.ScanAsync(new SingleFileDrive(file), classifiers: [classifier],
            options: new ScanOptions { EnableZipArchives = true, EnableBinaryDocuments = true, MaxFileSize = 32 });

        Assert.Equal(file.WebUrl + "!/" + name, Assert.Single(result.Findings).ResourcePath);
        Assert.False(result.Incomplete);
        Assert.Equal(1, result.Processed);
        Assert.Equal("final", result.FinalToken);
    }

    [Fact]
    public async Task RemoteZip_PartialEntryReadRetainsFindingsAndRemainsIncomplete()
    {
        var file = RemoteFile(false, "backup.zip", Zip(("credentials.txt", Encoding.UTF8.GetBytes("secret " + new string('x', 64)))), false);
        var result = await ScanZip(file, new ScanOptions { EnableZipArchives = true, MaxFileSize = 32, HeadSize = 16 });

        Assert.Single(result.Findings);
        Assert.True(result.Incomplete);
        Assert.Equal(0, result.Processed);
        Assert.Null(result.FinalToken);
    }

    [Fact]
    public async Task RemoteZip_FailedDocumentExtractionRemainsIncomplete()
    {
        var file = RemoteFile(false, "backup.zip", Zip(("credentials.docx", Encoding.UTF8.GetBytes("not a document"))), false);
        var result = await Microsoft365ReliabilityTests.ScanAsync(new SingleFileDrive(file), extension: ".docx",
            options: new ScanOptions { EnableZipArchives = true, EnableBinaryDocuments = true });

        Assert.True(result.Incomplete);
        Assert.Equal(0, result.Processed);
        Assert.Null(result.FinalToken);
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("entries")]
    [InlineData("entry-size")]
    [InlineData("buffer")]
    [InlineData("nested-invalid")]
    [InlineData("nested-depth")]
    public async Task UninspectableArchive_RemainsPendingWithoutAdvancingCheckpoints(string failure)
    {
        var bytes = Zip(("credentials.txt", Encoding.UTF8.GetBytes("secret")), ("public.txt", Encoding.UTF8.GetBytes("public")));
        var options = new ScanOptions { EnableZipArchives = true };
        switch (failure)
        {
            case "invalid": bytes = Encoding.UTF8.GetBytes("not a ZIP"); break;
            case "entries": options.MaxZipEntries = 1; break;
            case "entry-size": options.MaxZipEntryBytes = 1; break;
            case "buffer": options.MaxZipBufferedContainerBytes = 1; break;
            case "nested-invalid": bytes = Zip(("nested.zip", Encoding.UTF8.GetBytes("not a ZIP"))); break;
            case "nested-depth": bytes = Zip(("nested.zip", Zip(("third.zip", bytes)))); break;
        }
        var file = RemoteFile(false, "backup.zip", bytes, failure == "buffer");

        var result = await ScanZip(file, options);

        Assert.True(result.Incomplete);
        Assert.Equal(0, result.Processed);
        Assert.Equal(0, result.Scanned);
        Assert.Null(result.FinalToken);
        Assert.Empty(result.Checkpoints);
    }

    private static Task<Microsoft365ReliabilityTests.ScanOutcome> ScanZip(IRemoteFile file, ScanOptions options, Policy? policy = null)
        => Microsoft365ReliabilityTests.ScanAsync(new SingleFileDrive(file), options: options, policy: policy);

    private static SharePointConnector Connector(bool rest, Uri? target, bool includeFile = false, bool denyContent = false)
    {
        HttpResponseMessage Handle(HttpRequestMessage request)
        {
            var uri = request.RequestUri!;
            var url = Uri.UnescapeDataString(uri.AbsoluteUri);
            if (includeFile && (uri.AbsolutePath.EndsWith("/content", StringComparison.Ordinal)
                || uri.AbsolutePath.EndsWith("/$value", StringComparison.Ordinal)))
                return denyContent ? Microsoft365ReliabilityTests.Response(HttpStatusCode.Forbidden,
                    "{\"error\":{\"code\":\"accessDenied\",\"message\":\"Mock failure\"}}")
                    : new(HttpStatusCode.OK) { Content = new StringContent("secret") };
            if (includeFile && uri.AbsolutePath.Contains("/drives/", StringComparison.Ordinal)) return Json(new Dictionary<string, object>
            {
                ["value"] = new[] { new { id = "file", name = "credentials.txt", size = 6, file = new { }, eTag = "v1", webUrl = SiteUrl + "/SiteAssets/credentials.txt" } },
                ["@odata.deltaLink"] = "final"
            });
            if (includeFile && uri.AbsolutePath.EndsWith("/Files", StringComparison.Ordinal)) return Json(new
            { value = new[] { new { UniqueId = "file", Name = "credentials.txt", Length = "6", ETag = "v1", ServerRelativeUrl = "/sites/Test/SiteAssets/credentials.txt" } } });
            if (includeFile && uri.AbsolutePath.EndsWith("/Folders", StringComparison.Ordinal)) return Json(new { value = Array.Empty<object>() });
            if (url.Contains("/search/query", StringComparison.Ordinal)) return Json(new
            {
                PrimaryQueryResult = new
                {
                    RelevantResults = new
                    {
                        Table = new
                        {
                            Rows = new[] { new { Cells = new[]
                    { new { Key = "Title", Value = "Test" }, new { Key = "Path", Value = SiteUrl } } } }
                        }
                    }
                }
            });
            if (uri.AbsolutePath.Contains("getAllSites", StringComparison.Ordinal)) return Json(new
            { value = new[] { new { id = "site", name = "Test", webUrl = SiteUrl } } });
            if (uri.AbsolutePath.EndsWith("/lists", StringComparison.Ordinal) || uri.AbsolutePath.EndsWith("/drives", StringComparison.Ordinal))
            {
                var second = url.Contains("page=2", StringComparison.Ordinal);
                var data = rest ? Libraries : Libraries.Where(l => l.BaseType == 1).ToArray();
                var page = second ? data.Skip(8) : data.Take(8);
                object[] items;
                if (rest)
                {
                    if (!second)
                    {
                        Assert.Contains("$filter=BaseType eq 1", url, StringComparison.Ordinal);
                        Assert.DoesNotContain("Hidden eq false", url, StringComparison.Ordinal);
                        Assert.DoesNotContain("BaseTemplate eq 101", url, StringComparison.Ordinal);
                    }
                    items = page.Select(l => (object)new
                    {
                        l.Id,
                        Title = l.Title,
                        l.Hidden,
                        l.BaseType,
                        BaseTemplate = l.Template,
                        l.ItemCount,
                        RootFolder = new { ServerRelativeUrl = "/sites/Test/" + l.Path }
                    }).ToArray();
                }
                else
                {
                    if (!second) Assert.Contains("system", url, StringComparison.Ordinal);
                    items = page.Select(l => (object)new
                    {
                        id = l.Id,
                        name = l.Title,
                        webUrl = SiteUrl + "/" + string.Join('/', l.Path.Split('/').Select(Uri.EscapeDataString)),
                        system = l.Hidden ? new { } : null
                    }).ToArray();
                }
                var result = new Dictionary<string, object> { ["value"] = items };
                if (!second) result["@odata.nextLink"] = uri.GetLeftPart(UriPartial.Path) + "?page=2";
                return Json(result);
            }
            return rest ? Json(new { Title = "Test", Url = SiteUrl }) : Json(new { id = "site", name = "Test", webUrl = SiteUrl });
        }

        var targets = target == null ? null : new[] { target };
        if (rest)
        {
            var client = new SharePointRestClient(new Microsoft365ReliabilityTests.StubCredential(), "Tests",
                new HttpClient(new Microsoft365ReliabilityTests.Handler(Handle)));
            return new SharePointConnector(client, "tenant", new Uri("https://contoso.sharepoint.com"),
                useConfiguredTargets: target != null, configuredSiteTargets: targets);
        }
        return new SharePointConnector(Microsoft365ReliabilityTests.Graph(Handle), "tenant",
            useConfiguredTargets: target != null, configuredSiteTargets: targets);
    }

    private static HttpResponseMessage Json(object value)
        => Microsoft365ReliabilityTests.Response(HttpStatusCode.OK, JsonSerializer.Serialize(value));

    internal static IRemoteFile RemoteFile(bool rest, string name, byte[] bytes, bool nonSeekable, bool forbidRange = false)
    {
        HttpResponseMessage Handle(HttpRequestMessage request)
        {
            if (forbidRange) Assert.False(request.Headers.Contains("Range"));
            Stream stream = new MemoryStream(bytes);
            if (nonSeekable) stream = new NonSeekableStream(stream);
            return new(HttpStatusCode.OK) { Content = new StreamContent(stream) };
        }
        var path = "/sites/Test/Documents/" + name;
        if (rest)
        {
            var client = new SharePointRestClient(new Microsoft365ReliabilityTests.StubCredential(), "Tests",
                new HttpClient(new Microsoft365ReliabilityTests.Handler(Handle)));
            return new SharePointRestFile(client, new Uri(SiteUrl), new("file", name, path,
                new Uri("https://contoso.sharepoint.com" + path), false, false, bytes.Length, "v1"));
        }
        var item = Microsoft365ReliabilityTests.Item("file", name, "v1");
        item.Size = bytes.Length;
        item.WebUrl += "?web=1";
        return new SharePointFile(Microsoft365ReliabilityTests.Graph(Handle), "drive", item, "tenant");
    }

    private static byte[] Zip(params (string Name, byte[] Content)[] entries)
    {
        using var bytes = new MemoryStream();
        using (var archive = new ZipArchive(bytes, ZipArchiveMode.Create, true))
            foreach (var entry in entries) using (var stream = archive.CreateEntry(entry.Name).Open()) stream.Write(entry.Content);
        return bytes.ToArray();
    }

    internal sealed class SingleFileDrive(IRemoteFile file) : IRemoteDrive
    {
        public string Id => "drive";
        public string Name => "Documents";
        public string ConnectionId => "sharepoint://tenant/drive";
        public string WebUrl => SiteUrl + "/Documents";
        public DatastoreType DriveType => DatastoreType.SharePoint;
        public long? TotalSize => null;
        public long? UsedSize => null;
        public Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken ct = default)
            => Task.FromResult(((IEnumerable<IRemoteFile>)[file], "final"));
        public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
            Func<string, Task>? onCheckpoint = null, CancellationToken ct = default)
        {
            await onChange(file);
            if (onCheckpoint != null) await onCheckpoint("next");
            return "final";
        }
    }

    private sealed class NonSeekableStream(Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => inner.ReadAsync(buffer, ct);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }
}
