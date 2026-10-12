using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class Microsoft365NativePathRegressionTests
{
    private const string SiteUrl = "https://contoso.sharepoint.com/sites/Test";
    private static HttpResponseMessage Json(object value) => Response(HttpStatusCode.OK, JsonSerializer.Serialize(value));
    private static SharePointRestClient Rest(Func<HttpRequestMessage, HttpResponseMessage> callback)
        => new(new StubCredential(), "Tests", new HttpClient(new Handler(callback)));

    [Theory]
    [InlineData("Leadership Development/future leader's application.txt")]
    [InlineData("literal%20and%27.txt")]
    [InlineData("folder #100%/report + résumé.txt")]
    [InlineData("nested O'Brien/O''Brien's notes.txt")]
    public async Task NativeFieldsHistoryAndSharing_UseDecodedFilenameAfterOneHttpDecode(string suffix)
    {
        var path = "/sites/Test/Documents/" + suffix;
        var requests = new List<string>();
        var rest = Rest(request =>
        {
            var uri = request.RequestUri!;
            Assert.Empty(uri.Fragment);
            if (uri.AbsolutePath.Contains("GetFileByServerRelativePath", StringComparison.Ordinal))
            {
                requests.Add(uri.AbsoluteUri);
                var actualPath = DecodedResourceArgument(uri);
                if (actualPath != path) return Response(HttpStatusCode.NotFound, "The file " + actualPath + " does not exist.");
                if (uri.AbsolutePath.EndsWith("/RoleAssignments")) return Json(new { value = new[] {
                    new { Member = new { LoginName = "spo-grid-all-users/tenant", PrincipalType = 4 },
                        RoleDefinitionBindings = new[] { new { Name = "Read" } } } } });
                if (uri.AbsolutePath.EndsWith("/Versions")) return Json(new { value = new[] { new { ID = 512, Url = "_vti_history/512/Documents/history.txt", Size = 6 } } });
                if (uri.AbsolutePath.EndsWith("/ListItemAllFields")) return Json(new
                    { HasUniqueRoleAssignments = false, Author = new { EMail = "author@stratus.security" }, Custom = "secret" });
            }
            return Response(HttpStatusCode.OK, "secret");
        });
        var coverage = Microsoft365CoverageOptions.Disabled with { ReadSharing = true, ScanLibraryFields = true, ScanVersions = true };
        var file = new SharePointRestFile(rest, new(SiteUrl), new("file", "test.txt", path,
            SharePointRestClient.BuildWebUrl(new(SiteUrl), path), false, false, 6, "v1"), coverage);
        var rules = new[] { new Classifier { Name = "Content", EnableLlmValidation = false, Matches = [new()
            { Target = RuleTarget.Content, Patterns = ["secret"], IncludedExtensions = [".txt", ".json"] }] } };
        var result = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), classifiers: rules);
        Assert.False(result.Incomplete);
        Assert.Equal(3, result.Processed);
        Assert.Equal(3, result.Findings.Count);
        Assert.All(result.Findings, finding => Assert.Equal("Organization", finding.Exposure));
        Assert.Contains(result.Findings, finding => finding.ResourcePath.EndsWith("#sift-fields"));
        Assert.Contains(result.Findings, finding => finding.ResourcePath.EndsWith("#sift-version=512"));
        Assert.Equal(5, requests.Count);
    }

    [Fact]
    public async Task SupplementalFailures_AreLabeledCorrectlyAndWarningsStayBounded()
    {
        var rest = Rest(request => request.RequestUri!.AbsolutePath.EndsWith("/Versions")
            ? Response(HttpStatusCode.NotFound, "The file " + DecodedResourceArgument(request.RequestUri) + " does not exist.")
            : Response(HttpStatusCode.OK, "secret"));
        var files = Enumerable.Range(1, 30).Select(index => (IRemoteFile)new SharePointRestFile(rest, new(SiteUrl),
            new(index.ToString(), "test.txt", $"/sites/Test/Documents/file {index}.txt", new(SiteUrl + $"/Documents/file{index}.txt"),
                false, false, 6, "v1"), Microsoft365CoverageOptions.Disabled with { ScanVersions = true })).ToArray();
        var logger = new RecordingLogger();
        var result = await ScanAsync(new FileDrive(files), logger: logger);
        Assert.True(result.Incomplete);
        Assert.Equal(30, result.Findings.Count);
        Assert.Null(result.FinalToken);
        var warnings = logger.Entries.Where(entry => entry.Level == LogLevel.Warning).ToArray();
        Assert.DoesNotContain(warnings, entry => entry.Message.Contains("shortcut", StringComparison.OrdinalIgnoreCase));
        var detailWarnings = warnings.Where(entry => entry.Message.Contains("Could not inspect additional remote content")).ToArray();
        Assert.Empty(detailWarnings);
        Assert.Empty(warnings);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information
            && entry.Message.Contains("30 additional-content inspections"));
        Assert.Equal(30, logger.Entries.Count(entry => entry.Level == LogLevel.Debug && entry.Exception != null));
    }

    private static string DecodedResourceArgument(Uri uri)
    {
        const string marker = "decodedurl='";
        var start = uri.AbsoluteUri.IndexOf(marker, StringComparison.OrdinalIgnoreCase) + marker.Length;
        var end = uri.AbsoluteUri.IndexOf("')", start, StringComparison.Ordinal);
        return Uri.UnescapeDataString(uri.AbsoluteUri[start..end]).Replace("''", "'", StringComparison.Ordinal);
    }

    private sealed class RecordingLogger : ILogger<RemoteDriveScanner>
    {
        private readonly ConcurrentQueue<(LogLevel Level, string Message, Exception? Exception)> _entries = new();
        internal IReadOnlyCollection<(LogLevel Level, string Message, Exception? Exception)> Entries => _entries.ToArray();
        public bool IsEnabled(LogLevel level) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => _entries.Enqueue((level, formatter(state, exception), exception));
    }

    private sealed class FileDrive(IReadOnlyList<IRemoteFile> files) : IRemoteDrive
    {
        public string Id => "drive";
        public string Name => "Documents";
        public string ConnectionId => "sharepoint://tenant/drive";
        public string WebUrl => SiteUrl + "/Documents";
        public DatastoreType DriveType => DatastoreType.SharePoint;
        public long? TotalSize => null;
        public long? UsedSize => null;
        public Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken ct = default)
            => Task.FromResult(((IEnumerable<IRemoteFile>)files, "final"));
        public async Task<string> ProcessChangesAsync(string? token, Func<IRemoteFile, Task> onChange,
            Func<string, Task>? onCheckpoint = null, CancellationToken ct = default)
        {
            foreach (var file in files) { ct.ThrowIfCancellationRequested(); await onChange(file); }
            if (onCheckpoint != null) await onCheckpoint("next");
            return "final";
        }
    }
}
