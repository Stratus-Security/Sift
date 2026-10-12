using Azure.Core;
using Azure.Identity;
using Microsoft.Graph.Models;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using System.Net;
using System.Text.Json;
using System.Collections.Concurrent;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class Microsoft365DefaultCoverageTests
{
    private static Classifier Rule(RuleTarget target, string pattern, string extension) => new()
    {
        Name = target.ToString(), Matches = [new ClassifierMatch { Target = target, Patterns = [pattern], IncludedExtensions = [extension] }]
    };

    [Fact]
    public void ExclusionsAndExplicitSelections_AreSupportedWithoutPermissionExpansion()
    {
        var options = Microsoft365WorkloadOptions.Parse(new Dictionary<string, string> { ["ExcludeWorkloads"] = "engage;powerbi", ["ScanStorage"] = "false" });
        Assert.Equal(7, options.Enabled.Count);
        Assert.DoesNotContain("engage", options.Enabled);
        Assert.False(options.RequestAdditionalPermissions);
        Assert.True(options.IncludePersonalTasks);
        Assert.Empty(Microsoft365WorkloadOptions.Parse(new Dictionary<string, string> { ["Workloads"] = "storage" }).Enabled);
        Assert.Equal(["https://graph.microsoft.us/.default"],
            SharePointConnector.GetDelegatedScopes(new Dictionary<string, string> { ["Cloud"] = "GccHigh" }));
        var result = Stratus.Sift.Cli.CliCommandFactory.BuildRootCommand().Parse(["m365", "--request-additional-permissions"]);
        Assert.Empty(result.Errors);
    }

    [Theory]
    [InlineData(".loop")]
    [InlineData(".fluid")]
    [InlineData(".whiteboard")]
    [InlineData(".wbtx")]
    public async Task ConvertedFiles_PreserveMetadataAndScanDecodedTextWithoutFollowingLinks(string extension)
    {
        var requests = new List<Uri>();
        var graph = Graph(request =>
        {
            requests.Add(request.RequestUri!);
            Assert.Contains("format=html", request.RequestUri!.Query);
            return Response(HttpStatusCode.OK, "<p>se&#99;ret</p><a href='https://foreign.example/loop'>link</a>");
        });
        var name = "board" + extension;
        var file = new SharePointFile(graph, "drive", new DriveItem { Id = "item", Name = name, ETag = "version", Size = 2_000_000_000,
            File = new FileObject(), WebUrl = "https://contoso.sharepoint.com/board" + extension }, "tenant");
        var result = await ScanAsync(new SingleDrive(file),
            classifiers: [Rule(RuleTarget.Content, "secret", ".html"), Rule(RuleTarget.FileExtension, extension, extension)]);
        Assert.False(result.Incomplete);
        Assert.Equal(2, result.Findings.Count);
        Assert.Single(requests);
        Assert.Equal(name, file.Name);
        Assert.Equal(name + ".html", file.ContentName);
        Assert.Null(file.Size);
        Assert.Contains(Microsoft365ContentProjection.VersionSuffix, file.Version);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(415)]
    [InlineData(422)]
    public async Task ExpectedConversionFailures_RemainPendingWithoutWarningSpam(int status)
    {
        var graph = Graph(_ => Response((HttpStatusCode)status, ""));
        var file = new SharePointFile(graph, "drive", new DriveItem { Id = "item", Name = "board.loop", ETag = "v1",
            File = new FileObject(), WebUrl = "https://contoso.sharepoint.com/board.loop" }, "tenant");
        var logger = new RecordingLogger();
        var result = await ScanAsync(new SingleDrive(file), classifiers: [Rule(RuleTarget.Content, "secret", ".html")], logger: logger);
        Assert.True(result.Incomplete);
        Assert.Empty(result.Checkpoints);
        Assert.Null(result.FinalToken);
        Assert.DoesNotContain(logger.Levels, level => level >= LogLevel.Warning);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task NativeAndGraphConversion_InspectHistoryWithoutLosingCurrentFindings(bool native, bool historyUnavailable)
    {
        const string site = "https://contoso.sharepoint.com/sites/Test";
        const string suffix = "nested #100%/O'Brien.loop";
        var graphRequests = new ConcurrentQueue<Uri>();
        var graph = Graph(request =>
        {
            var uri = request.RequestUri!;
            graphRequests.Enqueue(uri);
            if (uri.AbsolutePath.EndsWith("/sites/contoso.sharepoint.com:/sites/Test"))
                return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { id = "site" }));
            if (uri.AbsolutePath.EndsWith("/sites/site/drives"))
                return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { value = new[] {
                    new { id = "wrong", webUrl = site + "/Other" }, new { id = "drive", webUrl = site + "/Documents" } } }));
            if (uri.AbsolutePath.Contains("/root:/"))
            {
                Assert.Equal("/v1.0/drives/drive/root:/" + suffix, Uri.UnescapeDataString(uri.AbsolutePath));
                Assert.Empty(uri.Fragment);
                return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { id = "item", file = new { } }));
            }
            if (uri.AbsolutePath.EndsWith("/versions"))
                return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { value = new[] { new { id = "2.0", size = 6 }, new { id = "1.0", size = 6 } } }));
            if (uri.AbsolutePath.EndsWith("/items/item"))
                return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { id = "item", publication = new { versionId = "2.0" } }));
            Assert.Contains("format=html", uri.Query);
            return historyUnavailable && uri.AbsolutePath.Contains("/versions/")
                ? Response(HttpStatusCode.BadRequest, "")
                : Response(HttpStatusCode.OK, "<p>secret</p>");
        });
        var coverage = Microsoft365CoverageOptions.Disabled with { GraphClient = graph, ScanVersions = true };
        Stratus.Sift.Connectors.Interfaces.IRemoteFile file;
        if (native)
        {
            var rest = new SharePointRestClient(new StubCredential(), "Tests", new HttpClient(new Handler(request =>
            {
                Assert.EndsWith("/Versions", request.RequestUri!.AbsolutePath);
                return Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { value = new[] {
                    new { ID = 512, VersionLabel = "1.0", Url = "_vti_history/512/Documents/history.loop", Size = 6 } } }));
            })));
            var relative = "/sites/Test/Documents/" + suffix;
            file = new SharePointRestFile(rest, new(site), new("native", "O'Brien.loop", relative,
                SharePointRestClient.BuildWebUrl(new(site), relative), false, false, 6, "v1"), coverage);
        }
        else
            file = new SharePointFile(graph, "drive", new DriveItem { Id = "item", Name = "O'Brien.loop", File = new FileObject(),
                ETag = "v1", WebUrl = site + "/Documents/board.loop" }, "tenant", false, coverage);
        var logger = new RecordingLogger();
        var result = await ScanAsync(new SingleDrive(file), classifiers: [Rule(RuleTarget.Content, "secret", ".html")], logger: logger);
        Assert.Equal(historyUnavailable, result.Incomplete);
        Assert.Equal(historyUnavailable ? 1 : 2, result.Findings.Count);
        Assert.Equal(2, graphRequests.Count(uri => uri.Query.Contains("format=html")));
        if (native) Assert.Single(graphRequests, uri => uri.AbsolutePath.Contains("/root:/"));
        Assert.DoesNotContain(logger.Levels, level => level >= LogLevel.Warning);
    }

    [Fact]
    public async Task NativeConversionWithoutGraph_RetainsMetadataAndStaysQuiet()
    {
        var rest = new SharePointRestClient(new StubCredential(), "Tests",
            new HttpClient(new Handler(_ => throw new InvalidOperationException("Native raw content must not be opened."))));
        var file = new SharePointRestFile(rest, new("https://contoso.sharepoint.com/sites/Test"),
            new("file", "board.whiteboard", "/sites/Test/Documents/board.whiteboard",
                new("https://contoso.sharepoint.com/sites/Test/Documents/board.whiteboard"), false, false, 6, "v1"));
        var logger = new RecordingLogger();
        var result = await ScanAsync(new SingleDrive(file),
            classifiers: [Rule(RuleTarget.Content, "secret", ".html"), Rule(RuleTarget.FileName, "board.whiteboard", ".whiteboard")], logger: logger);
        Assert.True(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.Null(result.FinalToken);
        Assert.DoesNotContain(logger.Levels, level => level >= LogLevel.Warning);
    }

    [Fact]
    public async Task ConversionRedirect_DownloadsHtmlWithoutSendingGraphCredentialsToStorage()
    {
        var requests = new List<string>();
        var graph = MicrosoftGraphClientBuilder.Create(new StubCredential(), "Tests", timeout: null,
            finalHandler: new Handler(request =>
            {
                requests.Add(request.RequestUri!.Host);
                if (request.RequestUri.Host == "graph.microsoft.com")
                {
                    Assert.NotNull(request.Headers.Authorization);
                    return new HttpResponseMessage(HttpStatusCode.Found) {
                        RequestMessage = request,
                        Headers = { Location = new Uri("https://download.example/converted") } };
                }
                Assert.Equal("download.example", request.RequestUri.Host);
                Assert.Null(request.Headers.Authorization);
                return Response(HttpStatusCode.OK, "<p>se&#99;ret</p>");
            }), retryOptions: null);
        using var stream = await Microsoft365ContentProjection.Open(graph, "drive", "item", CancellationToken.None);
        using var reader = new StreamReader(stream!);
        Assert.Contains("secret", await reader.ReadToEndAsync());
        Assert.Equal(["graph.microsoft.com", "download.example"], requests);
    }

    [Fact]
    public async Task DefaultToDoCoverage_IncludesAccessiblePersonalLists()
    {
        var graph = Graph(request => request.RequestUri!.AbsolutePath.EndsWith("/todo/lists")
            ? Response(HttpStatusCode.OK, JsonSerializer.Serialize(new { value = new[] { new { id = "personal", displayName = "secret", isShared = false } } }))
            : Response(HttpStatusCode.OK, "{\"value\":[]}"));
        var options = Microsoft365WorkloadOptions.Parse(new Dictionary<string, string>());
        var result = await ScanAsync(new Microsoft365GraphWorkloadDrive(new(graph), "tenant", "todo", options, false),
            classifiers: [Rule(RuleTarget.Content, "secret", ".json")]);
        Assert.False(result.Incomplete);
        Assert.Single(result.Findings);
    }

    [Fact]
    public async Task ExistingScopes_DoNotOpenAnySignInOrConsent()
    {
        var silent = new ScopeCredential("existing");
        var prompts = 0;
        var credential = new Microsoft365DelegatedCredential(silent, (_, _) => { prompts++; return Task.CompletedTask; }, ["login"], false);
        await credential.GetTokenAsync(new(["existing"]), CancellationToken.None);
        await Assert.ThrowsAsync<Microsoft365ConsentRequiredException>(async () =>
            await credential.GetTokenAsync(new(["additional"]), CancellationToken.None));
        Assert.Equal(0, prompts);
    }

    [Fact]
    public async Task MissingScopes_AllowNormalSignInButNeverRequestExtraConsentByDefault()
    {
        var silent = new ScopeCredential();
        var prompts = new List<string>();
        var credential = new Microsoft365DelegatedCredential(silent, (context, _) =>
        {
            prompts.AddRange(context.Scopes); silent.Grants.UnionWith(context.Scopes); return Task.CompletedTask;
        }, ["login"], false);
        for (var attempt = 0; attempt < 3; attempt++)
            await Assert.ThrowsAsync<Microsoft365ConsentRequiredException>(async () => await credential.GetTokenAsync(new(["additional"]), CancellationToken.None));
        Assert.Equal(["login"], prompts);
    }

    [Fact]
    public async Task ConcurrentMissingScopes_OnlyOpenOneNormalSignIn()
    {
        var silent = new ScopeCredential();
        var prompts = 0;
        var credential = new Microsoft365DelegatedCredential(silent, async (context, ct) =>
        {
            Interlocked.Increment(ref prompts);
            await Task.Yield();
            silent.Grants.UnionWith(context.Scopes);
        }, ["login"], false);
        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ =>
            Assert.ThrowsAsync<Microsoft365ConsentRequiredException>(async () =>
                await credential.GetTokenAsync(new(["additional"]), CancellationToken.None))));
        Assert.Equal(1, prompts);
    }

    [Fact]
    public async Task RejectedOptIn_DoesNotPromptRepeatedlyForTheSameScopes()
    {
        var silent = new ScopeCredential("login");
        var prompts = 0;
        var credential = new Microsoft365DelegatedCredential(silent, (_, _) =>
        {
            Interlocked.Increment(ref prompts);
            throw new AuthenticationFailedException("AADSTS65004: Consent was declined.");
        }, ["login"], true);
        await credential.GetTokenAsync(new(["login"]), CancellationToken.None);
        await Assert.ThrowsAsync<AuthenticationFailedException>(async () =>
            await credential.GetTokenAsync(new(["additional"]), CancellationToken.None));
        await Assert.ThrowsAsync<Microsoft365ConsentRequiredException>(async () =>
            await credential.GetTokenAsync(new(["additional"]), CancellationToken.None));
        Assert.Equal(1, prompts);
    }

    [Fact]
    public async Task ExplicitPermissionOptIn_RequestsOnlyMissingScopesAndReusesExistingAccess()
    {
        var silent = new ScopeCredential();
        var prompts = new List<string>();
        var credential = new Microsoft365DelegatedCredential(silent, (context, _) =>
        {
            prompts.AddRange(context.Scopes); silent.Grants.UnionWith(context.Scopes); return Task.CompletedTask;
        }, ["login"], true);
        await credential.GetTokenAsync(new(["additional"]), CancellationToken.None);
        await credential.GetTokenAsync(new(["additional"]), CancellationToken.None);
        Assert.Equal(["login", "additional"], prompts);
    }

    private sealed class ScopeCredential(params string[] grants) : TokenCredential
    {
        internal HashSet<string> Grants { get; } = new(grants, StringComparer.Ordinal);
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken ct)
        {
            if (!context.Scopes.All(Grants.Contains)) throw new AuthenticationRequiredException("Interaction required", context);
            return new("test-token", DateTimeOffset.UtcNow.AddHours(1));
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken ct) => ValueTask.FromResult(GetToken(context, ct));
    }

    private sealed class RecordingLogger : ILogger<Stratus.Sift.Connectors.Services.RemoteDriveScanner>
    {
        internal List<LogLevel> Levels { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? ex, Func<TState, Exception?, string> format) => Levels.Add(level);
    }

    private sealed class SingleDrive(Stratus.Sift.Connectors.Interfaces.IRemoteFile file) : Stratus.Sift.Connectors.Interfaces.IRemoteDrive
    {
        public string Id => "drive"; public string Name => "drive"; public string ConnectionId => "test://drive";
        public string WebUrl => "https://contoso.sharepoint.com/"; public DatastoreType DriveType => DatastoreType.SharePoint;
        public long? TotalSize => null; public long? UsedSize => null;
        public Task<(IEnumerable<Stratus.Sift.Connectors.Interfaces.IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? token, CancellationToken ct = default)
            => Task.FromResult<(IEnumerable<Stratus.Sift.Connectors.Interfaces.IRemoteFile>, string)>(([file], "final"));
    }
}
