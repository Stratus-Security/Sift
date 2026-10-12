using System.Net;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.SharePoint;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class Microsoft365WorkloadTests
{
    private static Classifier ContentRule(string extension) => new()
    {
        Name = "Workload probe " + extension,
        Matches = [new ClassifierMatch { Target = RuleTarget.Content, Patterns = ["secret"], IncludedExtensions = [extension] }]
    };
    private static HttpResponseMessage Json(object value) => Response(HttpStatusCode.OK, JsonSerializer.Serialize(value));
    private static HttpResponseMessage Empty() => Json(new { value = Array.Empty<object>() });
    private static Microsoft365GraphWorkloadDrive Drive(string workload, Func<HttpRequestMessage, HttpResponseMessage> handler,
        Microsoft365WorkloadOptions? options = null, bool appOnly = false)
        => new(new(Graph(handler)), "tenant", workload, options ?? new(), appOnly);

    [Fact]
    public void CliWorkloadConfiguration_AcceptsMultipleValuesAndRepeatedKeys()
    {
        var root = Stratus.Sift.Cli.CliCommandFactory.BuildRootCommand();
        var result = root.Parse(["m365", "--config", "Workloads=sharedmail", "ScanStorage=false", "SharedMailbox=first@stratussecurity.com",
            "--config", "SharedMailbox=second@stratussecurity.com"]);
        Assert.Empty(result.Errors);
        var configOption = Assert.IsType<System.CommandLine.Option<string[]>>(result.CommandResult.Command.Options.Single(option => option.Name == "--config"));
        var config = Stratus.Sift.Cli.CliConnectorConfiguration.ParseConnectorConfig(result.GetValue(configOption));
        var workloads = Microsoft365WorkloadOptions.Parse(config);
        Assert.False(workloads.ScanStorage);
        Assert.Equal(["first@stratussecurity.com", "second@stratussecurity.com"], workloads.SharedMailboxes);
    }

    [Fact]
    public void WorkloadConfiguration_DefaultsToAllAndAdditionalScopesAreReadOnly()
    {
        var defaults = Microsoft365WorkloadOptions.Parse(new Dictionary<string, string>());
        Assert.Equal(9, defaults.Enabled.Count);
        Assert.False(defaults.RequestAdditionalPermissions);
        Assert.Equal(["https://graph.microsoft.com/.default"], SharePointConnector.GetDelegatedScopes(new Dictionary<string, string>()));
        var options = Microsoft365WorkloadOptions.Parse(new Dictionary<string, string>
        {
            ["Workloads"] = "teams;planner,ToDo\nonenote,sharedmail", ["SharedMailbox"] = "support@stratussecurity.com"
        });
        Assert.Equal(5, options.Enabled.Count);
        Assert.Contains("Mail.Read.Shared", options.DelegatedScopes());
        Assert.DoesNotContain(options.DelegatedScopes(), scope => scope.Contains("Write", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(9, Microsoft365WorkloadOptions.Parse(new Dictionary<string, string> { ["Workloads"] = "all" }).Enabled.Count);
    }
    [Theory]
    [InlineData("RequestAdditionalPermissions", "maybe")]
    [InlineData("ExcludeWorkloads", "unknown")]
    [InlineData("ScanStorage", "maybe")]
    [InlineData("Workloads", "unknown")]
    [InlineData("MaxWorkloadItems", "0")]
    [InlineData("MaxWorkloadItems", "10000001")]
    [InlineData("IncludePersonalTasks", "maybe")]
    [InlineData("EmbeddedContainerTypeId", "not-a-guid")]
    [InlineData("DataverseUrl", "http://org.crm.dynamics.com")]
    [InlineData("DataverseUrl", "https://org.crm.dynamics.com.evil.test")]
    [InlineData("DataverseUrl", "https://org.crm.dynamics.com/api/data")]
    public void InvalidWorkloadConfiguration_IsRejected(string key, string value)
        => Assert.Throws<ArgumentException>(() => Microsoft365WorkloadOptions.Parse(new Dictionary<string, string> { [key] = value }));

    [Fact]
    public void WorkloadOnlyScopes_IncludeAttachmentReadsAndRespectExplicitScopes()
    {
        var config = new Dictionary<string, string> { ["Workloads"] = "teams,planner", ["ScanStorage"] = "false", ["RequestAdditionalPermissions"] = "true" };
        var scopes = SharePointConnector.GetDelegatedScopes(config).ToArray();
        Assert.Contains("Files.Read.All", scopes);
        Assert.Contains("Sites.Read.All", scopes);
        Assert.DoesNotContain("User.Read.All", scopes);
        config["DelegatedScopes"] = "User.Read,Tasks.Read";
        Assert.Equal(["User.Read", "Tasks.Read"], SharePointConnector.GetDelegatedScopes(config));
    }

    [Fact]
    public async Task Connector_WorkloadOnlyDiscoveryDoesNotEnumerateStorage()
    {
        var graph = Graph(_ => throw new InvalidOperationException("Workload-only discovery must not request storage."));
        var workloads = Microsoft365WorkloadOptions.Parse(new Dictionary<string, string> { ["Workloads"] = "teams,planner,todo", ["ScanStorage"] = "false" });
        var connector = new SharePointConnector(graph, "tenant", workloads: workloads);
        var drives = (await connector.GetDrivesAsync()).ToList();
        Assert.Equal(3, drives.Count);
        Assert.True(connector.DiscoveryReport.IsComplete);
        Assert.Equal(3, connector.DiscoveryReport.SourceCounts["workload sources"]);
        Assert.Equal([DatastoreType.Teams, DatastoreType.Planner, DatastoreType.ToDo], drives.Select(drive => drive.DriveType));
    }

    [Fact]
    public async Task Connector_WorkloadOnlyResumeScopeBelongsToAuthenticatedPrincipal()
    {
        var options = new Microsoft365WorkloadOptions { Enabled = new HashSet<string> { "todo" }, ScanStorage = false };
        async Task<(string Scope, string Connection)> Discover(string principal)
        {
            var credential = new PrincipalCredential(principal);
            var connector = new SharePointConnector(Graph(_ => throw new InvalidOperationException("No storage request expected.")), "common",
                workloads: options, workloadCredential: credential, workloadAuthenticationScopes: ["Tasks.Read"]);
            var drive = Assert.Single(await connector.GetDrivesAsync());
            Assert.Equal(1, credential.Calls);
            Assert.Contains("/tenant/", drive.ConnectionId);
            return (connector.CheckpointScope, drive.ConnectionId);
        }
        var first = await Discover("first-principal");
        var second = await Discover("second-principal");
        Assert.NotEqual(first.Scope, second.Scope);
        Assert.Equal(first.Connection, second.Connection);
    }

    private sealed class PrincipalCredential(string principal) : TokenCredential
    {
        internal int Calls { get; private set; }
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken ct)
        {
            Calls++;
            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { tid = "tenant", oid = principal, azp = "client" })))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return new AccessToken("header." + payload + ".signature", DateTimeOffset.UtcNow.AddHours(1));
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken ct) => ValueTask.FromResult(GetToken(context, ct));
    }

    [Fact]
    public async Task Connector_MissingRequiredTargetsAreReportedIncomplete()
    {
        var options = Microsoft365WorkloadOptions.Parse(new Dictionary<string, string> { ["Workloads"] = "sharedmail,embedded,onenote", ["ScanStorage"] = "false" });
        var connector = new SharePointConnector(Graph(_ => Empty()), "tenant", workloads: options, workloadAppOnly: true);
        Assert.Empty(await connector.GetDrivesAsync());
        Assert.False(connector.DiscoveryReport.IsComplete);
        Assert.Empty(connector.DiscoveryReport.Warnings);
        Assert.Equal(3, connector.DiscoveryReport.CoverageNotes.Count);
    }

    [Fact]
    public async Task GraphReader_AcceptsEquivalentOdataKeyContinuations()
    {
        var calls = 0;
        var reader = new Microsoft365GraphReader(Graph(request =>
        {
            calls++;
            return request.RequestUri!.Query.Contains("skiptoken")
                ? Json(new { value = new[] { new { id = "second" } } })
                : Json(new Dictionary<string, object> { ["value"] = new[] { new { id = "first" } },
                    ["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/teams('team')/channels('channel')/messages?$skiptoken=next" });
        }));
        var ids = new List<string>();
        await foreach (var item in reader.EnumerateAsync("teams/team/channels/channel/messages", CancellationToken.None))
            ids.Add(item.GetProperty("id").GetString()!);
        Assert.Equal(["first", "second"], ids);
        Assert.Equal(2, calls);
        Assert.NotEqual(Microsoft365GraphReader.CollectionPath(new("https://graph.microsoft.com/v1.0/" + "users/a%2Fb/messages")),
            Microsoft365GraphReader.CollectionPath(new("https://graph.microsoft.com/v1.0/" + "users/a/b/messages")));
    }

    [Fact]
    public async Task Teams_RemovesTenantSegmentAndDeduplicatesSharedChannels()
    {
        var messageReads = 0;
        var drive = Drive("teams", request =>
        {
            var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            Assert.DoesNotContain("/tenants/", path);
            if (path.EndsWith("/allChannels")) return Json(new Dictionary<string, object> { ["value"] = new[] { new Dictionary<string, object>
                { ["id"] = "shared", ["@odata.id"] = "https://graph.microsoft.com/v1.0/tenants/tenant/teams/owner/channels/shared" } } });
            if (path.EndsWith("/channels/shared/messages")) { messageReads++; return Json(new { value = new[] { new { id = "message", body = new { content = "secret" } } } }); }
            return Empty();
        }, new() { TeamIds = ["first", "second"], ChatIds = ["empty"] });
        var result = await ScanAsync(drive, extension: ".json");
        Assert.False(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.Equal(1, messageReads);
    }

    [Fact]
    public async Task Teams_ResolvesOrdinaryAttachmentWithoutSharesOrWritePermissions()
    {
        var drive = Drive("teams", request =>
        {
            var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            Assert.DoesNotContain("/shares/", path);
            if (path.EndsWith("/allChannels")) return Json(new { value = new[] { new { id = "channel" } } });
            if (path.EndsWith("/channels/channel/messages")) return Json(new { value = new[] { new { id = "message",
                attachments = new[] { new { contentType = "reference", contentUrl = "https://contoso.sharepoint.com/sites/team/Documents/notes.txt" } } } } });
            if (path == "/v1.0/sites/contoso.sharepoint.com:/sites/team/Documents") return Response(HttpStatusCode.NotFound, "");
            if (path == "/v1.0/sites/contoso.sharepoint.com:/sites/team") return Json(new { id = "site" });
            if (path == "/v1.0/sites/site/drives") return Json(new { value = new[] { new { id = "drive", webUrl = "https://contoso.sharepoint.com/sites/team/Documents" } } });
            if (path == "/v1.0/drives/drive/root:/notes.txt") return Json(new { id = "file", name = "notes.txt", size = 6, eTag = "v1", parentReference = new { driveId = "drive" } });
            if (path == "/v1.0/drives/drive/items/file/content") return Response(HttpStatusCode.OK, "secret");
            return Empty();
        }, new() { TeamIds = ["team"], ChatIds = ["empty"] });
        var result = await ScanAsync(drive, extension: ".txt");
        Assert.False(result.Incomplete);
        Assert.Single(result.Findings);
    }

    [Fact]
    public async Task Teams_ChannelReplyPagesAndChatsAreScanned()
    {
        var requests = new List<string>();
        var drive = Drive("teams", request =>
        {
            var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            requests.Add(path + request.RequestUri.Query);
            if (path.EndsWith("/allChannels")) return Json(new { value = new[] { new { id = "channel" } } });
            if (path.EndsWith("/channels/channel/messages")) return Json(new { value = new[] { new { id = "root", body = new { content = "secret root" } } } });
            if (path.EndsWith("/replies") && !request.RequestUri.Query.Contains("skiptoken"))
                return Json(new { value = new[] { new { id = "reply1", body = new { content = "secret reply" } } },
                });
            if (path.EndsWith("/chats/chat/messages")) return Json(new { value = new[] { new { id = "chat-message", body = new { content = "secret chat" } } } });
            return Empty();
        }, new() { TeamIds = ["team"], ChatIds = ["chat"] });
        var result = await ScanAsync(drive, extension: ".json");
        Assert.False(result.Incomplete);
        Assert.Equal(3, result.Findings.Count);
        Assert.Contains(requests, path => path.Contains("/replies"));
        Assert.Contains(requests, path => path.Contains("/chats/chat/messages"));
    }

    [Fact]
    public async Task Teams_UsesCanonicalSharedChannelOwnerAndReplyContinuations()
    {
        var requests = new List<string>();
        var drive = Drive("teams", request =>
        {
            var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            requests.Add(path);
            if (path.EndsWith("/allChannels"))
                return Json(new Dictionary<string, object> { ["value"] = new[] { new Dictionary<string, object>
                { ["id"] = "shared", ["@odata.id"] = "https://graph.microsoft.com/v1.0/teams/owner/channels/shared" } } });
            if (path.EndsWith("/owner/channels/shared/messages")) return Json(new { value = new[] { new { id = "root", body = new { content = "public" } } } });
            if (path.EndsWith("/replies"))
                return request.RequestUri.Query.Contains("skiptoken") ? Json(new { value = new[] { new { id = "second", body = new { content = "secret" } } } })
                    : Json(new Dictionary<string, object> { ["value"] = new[] { new { id = "first", body = new { content = "public" } } },
                        ["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/teams/owner/channels/shared/messages/root/replies?$skiptoken=next" });
            return Empty();
        }, new() { TeamIds = ["member"], ChatIds = ["empty"] });
        var result = await ScanAsync(drive, extension: ".json");
        Assert.False(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.Contains(requests, path => path.Contains("/teams/owner/"));
        Assert.DoesNotContain(requests, path => path.Contains("/teams/member/channels/"));
    }

    [Fact]
    public async Task Planner_ReadsDescriptionsAndChecklistFromTaskDetails()
    {
        var drive = Drive("planner", request => request.RequestUri!.AbsolutePath switch
        {
            "/v1.0/planner/plans/plan" => Json(new { id = "plan", title = "plan" }),
            "/v1.0/planner/plans/plan/details" => Json(new { categoryDescriptions = new { category1 = "secret" } }),
            "/v1.0/planner/plans/plan/tasks" => Json(new { value = new[] { new { id = "task", title = "Task" } } }),
            "/v1.0/planner/tasks/task/details" => Json(new { description = "secret", checklist = new { first = new { title = "secret" } } }),
            _ => Empty()
        }, new() { PlanIds = ["plan"] });
        var result = await ScanAsync(drive, extension: ".json");
        Assert.False(result.Incomplete);
        Assert.Equal(2, result.Findings.Count);
        Assert.Equal("https://contoso.sharepoint.com/file%20name.docx",
            Microsoft365GraphWorkloadDrive.DecodePlannerReference("https%3A//contoso%2Esharepoint%2Ecom/file%2520name%2Edocx"));
    }

    [Fact]
    public async Task ToDo_SkipsPersonalListsAndReadsSharedBodiesLinksAndAttachments()
    {
        var requests = new List<string>();
        var drive = Drive("todo", request =>
        {
            var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            requests.Add(path);
            return path switch
            {
                "/v1.0/me/todo/lists" => Json(new { value = new[] { new { id = "personal", isShared = false }, new { id = "shared", isShared = true } } }),
                "/v1.0/me/todo/lists/shared/tasks" => Json(new { value = new[] { new { id = "task", body = new { content = "secret" } } } }),
                "/v1.0/me/todo/lists/shared/tasks/task/attachments" => Json(new Dictionary<string, object> { ["value"] = new[] { new Dictionary<string, object>
                    { ["id"] = "file", ["@odata.type"] = "#microsoft.graph.taskFileAttachment", ["name"] = "notes.txt", ["size"] = 6 } } }),
                "/v1.0/me/todo/lists/shared/tasks/task/attachments/file/$value" => Response(HttpStatusCode.OK, "secret"),
                "/v1.0/me/todo/lists/shared/tasks/task/linkedResources" => Json(new { value = new[] { new { id = "link", displayName = "secret" } } }),
                _ => Empty()
            };
        });
        var result = await ScanAsync(drive, classifiers: [ContentRule(".json"), ContentRule(".txt")]);
        Assert.False(result.Incomplete);
        Assert.Equal(3, result.Findings.Count);
        Assert.DoesNotContain(requests, path => path.Contains("/personal/"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SharedMail_ExcludesPersonalMailboxBeforeReadingMessages(bool appOnly)
    {
        var paths = new List<string>();
        var drive = Drive("sharedmail", request =>
        {
            var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            paths.Add(path);
            if (path == "/v1.0/me") return Json(new { id = "self" });
            if (path == "/v1.0/" + "users/alias@stratussecurity.com") return Json(new { id = "self" });
            if (path.EndsWith("/userPurpose")) return Json(new { value = "user" });
            throw new InvalidOperationException("Personal mailbox content must not be requested.");
        }, new() { SharedMailboxes = ["alias@stratussecurity.com"] }, appOnly);
        var result = await ScanAsync(drive, extension: ".json");
        Assert.True(result.Incomplete);
        Assert.Empty(result.Findings);
        Assert.DoesNotContain(paths, path => path.Contains("/mailFolders") || path.Contains("/messages"));
        Assert.Equal(1, drive.EnumerationFailureCount);
        Assert.Contains(appOnly ? "not classified as shared" : "own mailbox", Assert.Single(drive.EnumerationFailures).Exception.Message);
    }

    [Fact]
    public async Task SharedMail_ResolvesSmtpAliasesBeforeOwnMailboxExclusion()
    {
        var requests = new List<string>();
        var drive = Drive("sharedmail", request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            requests.Add(path);
            if (path == "/v1.0/me") return Json(new { id = "self" });
            if (path.EndsWith("alias%40stratussecurity.com")) return Response(HttpStatusCode.NotFound, "");
            if (path == "/v1.0/" + "users")
            {
                Assert.Contains("proxyAddresses", Uri.UnescapeDataString(request.RequestUri.Query));
                Assert.Equal("eventual", Assert.Single(request.Headers.GetValues("ConsistencyLevel")));
                return Json(new { value = new[] { new { id = "self" } } });
            }
            throw new InvalidOperationException("Personal mailbox content must not be requested.");
        }, new() { SharedMailboxes = ["alias@stratussecurity.com"] });
        var result = await ScanAsync(drive, extension: ".json");
        Assert.True(result.Incomplete);
        Assert.Contains("own mailbox", Assert.Single(drive.EnumerationFailures).Exception.Message);
        Assert.DoesNotContain(requests, path => path.Contains("/messages") || path.Contains("/mailFolders"));
    }

    [Fact]
    public async Task SharedMail_HiddenChildFoldersCycleAndAttachmentsAreHandled()
    {
        var requests = new List<string>();
        var drive = Drive("sharedmail", request =>
        {
            var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            requests.Add(path);
            if (path == "/v1.0/me") return Json(new { id = "self" });
            if (path == "/v1.0/" + "users/shared@stratussecurity.com") return Json(new { id = "shared" });
            if (path == "/v1.0/" + "users/shared/mailFolders") return Json(new { value = new[] { new { id = "parent" } } });
            if (path.EndsWith("/parent/childFolders")) return Json(new { value = new[] { new { id = "child" } } });
            if (path.EndsWith("/child/childFolders")) return Json(new { value = new[] { new { id = "parent" } } });
            if (path.EndsWith("/child/messages")) return Json(new { value = new[] { new { id = "message", subject = "subject", body = new { content = "<p>secret</p>" }, hasAttachments = true } } });
            if (path.EndsWith("/message/attachments")) return Json(new Dictionary<string, object> { ["value"] = new[] { new Dictionary<string, object>
                { ["id"] = "file", ["name"] = "notes.txt", ["@odata.type"] = "#microsoft.graph.fileAttachment", ["size"] = 6 } } });
            if (path.EndsWith("/file/$value")) return Response(HttpStatusCode.OK, "secret");
            return Empty();
        }, new() { SharedMailboxes = ["shared@stratussecurity.com"] });
        var result = await ScanAsync(drive, classifiers: [ContentRule(".json"), ContentRule(".txt")]);
        Assert.False(result.Incomplete);
        Assert.Equal(2, result.Findings.Count);
        Assert.Equal(1, requests.Count(path => path.EndsWith("/parent/childFolders")));
        Assert.DoesNotContain(requests, path => path.StartsWith("/v1.0/me/mail"));
    }

    [Theory]
    [InlineData("https://graph.microsoft.com/v1.0/me/messages")]
    [InlineData("https://evil.test/v1.0/notes")]
    public async Task CollectionContinuations_CannotChangeMailboxOrOrigin(string link)
    {
        var calls = 0;
        var drive = Drive("todo", request =>
        {
            calls++;
            return Json(new Dictionary<string, object> { ["value"] = new[] { new { id = "list", isShared = true } }, ["@odata.nextLink"] = link });
        });
        var result = await ScanAsync(drive, extension: ".json");
        Assert.True(result.Incomplete);
        // Task/attachment calls can fail as they see the deliberately malformed fixture,
        // but the continuation itself must never be issued.
        Assert.True(calls < 8);
    }

    [Fact]
    public async Task OneNote_ReadsPageHtmlAndEmbeddedFiles()
    {
        var drive = Drive("onenote", request => request.RequestUri!.AbsolutePath switch
        {
            "/v1.0/me/onenote/pages" => Json(new { value = new[] { new { id = "page", title = "Notes", lastModifiedDateTime = "v1" } } }),
            "/v1.0/me/onenote/pages/page/content" => Response(HttpStatusCode.OK,
                "<html><body><p>se&#99;ret</p><object data-attachment='notes.txt' data='https://graph.microsoft.com/v1.0/me/onenote/resources/file/content'></object></body></html>"),
            "/v1.0/me/onenote/resources/file/content" => Response(HttpStatusCode.OK, "secret"),
            _ => Empty()
        });
        var result = await ScanAsync(drive, classifiers: [ContentRule(".json"), ContentRule(".txt")]);
        Assert.False(result.Incomplete);
        Assert.Equal(2, result.Findings.Count);
    }
    [Fact]
    public async Task OneNote_AppOnlyIsExplicitlyUnavailableWithoutMakingRequests()
    {
        var drive = Drive("onenote", _ => throw new InvalidOperationException(), appOnly: true);
        var result = await ScanAsync(drive, extension: ".json");
        Assert.True(result.Incomplete);
        Assert.Contains("retired", Assert.Single(drive.EnumerationFailures).Exception.Message);
    }
    [Fact]
    public async Task ConsumerFailure_PropagatesInsteadOfBeingHiddenAsAReadFailure()
    {
        var drive = Drive("todo", _ => Json(new { value = new[] { new { id = "list", isShared = true } } }));
        var error = new IOException("Journal commit failed");
        var actual = await Assert.ThrowsAsync<IOException>(() => drive.ProcessChangesAsync(null, _ => throw error));
        Assert.Same(error, actual);
        Assert.Equal(0, drive.EnumerationFailureCount);
    }
    [Fact]
    public async Task FailedSource_KeepsOtherFindingsButPreventsCompletion()
    {
        var drive = Drive("planner", request => request.RequestUri!.AbsolutePath switch
        {
            "/v1.0/planner/plans/plan" => Json(new { id = "plan", title = "secret" }),
            "/v1.0/planner/plans/plan/details" => Response(HttpStatusCode.Forbidden, ""),
            _ => Empty()
        }, new() { PlanIds = ["plan"] });
        var result = await ScanAsync(drive, extension: ".json");
        Assert.True(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.Empty(result.Checkpoints);
        Assert.Null(result.FinalToken);
    }
    [Fact]
    public async Task ServiceReader_RejectsForeignContinuationWithoutForwardingToken()
    {
        var requests = new List<Uri>();
        using var api = new Microsoft365ServiceReader(new StubCredential(), new("https://api.powerbi.com/v1.0/myorg/"), ["scope"],
            new Handler(request => { requests.Add(request.RequestUri!); return Json(new Dictionary<string, object>
            { ["value"] = Array.Empty<object>(), ["nextLink"] = "https://evil.test/collect" }); }));
        await Assert.ThrowsAsync<InvalidDataException>(async () => { await foreach (var _ in api.Enumerate("groups", CancellationToken.None)) { } });
        Assert.Single(requests);
        Assert.Equal("api.powerbi.com", requests[0].Host);
    }
    [Fact]
    public async Task ServiceReader_RejectsPartialDocumentInsteadOfScanningItsPrefixAsComplete()
    {
        using var api = new Microsoft365ServiceReader(new StubCredential(), new("https://org.crm.dynamics.com/api/data/v9.2/"), ["scope"],
            new Handler(_ =>
            {
                var response = Response(HttpStatusCode.PartialContent, "secret");
                response.Content.Headers.ContentRange = new(0, 5, 100);
                return response;
            }));
        await Assert.ThrowsAsync<InvalidDataException>(() => api.Open(new(api.Root, "document/$value"), CancellationToken.None));
    }
    [Fact]
    public async Task PowerBI_ScansParametersDataSourcesAndDataflowDefinitions()
    {
        using var api = new Microsoft365ServiceReader(new StubCredential(), new("https://api.powerbi.com/v1.0/myorg/"), ["scope"],
            new Handler(request => request.RequestUri!.AbsolutePath switch
            {
                "/v1.0/myorg/groups" => Json(new { value = new[] { new { id = "workspace" } } }),
                "/v1.0/myorg/groups/workspace/datasets" => Json(new { value = new[] { new { id = "dataset" } } }),
                "/v1.0/myorg/groups/workspace/datasets/dataset/parameters" => Json(new { value = new[] { new { name = "Password", currentValue = "secret" } } }),
                "/v1.0/myorg/groups/workspace/datasets/dataset/datasources" => Json(new { value = new[] { new { connectionDetails = new { server = "secret" } } } }),
                "/v1.0/myorg/groups/workspace/dataflows" => Json(new { value = new[] { new { objectId = "flow" } } }),
                "/v1.0/myorg/groups/workspace/dataflows/flow" => Json(new { expression = "secret" }),
                _ => Empty()
            }));
        using var drive = new Microsoft365PowerBIDrive(api, "tenant", 100);
        var result = await ScanAsync(drive, extension: ".json");
        Assert.False(result.Incomplete);
        Assert.Equal(3, result.Findings.Count);
    }
    [Fact]
    public async Task PowerPlatform_UsesGlobalOdataDiscoveryAndReadsAppPackagesLazily()
    {
        var package = new MemoryStream();
        using (var zip = new ZipArchive(package, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var writer = new StreamWriter(zip.CreateEntry("Src/Screen.fx").Open());
            writer.Write("secret");
        }
        var payload = package.ToArray();
        const string appId = "00000000-0000-0000-0000-000000000001";
        var downloads = 0;
        Microsoft365ServiceReader Api(Uri root, string[] scopes) => new(new StubCredential(), root, scopes,
            new Handler(request =>
            {
                var path = request.RequestUri!.AbsolutePath;
                if (path.EndsWith("/Instances")) return Json(new { value = new[] { new { ApiUrl = "https://org.crm.dynamics.com/api/data/v9.2/" } } });
                if (path.EndsWith("/workflows")) return Json(new { value = new[] { new { workflowid = "flow", clientdata = "{\"description\":\"secret\"}" } } });
                if (path.EndsWith("/canvasapps")) return Json(new { value = new[] { new { canvasappid = appId, name = "app", modifiedon = "v1" } } });
                if (path.EndsWith("/document/$value"))
                {
                    downloads++;
                    return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) };
                }
                return Empty();
            }));
        var drive = new Microsoft365PowerPlatformDrive(new StubCredential(), "tenant", new(), Api);
        var files = (await drive.GetChangesAsync(null)).Changes.ToArray();
        Assert.Equal(0, downloads);
        var app = Assert.Single(files, file => file.Name.EndsWith(".msapp"));
        using (var stream = await app.GetContentAsync()) Assert.NotNull(stream);
        Assert.Equal(1, downloads);
        var result = await ScanAsync(drive, classifiers: [ContentRule(".json"), ContentRule(".fx")],
            options: new Stratus.Sift.Scanner.Models.ScanOptions { EnableZipArchives = true });
        Assert.False(result.Incomplete);
        Assert.Equal(2, result.Findings.Count);
    }
    [Fact]
    public async Task Embedded_ScansSupportedFilesAndConvertedLoopContent()
    {
        var requests = new List<string>();
        var graph = Graph(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            requests.Add(path);
            if (path.EndsWith("/containers/container/drive")) return Json(new { id = "drive", name = "Container", webUrl = "https://contoso.sharepoint.com/container" });
            if (path.Contains("/delta", StringComparison.Ordinal)) return Json(new Dictionary<string, object> { ["value"] = new[] {
                new { id = "loop", name = "notes.loop", size = 6, eTag = "v1", webUrl = "https://contoso.sharepoint.com/notes.loop", file = new { mimeType = "application/octet-stream" } },
                new { id = "text", name = "notes.txt", size = 6, eTag = "v1", webUrl = "https://contoso.sharepoint.com/notes.txt", file = new { mimeType = "text/plain" } } },
                ["@odata.deltaLink"] = "https://graph.microsoft.com/v1.0/drives/drive/root/delta?token=end" });
            if (path.EndsWith("/items/text/content")) return Response(HttpStatusCode.OK, "secret");
            if (path.EndsWith("/items/loop/content")) { Assert.Contains("format=html", request.RequestUri.Query); return Response(HttpStatusCode.OK, "<p>se&#99;ret</p>"); }
            return Empty();
        });
        var drive = new Microsoft365EmbeddedDrive(graph, "tenant", new() { ContainerIds = ["container"] }, Microsoft365CoverageOptions.Disabled);
        var result = await ScanAsync(drive, classifiers: [ContentRule(".txt"), ContentRule(".html")]);
        Assert.False(result.Incomplete);
        Assert.True(result.Findings.Count == 2, string.Join("\n", requests.Concat(drive.EnumerationFailures.Select(failure => failure.Exception.Message))));
        Assert.Equal(0, drive.EnumerationFailureCount);
        Assert.Empty(result.Checkpoints);
    }

    [Fact]
    public async Task Engage_ReadsOlderMessagesAndStopsOnNonadvancingCursor()
    {
        var requests = new List<string>();
        using var api = new Microsoft365ServiceReader(new StubCredential(), new("https://www.yammer.com/api/v1/"), ["scope"],
            new Handler(request =>
            {
                var path = request.RequestUri!.AbsolutePath;
                requests.Add(path + request.RequestUri.Query);
                if (path.EndsWith("/groups.json")) return request.RequestUri.Query.Contains("page=2") ? Json(Array.Empty<object>())
                    : Json(new[] { new { id = 1, name = "community" } });
                if (path.Contains("/messages/in_group/")) return Json(new { messages = new[] { new { id = 10, body = new { plain = "secret" } } } });
                return Empty();
            }));
        using var drive = new Microsoft365EngageDrive(api, "tenant", 100);
        var result = await ScanAsync(drive, extension: ".json");
        Assert.True(result.Incomplete);
        Assert.Single(result.Findings);
        Assert.Equal(2, requests.Count(path => path.Contains("/messages/in_group/")));
        Assert.Contains("repeated", Assert.Single(drive.EnumerationFailures).Exception.Message);
    }
    [Fact]
    public async Task WorkloadItemLimit_ReportsPartialInsteadOfLoopingOrClaimingCompletion()
    {
        var drive = Drive("todo", request => request.RequestUri!.AbsolutePath.EndsWith("/lists")
            ? Json(new { value = new[] { new { id = "first", isShared = true }, new { id = "second", isShared = true } } }) : Empty(),
            new() { MaxItems = 1 });
        var result = await ScanAsync(drive, extension: ".json");
        Assert.True(result.Incomplete);
        Assert.Equal(1, result.Processed);
        Assert.Contains("MaxWorkloadItems", Assert.Single(drive.EnumerationFailures).Exception.Message);
    }
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => Task.FromResult(callback(request));
    }
}
