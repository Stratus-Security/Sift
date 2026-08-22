using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Atlassian;

namespace Stratus.Sift.Connectors.Tests;

public class AtlassianConnectorTests
{
    [Fact]
    public void ProviderName_IsAtlassian()
    {
        var connector = new AtlassianConnector(new HttpClient(new DelegateHandler(_ => Task.FromResult(Json("{}")))));

        Assert.Equal("Atlassian", connector.ProviderName);
    }

    [Fact]
    public void LegacyJiraConnector_ForwardsToAtlassianConnector()
    {
#pragma warning disable CS0618
        var connector = new Stratus.Sift.Connectors.Jira.JiraConnector(
            new HttpClient(new DelegateHandler(_ => Task.FromResult(Json("{}")))));
#pragma warning restore CS0618

        Assert.Equal("Atlassian", connector.ProviderName);
    }

    [Fact]
    public async Task ConfluenceDiscovery_ContinuesWhenJiraIsUnavailable()
    {
        var handler = new DelegateHandler(request => Task.FromResult(request.RequestUri!.AbsolutePath switch
        {
            "/rest/api/3/myself" => new HttpResponseMessage(HttpStatusCode.Forbidden),
            "/wiki/api/v2/spaces" => Json("""{"results":[{"id":"200","key":"ENG","name":"Engineering"}],"_links":{}}"""),
            _ => throw new InvalidOperationException(request.RequestUri.AbsolutePath)
        }));
        var connector = new AtlassianConnector(new HttpClient(handler));

        await connector.InitializeAsync(new Dictionary<string, string>
        {
            ["Url"] = "https://example.atlassian.net",
            ["Email"] = "user@stratus.security",
            ["Token"] = "api-token"
        });

        var drive = Assert.Single(await connector.GetDrivesAsync());
        Assert.Equal(Stratus.Sift.Core.Enums.DatastoreType.Confluence, drive.DriveType);
        Assert.Equal("Confluence: ENG - Engineering", drive.Name);
    }

    [Fact]
    public async Task ApiClient_ParsesAtlassianResponsesDeeperThanDefaultLimit()
    {
        var nestedValue = "\"deep secret\"";
        for (var depth = 0; depth < 80; depth++)
        {
            nestedValue = $"[{nestedValue}]";
        }

        var handler = new DelegateHandler(_ => Task.FromResult(Json($"{{\"value\":{nestedValue}}}")));
        var api = new AtlassianApiClient(new HttpClient(handler), new Uri("https://example.atlassian.net/"));

        using var document = await api.GetJsonAsync("rest/api/3/search/jql", CancellationToken.None);
        var extracted = JiraDrive.GetFlexibleValueText(document.RootElement.GetProperty("value"));

        Assert.Equal("deep secret", extracted);
    }

    [Fact]
    public async Task OAuthAuthentication_DiscoversCloudIdAndUsesGateway()
    {
        var requests = new List<(Uri Uri, AuthenticationHeaderValue? Authorization)>();
        var handler = new DelegateHandler(async request =>
        {
            requests.Add((request.RequestUri!, request.Headers.Authorization));
            return Json(request.RequestUri!.AbsolutePath switch
            {
                "/oauth/token/accessible-resources" => """[{"id":"cloud-1","url":"https://example.atlassian.net"}]""",
                "/ex/jira/cloud-1/rest/api/3/myself" => "{}",
                "/ex/jira/cloud-1/rest/api/3/field" => "[]",
                _ => throw new InvalidOperationException(request.RequestUri.AbsolutePath)
            });
        });
        var connector = new AtlassianConnector(new HttpClient(handler));

        await connector.InitializeAsync(new Dictionary<string, string>
        {
            ["Url"] = "https://example.atlassian.net",
            ["Token"] = "oauth-token"
        });

        Assert.Contains(requests, request => request.Uri.AbsolutePath == "/oauth/token/accessible-resources");
        Assert.Contains(requests, request => request.Uri.AbsolutePath == "/ex/jira/cloud-1/rest/api/3/myself");
        Assert.All(requests, request =>
        {
            Assert.Equal("Bearer", request.Authorization?.Scheme);
            Assert.Equal("oauth-token", request.Authorization?.Parameter);
        });
    }

    [Fact]
    public async Task IssueScan_IncludesCustomFieldsAndStableNumericAttachmentId()
    {
        string? searchBody = null;
        var handler = new DelegateHandler(async request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                searchBody = await request.Content!.ReadAsStringAsync();
            }

            return Json(request.RequestUri!.AbsolutePath switch
            {
                "/rest/api/3/myself" => "{}",
                "/rest/api/3/field" => """[{"id":"customfield_10001","name":"Sensitive custom field","custom":true}]""",
                "/rest/api/3/project/search" => """{"values":[{"id":"10000","key":"SEC","name":"Security"}],"total":1}""",
                "/rest/api/3/search/jql" => """{"isLast":true,"issues":[{"id":"20000","key":"SEC-1","fields":{"summary":"Test","description":null,"environment":null,"attachment":[{"id":10001,"filename":"evidence.txt","size":20,"mimeType":"text/plain"}],"labels":[],"status":{"name":"Open"},"reporter":{"displayName":"Reporter"},"assignee":null,"created":"2026-07-01T00:00:00Z","updated":"2026-07-02T00:00:00Z","customfield_10001":{"value":"custom secret"}}}]}""",
                "/rest/api/3/issue/SEC-1/comment" => """{"comments":[],"startAt":0,"total":0}""",
                _ => throw new InvalidOperationException(request.RequestUri.AbsolutePath)
            });
        });
        var connector = new AtlassianConnector(new HttpClient(handler));
        await connector.InitializeAsync(new Dictionary<string, string>
        {
            ["Url"] = "https://example.atlassian.net",
            ["Email"] = "user@stratus.security",
            ["Token"] = "api-token"
        });
        var drive = Assert.Single(await connector.GetDrivesAsync());
        Assert.Equal(Stratus.Sift.Core.Enums.DatastoreType.Jira, drive.DriveType);

        var (changes, _) = await drive.GetChangesAsync(null);
        var files = changes.ToList();
        var issue = Assert.Single(files, file => file.Name == "SEC-1.txt");
        var attachment = Assert.Single(files, file => file.Name == "evidence.txt");
        await using var content = await issue.GetContentAsync();
        using var reader = new StreamReader(content!);

        Assert.Contains("custom secret", await reader.ReadToEndAsync());
        Assert.Equal("10001", attachment.Id);
        Assert.Contains("customfield_10001", searchBody);
        Assert.DoesNotContain("nextPageToken", searchBody);
        Assert.Contains("ORDER BY updated DESC", searchBody);
    }

    [Fact]
    public async Task DeltaToken_WithDifferentJql_DoesNotReuseOldTimestamp()
    {
        var jqlBodies = new List<string>();
        var handler = new DelegateHandler(async request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                jqlBodies.Add(await request.Content!.ReadAsStringAsync());
            }

            return Json("""{"isLast":true,"issues":[]}""");
        });
        var api = new AtlassianApiClient(new HttpClient(handler), new Uri("https://example.atlassian.net/"));
        var firstDrive = new JiraDrive(api, new Uri("https://example.atlassian.net/"), "1", "SEC", "Security", "status = Open", new Dictionary<string, string>());
        var secondDrive = new JiraDrive(api, new Uri("https://example.atlassian.net/"), "1", "SEC", "Security", "status = Closed", new Dictionary<string, string>());

        var token = await firstDrive.ProcessChangesAsync(null, _ => Task.CompletedTask);
        await secondDrive.ProcessChangesAsync(token, _ => Task.CompletedTask);

        using var secondRequest = JsonDocument.Parse(jqlBodies[1]);
        var secondJql = secondRequest.RootElement.GetProperty("jql").GetString();
        Assert.DoesNotContain("updated >=", secondJql);
    }

    [Fact]
    public async Task DeltaToken_WithSameJql_RemainsReusableWithNewestFirstOrdering()
    {
        var jqlBodies = new List<string>();
        var handler = new DelegateHandler(async request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                jqlBodies.Add(await request.Content!.ReadAsStringAsync());
            }

            return Json("""{"isLast":true,"issues":[]}""");
        });
        var api = new AtlassianApiClient(new HttpClient(handler), new Uri("https://example.atlassian.net/"));
        var drive = new JiraDrive(api, new Uri("https://example.atlassian.net/"), "1", "SEC", "Security", null, new Dictionary<string, string>());

        var token = await drive.ProcessChangesAsync(null, _ => Task.CompletedTask);
        await drive.ProcessChangesAsync(token, _ => Task.CompletedTask);

        using var secondRequest = JsonDocument.Parse(jqlBodies[1]);
        var secondJql = secondRequest.RootElement.GetProperty("jql").GetString();
        Assert.Contains("updated >=", secondJql);
        Assert.EndsWith("ORDER BY updated DESC", secondJql);
    }

    [Fact]
    public async Task ConfluenceScan_TraversesPagesCommentsRepliesAndAttachments()
    {
        var requestedUris = new List<Uri>();
        var handler = new DelegateHandler(request =>
        {
            requestedUris.Add(request.RequestUri!);
            return Task.FromResult(Json(request.RequestUri!.AbsolutePath switch
        {
            "/rest/api/3/myself" => "{}",
            "/rest/api/3/field" => "[]",
            "/rest/api/3/project/search" => """{"values":[],"total":0}""",
            "/wiki/api/v2/spaces" => """{"results":[{"id":"200","key":"ENG","name":"Engineering"}],"_links":{}}""",
            "/wiki/api/v2/spaces/200/pages" => """
                {"results":[{"id":"300","title":"Runbook","spaceId":"200","authorId":"U1","createdAt":"2026-07-01T00:00:00Z","version":{"createdAt":"2026-07-02T00:00:00Z","authorId":"U1"},"body":{"atlas_doc_format":{"value":"{\"type\":\"doc\",\"content\":[{\"type\":\"text\",\"text\":\"page secret\"}]}"}},"_links":{"webui":"/spaces/ENG/pages/300"}}],"_links":{}}
                """,
            "/wiki/api/v2/pages/300/footer-comments" => """{"results":[{"id":"400","version":{"createdAt":"2026-07-03T00:00:00Z","authorId":"U2"},"body":{"atlas_doc_format":{"value":"{\"text\":\"comment secret\"}"}},"_links":{}}],"_links":{}}""",
            "/wiki/api/v2/footer-comments/400/children" => """{"results":[{"id":"401","version":{"createdAt":"2026-07-04T00:00:00Z","authorId":"U3"},"body":{"atlas_doc_format":{"value":"{\"text\":\"reply secret\"}"}},"_links":{}}],"_links":{}}""",
            "/wiki/api/v2/footer-comments/401/children" => """{"results":[],"_links":{}}""",
            "/wiki/api/v2/pages/300/inline-comments" => """{"results":[],"_links":{}}""",
            "/wiki/api/v2/pages/300/attachments" => """{"results":[{"id":"500","title":"evidence.txt","fileSize":12,"mediaType":"text/plain","createdAt":"2026-07-05T00:00:00Z","version":{"createdAt":"2026-07-05T00:00:00Z"},"_links":{}}],"_links":{}}""",
            "/wiki/api/v2/attachments/500/footer-comments" => """{"results":[],"_links":{}}""",
            "/wiki/api/v2/spaces/200/blogposts" => """{"results":[{"id":"600","title":"Incident update","spaceId":"200","authorId":"U4","createdAt":"2026-07-06T00:00:00Z","version":{"createdAt":"2026-07-06T01:00:00Z","authorId":"U4"},"body":{"atlas_doc_format":{"value":"{\"type\":\"doc\",\"content\":[{\"type\":\"text\",\"text\":\"blog secret\"}]}"}},"_links":{"webui":"/spaces/ENG/blog/600"}}],"_links":{}}""",
            "/wiki/api/v2/blogposts/600/footer-comments" => """{"results":[],"_links":{}}""",
            "/wiki/api/v2/blogposts/600/inline-comments" => """{"results":[],"_links":{}}""",
            "/wiki/api/v2/blogposts/600/attachments" => """{"results":[],"_links":{}}""",
            _ => throw new InvalidOperationException(request.RequestUri.AbsolutePath)
            }));
        });
        var connector = new AtlassianConnector(new HttpClient(handler));
        await connector.InitializeAsync(new Dictionary<string, string>
        {
            ["Url"] = "https://example.atlassian.net",
            ["Email"] = "user@stratus.security",
            ["Token"] = "api-token"
        });

        var drive = Assert.Single(await connector.GetDrivesAsync());
        var (changes, token) = await drive.GetChangesAsync(null);
        var files = changes.ToArray();

        Assert.Equal(Stratus.Sift.Core.Enums.DatastoreType.Confluence, drive.DriveType);
        Assert.Equal(5, files.Length);
        Assert.Contains(files, file => file.Name == "Runbook.txt");
        Assert.Contains(files, file => file.Name == "footer-comment-400.txt");
        Assert.Contains(files, file => file.Name == "footer-comment-401.txt");
        Assert.Contains(files, file => file.Name == "evidence.txt");
        Assert.Contains(files, file => file.Name == "Incident update.txt");
        Assert.True(DateTimeOffset.TryParse(token, out _));
        var page = Assert.Single(files, file => file.Name == "Runbook.txt");
        await using var content = await page.GetContentAsync();
        using var reader = new StreamReader(content!);
        Assert.Contains("page secret", await reader.ReadToEndAsync());
        AssertNewestFirstQuery("/wiki/api/v2/spaces/200/pages");
        AssertNewestFirstQuery("/wiki/api/v2/spaces/200/blogposts");
        AssertNewestFirstQuery("/wiki/api/v2/pages/300/footer-comments");
        AssertNewestFirstQuery("/wiki/api/v2/footer-comments/400/children");
        AssertNewestFirstQuery("/wiki/api/v2/pages/300/attachments");

        void AssertNewestFirstQuery(string path)
        {
            Assert.Contains(
                requestedUris,
                uri => uri.AbsolutePath == path
                    && uri.Query.Contains("sort=-modified-date", StringComparison.Ordinal));
        }
    }

    private static HttpResponseMessage Json(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return callback(request);
        }
    }
}
