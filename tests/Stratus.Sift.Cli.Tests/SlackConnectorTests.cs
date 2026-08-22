using System.Net;
using System.Text.Json;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Slack;

namespace Stratus.Sift.Connectors.Tests;

public class SlackConnectorTests
{
    [Fact]
    public async Task IncrementalScan_FindsOldEditedParentAndNewReply()
    {
        var requests = new List<Uri>();
        var handler = new DelegateHandler(request =>
        {
            requests.Add(request.RequestUri!);
            return Json(request.RequestUri!.AbsolutePath switch
            {
                "/api/auth.test" => """{"ok":true,"team_id":"T1","team":"Test","url":"https://test.slack.com/"}""",
                "/api/conversations.list" => """{"ok":true,"channels":[{"id":"C1","name":"security"}],"response_metadata":{"next_cursor":""}}""",
                "/api/conversations.history" => """{"ok":true,"messages":[{"type":"message","user":"U1","text":"edited parent","ts":"100.000001","edited":{"ts":"250.000001"},"reply_count":1,"latest_reply":"300.000001"}],"response_metadata":{"next_cursor":""}}""",
                "/api/conversations.replies" => """{"ok":true,"messages":[{"type":"message","user":"U1","text":"parent","ts":"100.000001"},{"type":"message","user":"U2","text":"new reply","ts":"300.000001","thread_ts":"100.000001"}],"response_metadata":{"next_cursor":""}}""",
                _ => throw new InvalidOperationException(request.RequestUri.AbsolutePath)
            });
        });
        var connector = new SlackConnector(new HttpClient(handler));
        await connector.InitializeAsync(new Dictionary<string, string> { ["Token"] = "xoxb-test" });
        var drive = Assert.Single(await connector.GetDrivesAsync());
        var changes = new List<IRemoteFile>();

        var token = await drive.ProcessChangesAsync("200.000001", file =>
        {
            changes.Add(file);
            return Task.CompletedTask;
        });

        Assert.Equal("300.000001", token);
        Assert.Contains(changes, file => file.Name == "message-100-000001.txt");
        Assert.Contains(changes, file => file.Name == "message-300-000001.txt");
        Assert.DoesNotContain("oldest=", requests.Single(uri => uri.AbsolutePath.EndsWith("conversations.history", StringComparison.Ordinal)).Query);
        var listQueries = requests.Where(uri => uri.AbsolutePath.EndsWith("conversations.list", StringComparison.Ordinal)).Select(uri => uri.Query).ToArray();
        Assert.Equal(4, listQueries.Length);
        Assert.All(listQueries, query => Assert.Contains("exclude_archived=false", query));
        Assert.Contains(listQueries, query => query.Contains("types=im", StringComparison.Ordinal));
        Assert.Contains(listQueries, query => query.Contains("types=mpim", StringComparison.Ordinal));
        var repliesQuery = requests.Single(uri => uri.AbsolutePath.EndsWith("conversations.replies", StringComparison.Ordinal)).Query;
        Assert.Contains("limit=15", repliesQuery);
        Assert.Contains("oldest=200.000001", repliesQuery);
    }

    [Fact]
    public void ExtractMessageText_IncludesLegacyAttachmentContent()
    {
        using var document = JsonDocument.Parse("""
            {"text":"message","attachments":[{"pretext":"pre secret","title":"title secret","text":"body secret","fallback":"fallback secret","fields":[{"title":"field","value":"field secret"}]}]}
            """);

        var text = SlackDrive.ExtractMessageText(document.RootElement);

        Assert.Contains("pre secret", text);
        Assert.Contains("body secret", text);
        Assert.Contains("field secret", text);
    }

    [Fact]
    public async Task RateLimitGate_PacesSubsequentCallsForTheLimitedMethodOnly()
    {
        var now = new DateTimeOffset(2026, 7, 14, 0, 0, 0, TimeSpan.Zero);
        var delays = new List<TimeSpan>();
        var gate = new SlackRateLimitGate(
            () => now,
            (delay, _) =>
            {
                delays.Add(delay);
                now += delay;
                return Task.CompletedTask;
            });

        SlackRateLimitObservation observation;
        using (await gate.EnterAsync("conversations.replies", CancellationToken.None))
        {
            observation = gate.ReportRateLimit("conversations.replies", TimeSpan.FromSeconds(10), attempt: 0);
        }

        using (await gate.EnterAsync("conversations.history", CancellationToken.None))
        {
            gate.ReportSuccess("conversations.history");
        }

        using (await gate.EnterAsync("conversations.replies", CancellationToken.None))
        {
            gate.ReportSuccess("conversations.replies");
        }

        using (await gate.EnterAsync("conversations.replies", CancellationToken.None))
        {
        }

        Assert.Equal(TimeSpan.FromSeconds(10.25), observation.RetryDelay);
        Assert.Equal(TimeSpan.FromSeconds(10), observation.PacingInterval);
        Assert.Equal([TimeSpan.FromSeconds(10.25), TimeSpan.FromSeconds(10.25)], delays);
    }

    [Fact]
    public async Task RateLimitGate_LearnsTheFullWindow_WhenAProactivelyPacedCallIsStillLimited()
    {
        var now = new DateTimeOffset(2026, 7, 14, 0, 0, 0, TimeSpan.Zero);
        var gate = new SlackRateLimitGate(
            () => now,
            (delay, _) =>
            {
                now += delay;
                return Task.CompletedTask;
            });

        using (await gate.EnterAsync("conversations.replies", CancellationToken.None))
        {
            gate.ReportSuccess("conversations.replies");
        }

        using (await gate.EnterAsync("conversations.replies", CancellationToken.None))
        {
            gate.ReportRateLimit("conversations.replies", TimeSpan.FromSeconds(30), attempt: 0);
        }

        using (await gate.EnterAsync("conversations.replies", CancellationToken.None))
        {
            gate.ReportSuccess("conversations.replies");
        }

        SlackRateLimitObservation secondLimit;
        using (await gate.EnterAsync("conversations.replies", CancellationToken.None))
        {
            secondLimit = gate.ReportRateLimit("conversations.replies", TimeSpan.FromSeconds(30), attempt: 0);
        }

        Assert.True(secondLimit.PacingInterval >= TimeSpan.FromSeconds(60));
    }

    [Fact]
    public void RateLimitNoticeLimiter_ReportsOnlyTheFirstNoticeForEachMethod()
    {
        var limiter = new SlackRateLimitNoticeLimiter();

        Assert.True(limiter.ShouldReport("conversations.replies"));
        Assert.False(limiter.ShouldReport("conversations.replies"));
        Assert.True(limiter.ShouldReport("conversations.history"));
    }

    [Theory]
    [InlineData("{\"ok\":false,\"error\":\"ratelimited\",\"retry_after\":10}", 10)]
    [InlineData("{\"ok\":false,\"error\":\"ratelimited\",\"response_metadata\":{\"retry_after\":\"30\"}}", 30)]
    public void RateLimitGate_ReadsRetryAfterFromSlackJsonErrors(string json, int expectedSeconds)
    {
        using var document = JsonDocument.Parse(json);

        var retryAfter = SlackRateLimitGate.GetRetryAfter(document.RootElement);

        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), retryAfter);
    }

    private static HttpResponseMessage Json(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(callback(request));
        }
    }
}
