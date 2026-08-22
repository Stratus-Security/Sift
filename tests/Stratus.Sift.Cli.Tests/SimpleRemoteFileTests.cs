using System.Net;
using System.Net.Http.Headers;
using Stratus.Sift.Connectors.Services;

namespace Stratus.Sift.Connectors.Tests;

public class SimpleRemoteFileTests
{
    [Fact]
    public async Task GetContentRangeAsync_UsesHttpRangeAndReturnsOnlyRequestedBytes()
    {
        RangeHeaderValue? observedRange = null;
        var handler = new DelegateHandler(request =>
        {
            observedRange = request.Headers.Range;
            return new HttpResponseMessage(HttpStatusCode.PartialContent)
            {
                Content = new StringContent("fghij")
            };
        });
        var file = CreateRemoteFile(handler);

        await using var stream = await file.GetContentRangeAsync(5, 9);
        using var reader = new StreamReader(stream!);

        Assert.Equal("fghij", await reader.ReadToEndAsync());
        Assert.Equal(5, observedRange?.Ranges.Single().From);
        Assert.Equal(9, observedRange?.Ranges.Single().To);
    }

    [Fact]
    public async Task GetContentAsync_WrapsRetryableHttpFailures()
    {
        var file = CreateRemoteFile(new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));

        var exception = await Assert.ThrowsAsync<RemoteContentUnavailableException>(() => file.GetContentAsync());

        Assert.True(exception.ShouldRetry);
        Assert.Equal(503, exception.StatusCode);
    }

    [Fact]
    public async Task GetContentRangeAsync_ReadsOnlyRequestedLocalBytes()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "0123456789");
            var file = new SimpleRemoteFile("local-1", "local.txt", path, string.Empty, new FileInfo(path));

            await using var stream = await file.GetContentRangeAsync(3, 6);
            using var reader = new StreamReader(stream!);

            Assert.Equal("3456", await reader.ReadToEndAsync());
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static SimpleRemoteFile CreateRemoteFile(HttpMessageHandler handler)
    {
        return new SimpleRemoteFile(
            "file-1",
            "large.txt",
            "remote://large.txt",
            "https://example.test/large.txt",
            1024,
            "text/plain",
            new HttpClient(handler),
            new Uri("https://example.test/large.txt"));
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(callback(request));
        }
    }
}
