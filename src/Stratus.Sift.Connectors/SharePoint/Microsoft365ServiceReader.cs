using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Azure.Core;
using Stratus.Sift.Connectors.Services;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class Microsoft365ServiceReader : IDisposable
{
    private readonly TokenCredential _credential;
    private readonly string[] _scopes;
    private readonly HttpClient _http;
    private readonly RequestThrottleGate _throttle = new();
    internal Uri Root { get; }
    internal Microsoft365ServiceReader(TokenCredential credential, Uri root, string[] scopes, HttpMessageHandler? handler = null)
    {
        _credential = credential; Root = root; _scopes = scopes;
        _http = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(5) };
    }
    internal async Task<JsonDocument> Get(string path, CancellationToken ct)
    {
        using var stream = await Open(new Uri(Root, path), ct);
        return JsonDocument.Parse(await ReadBytesAsync(stream, ct), new JsonDocumentOptions { MaxDepth = 128 });
    }
    internal async Task<Stream> Open(Uri uri, CancellationToken ct)
    {
        if (!Microsoft365GraphWorkloadDrive.SameOrigin(uri, Root) || uri.UserInfo.Length > 0)
            throw new InvalidDataException("Workload continuation or resource URL changed service origin.");
        for (var attempt = 0; ; attempt++)
        {
            await _throttle.WaitAsync(ct);
            var token = await _credential.GetTokenAsync(new TokenRequestContext(_scopes), ct);
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
            var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (RequestThrottleGate.ShouldThrottle(response.StatusCode) && attempt < 4)
            {
                _throttle.Observe(response, TimeSpan.FromSeconds(5));
                response.Dispose();
                continue;
            }
            try
            {
                if (!response.IsSuccessStatusCode)
                    throw new HttpRequestException($"Workload request failed with HTTP {(int)response.StatusCode}.", null, response.StatusCode);
                if (response.StatusCode == HttpStatusCode.PartialContent)
                {
                    var range = response.Content.Headers.ContentRange;
                    if (range?.From != 0 || !range.To.HasValue || !range.Length.HasValue || range.To.Value + 1 != range.Length.Value)
                        throw new InvalidDataException("Workload download returned only part of a document; it cannot be marked complete.");
                }
                var stream = await response.Content.ReadAsStreamAsync(ct);
                return new ResponseStream(stream, response);
            }
            catch { response.Dispose(); throw; }
        }
    }
    internal async Task<Stream> OpenOwned(Uri uri, CancellationToken ct)
    {
        try { return new ResponseStream(await Open(uri, ct), null, this); }
        catch { Dispose(); throw; }
    }
    internal async IAsyncEnumerable<JsonElement> Enumerate(string path, [EnumeratorCancellation] CancellationToken ct)
    {
        var uri = new Uri(Root, path);
        var visited = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            if (visited.Count >= Microsoft365CoverageOptions.MaxPages || !visited.Add(uri.AbsoluteUri))
                throw new InvalidDataException("Workload collection exceeded its page limit or repeated a continuation.");
            using var stream = await Open(uri, ct);
            using var json = JsonDocument.Parse(await ReadBytesAsync(stream, ct));
            if (!json.RootElement.TryGetProperty("value", out var values) || values.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Workload collection has no value array.");
            foreach (var value in values.EnumerateArray()) yield return value.Clone();
            var next = String(json.RootElement, "@odata.nextLink") ?? String(json.RootElement, "nextLink");
            if (string.IsNullOrWhiteSpace(next)) yield break;
            uri = new Uri(uri, next);
        }
    }
    public void Dispose() => _http.Dispose();
    private sealed class ResponseStream(Stream inner, HttpResponseMessage? response, IDisposable? owner = null) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override int Read(byte[] b, int o, int c) => inner.Read(b, o, c);
        public override int Read(Span<byte> b) => inner.Read(b);
        public override ValueTask<int> ReadAsync(Memory<byte> b, CancellationToken ct = default) => inner.ReadAsync(b, ct);
        public override Task<int> ReadAsync(byte[] b, int o, int c, CancellationToken ct) => inner.ReadAsync(b, o, c, ct);
        public override long Seek(long o, SeekOrigin origin) => inner.Seek(o, origin);
        public override void Flush() => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) { inner.Dispose(); response?.Dispose(); owner?.Dispose(); } base.Dispose(disposing); }
        public override async ValueTask DisposeAsync() { await inner.DisposeAsync(); response?.Dispose(); owner?.Dispose(); GC.SuppressFinalize(this); }
    }
}
