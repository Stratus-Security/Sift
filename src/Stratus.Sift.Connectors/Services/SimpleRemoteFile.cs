using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Stratus.Sift.Connectors.Interfaces;

namespace Stratus.Sift.Connectors.Services;

internal sealed class SimpleRemoteFile : IRemoteFile
{
    private readonly byte[]? _content;
    private readonly HttpClient? _httpClient;
    private readonly Uri? _downloadUri;
    private readonly string? _localPath;

    internal SimpleRemoteFile(
        string id,
        string name,
        string path,
        string webUrl,
        string content,
        string contentType = "text/plain")
    {
        Id = id;
        Name = name;
        Path = path;
        WebUrl = webUrl;
        ContentType = contentType;
        _content = Encoding.UTF8.GetBytes(content);
        Size = _content.LongLength;
    }

    internal SimpleRemoteFile(
        string id,
        string name,
        string path,
        string webUrl,
        long? size,
        string? contentType,
        HttpClient httpClient,
        Uri downloadUri)
    {
        Id = id;
        Name = name;
        Path = path;
        WebUrl = webUrl;
        Size = size;
        ContentType = contentType;
        _httpClient = httpClient;
        _downloadUri = downloadUri;
    }

    internal SimpleRemoteFile(
        string id,
        string name,
        string path,
        string webUrl,
        FileInfo localFile,
        string? contentType = null)
    {
        Id = id;
        Name = name;
        Path = path;
        WebUrl = webUrl;
        Size = localFile.Exists ? localFile.Length : null;
        ContentType = contentType;
        _localPath = localFile.FullName;
    }

    public string Id { get; }
    public string Name { get; }
    public string Path { get; }
    public string WebUrl { get; }
    public long? Size { get; }
    public string? ContentType { get; }
    public bool IsDeleted => false;
    public bool IsDirectory => false;
    public bool IsLink => false;
    public bool IsExternal => false;

    public async Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default)
    {
        if (_content != null)
        {
            return new MemoryStream(_content, writable: false);
        }

        if (_localPath != null)
        {
            return OpenLocalStream();
        }

        return await OpenRemoteStreamAsync(rangeStart: null, rangeEnd: null, cancellationToken);
    }

    public async Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(start);
        if (end < start)
        {
            throw new ArgumentOutOfRangeException(nameof(end), "The range end must be greater than or equal to the start.");
        }

        if (_content != null)
        {
            var availableEnd = Math.Min(_content.LongLength - 1, end);
            if (start >= _content.LongLength || availableEnd < start)
            {
                return new MemoryStream(Array.Empty<byte>(), writable: false);
            }

            var length = checked((int)(availableEnd - start + 1));
            return new MemoryStream(_content, checked((int)start), length, writable: false, publiclyVisible: true);
        }

        if (_localPath != null)
        {
            var stream = OpenLocalStream();
            if (start >= stream.Length)
            {
                stream.Dispose();
                return new MemoryStream(Array.Empty<byte>(), writable: false);
            }

            stream.Seek(start, SeekOrigin.Begin);
            return new LengthLimitedReadStream(stream, Math.Min(end - start + 1, stream.Length - start));
        }

        return await OpenRemoteStreamAsync(start, end, cancellationToken);
    }

    private FileStream OpenLocalStream()
    {
        try
        {
            return new FileStream(_localPath!, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw CreateContentException(ex);
        }
    }

    private async Task<Stream?> OpenRemoteStreamAsync(long? rangeStart, long? rangeEnd, CancellationToken cancellationToken)
    {
        if (_httpClient == null || _downloadUri == null)
        {
            return null;
        }

        HttpResponseMessage? response = null;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, _downloadUri);
            if (rangeStart.HasValue && rangeEnd.HasValue)
            {
                request.Headers.Range = new RangeHeaderValue(rangeStart.Value, rangeEnd.Value);
            }

            response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            response.EnsureSuccessStatusCode();
            var stream = await response.Content.ReadAsStreamAsync(cancellationToken);

            var requestedLength = rangeStart.HasValue && rangeEnd.HasValue
                ? checked(rangeEnd.Value - rangeStart.Value + 1)
                : (long?)null;

            if (requestedLength.HasValue
                && response.StatusCode != HttpStatusCode.PartialContent
                && rangeStart!.Value > 0)
            {
                await SkipAsync(stream, rangeStart.Value, cancellationToken);
            }

            var ownedStream = new ResponseOwnedReadStream(stream, response, requestedLength);
            response = null;
            return ownedStream;
        }
        catch (Exception ex) when (ex is not RemoteContentUnavailableException)
        {
            response?.Dispose();
            if (ex is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw CreateContentException(ex);
        }
    }

    private static async Task SkipAsync(Stream stream, long bytesToSkip, CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        var remaining = bytesToSkip;
        while (remaining > 0)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)), cancellationToken);
            if (read == 0)
            {
                break;
            }

            remaining -= read;
        }
    }

    private static RemoteContentUnavailableException CreateContentException(Exception exception)
    {
        var statusCode = exception is HttpRequestException httpException && httpException.StatusCode.HasValue
            ? (int?)httpException.StatusCode.Value
            : null;
        var shouldRetry = statusCode is 408 or 429 or 500 or 502 or 503 or 504
            || exception is TimeoutException
            || exception is IOException
            || exception is OperationCanceledException
            || exception is HttpRequestException { StatusCode: null };

        return new RemoteContentUnavailableException(
            statusCode.HasValue
                ? $"Remote content download failed with HTTP {statusCode.Value}."
                : "Remote content could not be downloaded.",
            shouldRetry,
            statusCode,
            exception);
    }

    private sealed class ResponseOwnedReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly HttpResponseMessage _response;
        private long? _remaining;

        internal ResponseOwnedReadStream(Stream inner, HttpResponseMessage response, long? remaining)
        {
            _inner = inner;
            _response = response;
            _remaining = remaining;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining == 0)
            {
                return 0;
            }

            try
            {
                var read = _inner.Read(buffer, offset, LimitCount(count));
                DecrementRemaining(read);
                return read;
            }
            catch (Exception ex)
            {
                throw CreateContentException(ex);
            }
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_remaining == 0)
            {
                return 0;
            }

            try
            {
                var read = await _inner.ReadAsync(buffer[..LimitCount(buffer.Length)], cancellationToken);
                DecrementRemaining(read);
                return read;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CreateContentException(ex);
            }
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
                _response.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await _inner.DisposeAsync();
            _response.Dispose();
            GC.SuppressFinalize(this);
        }

        private int LimitCount(int requested)
        {
            return _remaining.HasValue ? (int)Math.Min(requested, _remaining.Value) : requested;
        }

        private void DecrementRemaining(int read)
        {
            if (_remaining.HasValue)
            {
                _remaining = Math.Max(0, _remaining.Value - read);
            }
        }
    }

    private sealed class LengthLimitedReadStream : Stream
    {
        private readonly Stream _inner;
        private long _remaining;

        internal LengthLimitedReadStream(Stream inner, long remaining)
        {
            _inner = inner;
            _remaining = remaining;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining == 0) return 0;
            var read = _inner.Read(buffer, offset, (int)Math.Min(count, _remaining));
            _remaining -= read;
            return read;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_remaining == 0) return 0;
            var read = await _inner.ReadAsync(buffer[..(int)Math.Min(buffer.Length, _remaining)], cancellationToken);
            _remaining -= read;
            return read;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await _inner.DisposeAsync();
            GC.SuppressFinalize(this);
        }
    }
}
