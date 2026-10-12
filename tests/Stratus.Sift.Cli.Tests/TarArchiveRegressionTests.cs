using System.Formats.Tar;
using System.Text;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Scanner.Models;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class TarArchiveRegressionTests
{
    [Theory]
    [InlineData(TarEntryFormat.V7, false)]
    [InlineData(TarEntryFormat.V7, true)]
    [InlineData(TarEntryFormat.Ustar, false)]
    [InlineData(TarEntryFormat.Ustar, true)]
    [InlineData(TarEntryFormat.Pax, false)]
    [InlineData(TarEntryFormat.Pax, true)]
    [InlineData(TarEntryFormat.Gnu, false)]
    [InlineData(TarEntryFormat.Gnu, true)]
    public async Task StandardTarVariants_ScanFromSeekableAndRemoteStreams(TarEntryFormat format, bool forwardOnly)
    {
        using var buffer = new MemoryStream();
        using (var writer = new TarWriter(buffer, format, leaveOpen: true))
        {
            TarEntry entry = format switch
            {
                TarEntryFormat.V7 => new V7TarEntry(TarEntryType.V7RegularFile, "test.txt"),
                TarEntryFormat.Ustar => new UstarTarEntry(TarEntryType.RegularFile, "test.txt"),
                TarEntryFormat.Gnu => new GnuTarEntry(TarEntryType.RegularFile, "test.txt"),
                _ => new PaxTarEntry(TarEntryType.RegularFile, "test.txt")
            };
            entry.DataStream = new MemoryStream(Encoding.UTF8.GetBytes("secret"));
            writer.WriteEntry(entry);
        }
        var result = await Scan(buffer.ToArray(), forwardOnly);
        Assert.False(result.Incomplete);
        Assert.Contains("!/test.txt", Assert.Single(result.Findings).ResourcePath);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmptyTarWithEndMarkers_IsAValidCompletedArchive(bool forwardOnly)
    {
        var result = await Scan(new byte[1024], forwardOnly);
        Assert.False(result.Incomplete);
        Assert.Empty(result.Findings);
        Assert.Equal(1, result.Processed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(200)]
    public async Task UnrecognizableTar_ReturnsConciseReasonAndKeepsStackInDebug(int length)
    {
        var logger = new RecordingLogger();
        var scanner = new FileScanner(logger, new ContentExtractor(), new ValidatorFactory([]));
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([]);
        using var stream = new MemoryStream(Enumerable.Repeat((byte)'x', length).ToArray());
        var result = await scanner.ScanStreamAsync(stream, "test.tar",
            ScannerExecutionPlan.Create(optimizer, new Dictionary<Guid, List<Policy>>()),
            new ScanOptions { EnableZipArchives = true });
        Assert.False(result.IsComplete);
        Assert.Contains("file contents were not recognized", result.IncompleteReason);
        Assert.DoesNotContain("Supported Reader Formats", result.IncompleteReason);
        Assert.DoesNotContain(logger.Entries, entry => entry.Level >= LogLevel.Warning);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Debug && entry.Exception != null);
    }

    private static Task<ScanOutcome> Scan(byte[] bytes, bool forwardOnly)
    {
        var file = new Microsoft365ContentFile("archive", "test.tar", "https://contoso.sharepoint.com/test.tar", "v1", bytes.Length,
            (_, _) => Task.FromResult<Stream?>(forwardOnly ? new ForwardOnlyStream(bytes) : new MemoryStream(bytes)));
        return ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), options: new ScanOptions { EnableZipArchives = true });
    }

    private sealed class ForwardOnlyStream(byte[] bytes) : Stream
    {
        private readonly MemoryStream _inner = new(bytes);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, Math.Min(count, 17));
        public override int Read(Span<byte> buffer) => _inner.Read(buffer[..Math.Min(buffer.Length, 17)]);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => _inner.ReadAsync(buffer[..Math.Min(buffer.Length, 17)], ct);
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long length) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }

    private sealed class RecordingLogger : ILogger<FileScanner>
    {
        internal List<(LogLevel Level, Exception? Exception)> Entries { get; } = [];
        public bool IsEnabled(LogLevel level) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((level, exception));
    }
}
