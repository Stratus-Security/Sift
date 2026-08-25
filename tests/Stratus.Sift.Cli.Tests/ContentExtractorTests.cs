using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli.Tests;

public sealed class ContentExtractorTests : IDisposable
{
    private readonly string _tempDirectory = Path.Combine(Path.GetTempPath(), $"sift-extractor-{Guid.NewGuid():N}");

    public ContentExtractorTests() => Directory.CreateDirectory(_tempDirectory);

    [Fact]
    public void ExtractDocx_StreamsParagraphText()
    {
        var path = Path.Combine(_tempDirectory, "sample.docx");
        using (var document = WordprocessingDocument.Create(path, WordprocessingDocumentType.Document))
        {
            var mainPart = document.AddMainDocumentPart();
            mainPart.Document = new Document(new Body(
                new Paragraph(new Run(new Text("first secret"))),
                new Paragraph(new Run(new Text("second secret")))));
            mainPart.Document.Save();
        }

        var extracted = new ContentExtractor().Extract(path);

        Assert.Contains("first secret", extracted);
        Assert.Contains("second secret", extracted);
    }

    [Fact]
    public void ExtractNonSeekableStream_RejectsInputOverLimit()
    {
        using var content = new MemoryStream(new byte[(10 * 1024 * 1024) + 1], writable: false);
        using var stream = new NonSeekableReadStream(content);

        var extracted = new ContentExtractor().Extract(stream, ".pdf");

        Assert.Empty(extracted);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory)) Directory.Delete(_tempDirectory, recursive: true);
    }

    private sealed class NonSeekableReadStream(Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
