using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using Stratus.Sift.Scanner.Services;
using Excel = DocumentFormat.OpenXml.Spreadsheet;

namespace Stratus.Sift.Cli.Tests;

public sealed class ContentExtractorTests : IDisposable
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExtractXlsx_ReadsInlineStringsAndSeparatesCells(bool richText)
    {
        using var content = new MemoryStream(InlineWorkbook(richText));
        var result = new ContentExtractor().ExtractWithResult(content, ".xlsx");

        Assert.True(result.IsComplete, result.Error);
        Assert.Contains("secret separate", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void ExtractXlsx_PreservesSharedStringsAndNumericCells()
    {
        using var content = new MemoryStream();
        using (var document = SpreadsheetDocument.Create(content, SpreadsheetDocumentType.Workbook))
        {
            var workbook = document.AddWorkbookPart();
            workbook.Workbook = new Excel.Workbook();
            var strings = workbook.AddNewPart<SharedStringTablePart>();
            strings.SharedStringTable = new Excel.SharedStringTable(new Excel.SharedStringItem(new Excel.Text("secret")));
            var worksheet = workbook.AddNewPart<WorksheetPart>();
            worksheet.Worksheet = new Excel.Worksheet(new Excel.SheetData(new Excel.Row(
                new Excel.Cell { DataType = Excel.CellValues.SharedString, CellValue = new Excel.CellValue("0") },
                new Excel.Cell { CellValue = new Excel.CellValue("42") })));
            workbook.Workbook.Append(new Excel.Sheets(new Excel.Sheet
                { Id = workbook.GetIdOfPart(worksheet), SheetId = 1, Name = "Test" }));
        }
        content.Position = 0;

        var result = new ContentExtractor().ExtractWithResult(content, ".xlsx");

        Assert.True(result.IsComplete, result.Error);
        Assert.Contains("secret 42", result.Text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(".docx")]
    [InlineData(".xlsx")]
    [InlineData(".pdf")]
    public void ExtractWithResult_ReportsCorruptDocument(string extension)
    {
        using var content = new MemoryStream([1, 2, 3]);
        var result = new ContentExtractor().ExtractWithResult(content, extension);

        Assert.False(result.IsComplete);
        Assert.NotEmpty(result.Error!);
        Assert.Empty(result.Text);
    }

    [Fact]
    public void ExtractWithResult_ReportsTextTruncation()
    {
        using var content = new MemoryStream();
        using (var document = WordprocessingDocument.Create(content, WordprocessingDocumentType.Document))
        {
            document.AddMainDocumentPart().Document = new Document(new Body(new Paragraph(
                new Run(new Text(new string('x', 10 * 1024 * 1024 + 1))))));
        }
        content.Position = 0;

        var result = new ContentExtractor().ExtractWithResult(content, ".docx");

        Assert.False(result.IsComplete);
        Assert.Contains("text limit", result.Error!, StringComparison.Ordinal);
        Assert.Equal(10 * 1024 * 1024, result.Text.Length);
    }

    internal static byte[] InlineWorkbook(bool richText)
    {
        using var content = new MemoryStream();
        using (var document = SpreadsheetDocument.Create(content, SpreadsheetDocumentType.Workbook))
        {
            var workbook = document.AddWorkbookPart();
            workbook.Workbook = new Excel.Workbook();
            var worksheet = workbook.AddNewPart<WorksheetPart>();
            var inline = richText
                ? new Excel.InlineString(new Excel.Run(new Excel.Text("sec")), new Excel.Run(new Excel.Text("ret")))
                : new Excel.InlineString(new Excel.Text("secret"));
            worksheet.Worksheet = new Excel.Worksheet(new Excel.SheetData(new Excel.Row(
                new Excel.Cell { DataType = Excel.CellValues.InlineString, InlineString = inline },
                new Excel.Cell { DataType = Excel.CellValues.InlineString,
                    InlineString = new Excel.InlineString(new Excel.Text("separate")) })));
            workbook.Workbook.Append(new Excel.Sheets(new Excel.Sheet
                { Id = workbook.GetIdOfPart(worksheet), SheetId = 1, Name = "Test" }));
        }
        return content.ToArray();
    }

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
