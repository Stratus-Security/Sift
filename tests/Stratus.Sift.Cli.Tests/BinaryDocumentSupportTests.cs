using System.IO.Compression;
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using Microsoft.Extensions.Logging.Abstractions;
using OfficeIMO.Excel;
using OfficeIMO.Drawing;
using OfficeIMO.OneNote;
using OfficeIMO.PowerPoint;
using OfficeIMO.Word;
using OpenMcdf;
using Stratus.Sift.Cli;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Models;
using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Services;
using A = DocumentFormat.OpenXml.Drawing;
using P = DocumentFormat.OpenXml.Presentation;
using W = DocumentFormat.OpenXml.Wordprocessing;
using S = DocumentFormat.OpenXml.Spreadsheet;

namespace Stratus.Sift.Cli.Tests;

public sealed class BinaryDocumentSupportTests
{
    public static IEnumerable<object[]> Formats() => ContentExtractor.SupportedExtensions
        .Where(extension => extension != ".pdf" && !new[] { ".xlsb", ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif", ".webp" }.Contains(extension))
        .Order().Select(extension => new object[] { extension });

    public static IEnumerable<object[]> RemoteFormats() => new[] { ".pptx", ".ppt", ".doc", ".xls", ".one", ".onepkg" }
        .SelectMany(extension => new[] { false, true }.SelectMany(rest => new[] { false, true }
            .Select(nonSeekable => new object[] { extension, rest, nonSeekable })));

    [Theory]
    [MemberData(nameof(Formats))]
    public void NewFormats_ExtractTextAndParticipateInBuiltInExtensionProfiles(string extension)
    {
        var extractor = new ContentExtractor();
        using var stream = new MemoryStream(Document(extension));
        stream.Position = Math.Min(5, stream.Length);
        var result = extractor.ExtractWithResult(stream, extension.ToUpperInvariant());

        Assert.True(extractor.Supports(extension.ToUpperInvariant()));
        Assert.Contains(extension, ContentExtensionProfiles.Resolve(ContentExtensionProfiles.SourceAndConfig));
        Assert.Contains(extension, ContentExtensionProfiles.Resolve(ContentExtensionProfiles.Documents));
        Assert.True(result.IsComplete, result.Error);
        Assert.Contains("secret", result.Text, StringComparison.Ordinal);
        Assert.True(stream.CanRead);
    }

    [Theory]
    [MemberData(nameof(Formats))]
    public void NewFormats_CorruptionNeverCompletes(string extension)
    {
        using var stream = new MemoryStream([1, 2, 3]);
        var result = new ContentExtractor().ExtractWithResult(stream, extension);

        Assert.False(result.IsComplete);
        Assert.NotEmpty(result.Error!);
    }

    [Fact]
    public void PowerPoint_ExtractsSplitRunsNotesTablesCommentsAndHiddenSlides()
    {
        using var bytes = new MemoryStream(Presentation());
        var result = new ContentExtractor().ExtractWithResult(bytes, ".pptx");

        Assert.True(result.IsComplete, result.Error);
        Assert.Contains("secret", result.Text);
        Assert.Contains("speaker-secret", result.Text);
        Assert.Contains("cell-secret", result.Text);
        Assert.Contains("comment-secret", result.Text);
        Assert.Contains("hidden-secret", result.Text);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OneNote_ExtractsDesktopAndCloudSectionsIncludingNestedTables(bool cloud)
    {
        var section = Section();
        var row = new OneNoteTableRow();
        var cell = new OneNoteTableCell();
        cell.Content.Add(Paragraph("cell-secret"));
        row.Cells.Add(cell);
        var table = new OneNoteTable();
        table.Rows.Add(row);
        section.Pages[0].DirectContent.Add(table);
        var outline = new OneNoteOutline();
        var parent = Paragraph("parent-secret");
        parent.Children.Add(Paragraph("child-secret"));
        outline.Children.Add(parent);
        section.Pages[0].Outlines.Add(outline);
        using var bytes = new MemoryStream(section.ToByteArray(new OneNoteWriterOptions
        {
            StorageFormat = cloud ? OneNoteStorageFormat.FileSynchronizationPackage : OneNoteStorageFormat.RevisionStore
        }));

        var result = new ContentExtractor().ExtractWithResult(bytes, ".one");

        Assert.True(result.IsComplete, result.Error);
        foreach (var token in new[] { "title-secret", "secret", "cell-secret", "parent-secret", "child-secret" })
            Assert.Contains(token, result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void OneNotePackage_ExtractsEverySectionAndSectionGroup()
    {
        var notebook = new OneNoteNotebook { Name = "notebook" };
        notebook.Sections.Add(Section());
        var group = new OneNoteSectionGroup { Name = "nested" };
        var section = Section();
        section.Name = "second";
        section.Pages[0].DirectContent.Add(Paragraph("nested-secret"));
        group.Sections.Add(section);
        notebook.SectionGroups.Add(group);
        using var bytes = new MemoryStream(OneNotePackageWriter.Write(notebook));

        var result = new ContentExtractor().ExtractWithResult(bytes, ".onepkg");

        Assert.True(result.IsComplete, result.Error);
        Assert.Contains("nested-secret", result.Text);
    }

    [Fact]
    public void LegacyPowerPoint_ExtractsIndependentlyAuthoredCentralSlideText()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "LegacyOffice", "basic_test_ppt_file.ppt");
        var result = new ContentExtractor().ExtractWithResult(path);
        Assert.True(result.IsComplete, result.Error);
        foreach (var token in new[] { "This is a test title", "This is a test subtitle", "This is on page 1",
                     "This is the title on page 2", "This is page two", "It has several blocks of text",
                     "None of them have formatting", "These are the notes for page 1", "These are the notes on page two" })
            Assert.Contains(token, result.Text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LegacyPowerPoint_CentralTextUsesCurrentPersistMappingsAndRejectsEditCycles(bool cycle)
    {
        byte[] Record(ushort type, byte[] body, bool container = false)
        {
            var record = new byte[8 + body.Length];
            BinaryPrimitives.WriteUInt16LittleEndian(record, container ? (ushort)15 : (ushort)0);
            BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(2), type);
            BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(4), (uint)body.Length);
            body.CopyTo(record, 8);
            return record;
        }
        byte[] DocumentRecord(string text) => Record(1000,
            Record(4080, Record(4000, Encoding.Unicode.GetBytes(text)), true), true);
        var retired = DocumentRecord("retired-secret");
        var current = DocumentRecord("current-secret");
        var persistBody = new byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(persistBody, (1U << 20) | 1U);
        BinaryPrimitives.WriteUInt32LittleEndian(persistBody.AsSpan(4), (uint)retired.Length);
        var persist = Record(6002, persistBody);
        var editOffset = retired.Length + current.Length + persist.Length;
        var editBody = new byte[28];
        BinaryPrimitives.WriteUInt32LittleEndian(editBody.AsSpan(8), cycle ? (uint)editOffset : 0);
        BinaryPrimitives.WriteUInt32LittleEndian(editBody.AsSpan(12), (uint)(retired.Length + current.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(editBody.AsSpan(16), 1);
        var userBody = new byte[20];
        BinaryPrimitives.WriteUInt32LittleEndian(userBody.AsSpan(8), (uint)editOffset);
        using var bytes = new MemoryStream();
        using (var storage = RootStorage.Create(bytes, flags: StorageModeFlags.LeaveOpen))
        {
            using (var data = storage.CreateStream("PowerPoint Document"))
                foreach (var record in new[] { retired, current, persist, Record(4085, editBody) }) data.Write(record);
            using (var user = storage.CreateStream("Current User")) user.Write(Record(4086, userBody));
            storage.Flush();
        }
        bytes.Position = 0;
        var extracted = new StringBuilder();
        if (cycle) Assert.Throws<InvalidDataException>(() => ContentExtractor.AppendLegacySlideListText(bytes, extracted));
        else
        {
            Assert.True(ContentExtractor.AppendLegacySlideListText(bytes, extracted));
            Assert.Contains("current-secret", extracted.ToString());
            Assert.DoesNotContain("retired-secret", extracted.ToString());
        }
    }

    [Theory]
    [MemberData(nameof(RemoteFormats))]
    public async Task Microsoft365_ExtractsDocumentsAcrossGraphRestAndNonSeekableDownloads(string extension, bool rest, bool nonSeekable)
    {
        var file = Microsoft365CoverageTests.RemoteFile(rest, "credentials" + extension, Document(extension), nonSeekable);
        var result = await Microsoft365ReliabilityTests.ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file),
            extension: extension, options: new ScanOptions { EnableBinaryDocuments = true });

        Assert.False(result.Incomplete);
        Assert.Contains(result.Findings, finding => finding.ResourcePath == file.WebUrl);
        Assert.Equal(1, result.Processed);
        Assert.Equal(1, result.Scanned);
        Assert.Equal("final", result.FinalToken);
    }

    [Theory]
    [InlineData(".pptx")]
    [InlineData(".ppt")]
    [InlineData(".doc")]
    [InlineData(".xls")]
    [InlineData(".one")]
    [InlineData(".onepkg")]
    public async Task LocalAndZipScans_ApplyBinaryExtractionAndRespectTheBinaryFlag(string extension)
    {
        var scanner = Scanner();
        var (classifiers, policies) = Rules(extension);
        var directory = Path.Combine(Path.GetTempPath(), "sift-binary-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "credentials" + extension);
            File.WriteAllBytes(path, Document(extension));
            var result = scanner.ScanFileWithResult(path, classifiers, policies, new ScanOptions { EnableBinaryDocuments = true });
            Assert.True(result.IsComplete);
            Assert.NotEmpty(result.Issues);
            Assert.Empty(scanner.ScanFile(path, classifiers, policies, new ScanOptions { EnableBinaryDocuments = false }));

            using var bytes = new MemoryStream();
            using (var zip = new ZipArchive(bytes, ZipArchiveMode.Create, true))
            using (var entry = zip.CreateEntry("credentials" + extension).Open()) entry.Write(Document(extension));
            bytes.Position = 0;
            var optimizer = new ClassifierOptimizer();
            optimizer.LoadClassifiers(classifiers);
            var plan = ScannerExecutionPlan.Create(optimizer, classifiers.ToDictionary(rule => rule.Id, _ => policies));
            var zipped = await scanner.ScanStreamAsync(bytes, "backup.zip", plan,
                new ScanOptions { EnableBinaryDocuments = true, EnableZipArchives = true });
            Assert.True(zipped.IsComplete);
            Assert.Contains(zipped.Issues, issue => issue.ResourcePath == "backup.zip!/credentials" + extension);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OneNoteUninspectedAttachments_PreserveTextFindingsAndPreventCheckpoints(bool rest)
    {
        var section = Section();
        section.Pages[0].DirectContent.Add(new OneNoteEmbeddedFile
        {
            SourcePath = "attachment.unsupported",
            FileName = "attachment.unsupported",
            Payload = OneNoteBinaryPayload.FromBytes(Encoding.UTF8.GetBytes("attachment content"))
        });
        var bytes = section.ToByteArray();
        using var content = new MemoryStream(bytes);
        var extraction = new ContentExtractor().ExtractWithResult(content, ".one");
        Assert.False(extraction.IsComplete);
        Assert.Contains("secret", extraction.Text);

        var file = Microsoft365CoverageTests.RemoteFile(rest, "credentials.one", bytes, true);
        var result = await Microsoft365ReliabilityTests.ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file),
            extension: ".one", options: new ScanOptions { EnableBinaryDocuments = true });
        Assert.True(result.Incomplete);
        Assert.NotEmpty(result.Findings);
        Assert.Equal(0, result.Processed);
        Assert.Equal(0, result.Scanned);
        Assert.Null(result.FinalToken);
    }

    [Fact]
    public void WordRelatedParts_ExtractHeadersFootersCommentsAndFields()
    {
        using var bytes = new MemoryStream();
        using (var document = WordprocessingDocument.Create(bytes, WordprocessingDocumentType.Document))
        {
            var main = document.AddMainDocumentPart();
            main.Document = new W.Document(new W.Body(new W.Paragraph(new W.Run(new W.Text("body-secret"),
                new W.FieldCode("field-secret")))));
            main.AddNewPart<HeaderPart>().Header = new W.Header(new W.Paragraph(new W.Run(new W.Text("header-secret"))));
            main.AddNewPart<FooterPart>().Footer = new W.Footer(new W.Paragraph(new W.Run(new W.Text("footer-secret"))));
            main.AddNewPart<WordprocessingCommentsPart>().Comments = new W.Comments(new W.Comment(
                new W.Paragraph(new W.Run(new W.Text("comment-secret"))))
            { Id = "0" });
        }
        bytes.Position = 0;
        var result = new ContentExtractor().ExtractWithResult(bytes, ".docx");
        Assert.True(result.IsComplete, result.Error);
        foreach (var token in new[] { "body-secret", "field-secret", "header-secret", "footer-secret", "comment-secret" })
            Assert.Contains(token, result.Text);
    }

    [Fact]
    public void Excel_ExtractsFormulaSourceAndCellComments()
    {
        using var bytes = new MemoryStream();
        using (var document = SpreadsheetDocument.Create(bytes, SpreadsheetDocumentType.Workbook))
        {
            var workbook = document.AddWorkbookPart();
            workbook.Workbook = new S.Workbook();
            var worksheet = workbook.AddNewPart<WorksheetPart>();
            worksheet.Worksheet = new S.Worksheet(new S.SheetData(new S.Row(new S.Cell
            {
                DataType = S.CellValues.String,
                CellFormula = new S.CellFormula("\"formula-secret\""),
                CellValue = new S.CellValue("cached-value")
            })));
            worksheet.AddNewPart<WorksheetCommentsPart>().Comments = new S.Comments(
                new S.Authors(new S.Author("Author")), new S.CommentList(new S.Comment
                {
                    Reference = "A1",
                    AuthorId = 0,
                    CommentText = new S.CommentText(new S.Text("comment-secret"))
                }));
            workbook.Workbook.Append(new S.Sheets(new S.Sheet
            {
                Id = workbook.GetIdOfPart(worksheet),
                SheetId = 1,
                Name = "Hidden",
                State = S.SheetStateValues.Hidden
            }));
        }
        bytes.Position = 0;
        var result = new ContentExtractor().ExtractWithResult(bytes, ".xlsx");
        Assert.True(result.IsComplete, result.Error);
        foreach (var token in new[] { "formula-secret", "cached-value", "comment-secret" }) Assert.Contains(token, result.Text);
    }

    [Fact]
    public void OneNote_ExtractsConflictPagesAndHyperlinksWithoutHistoricalSnapshots()
    {
        var section = Section();
        var conflict = new OneNotePage { Title = "conflict-secret", IsConflictPage = true };
        conflict.DirectContent.Add(Paragraph("conflict-body-secret"));
        var history = new OneNotePage { Title = "old-snapshot", IsVersionHistoryPage = true };
        history.DirectContent.Add(Paragraph("historical-content"));
        section.Pages[0].ConflictPages.Add(conflict);
        section.Pages[0].VersionHistory.Add(history);
        var paragraph = Paragraph("link text");
        paragraph.Runs[0].Hyperlink = "https://example.test/link-secret";
        section.Pages[0].DirectContent.Add(paragraph);
        using var bytes = new MemoryStream(section.ToByteArray());
        var result = new ContentExtractor().ExtractWithResult(bytes, ".one");
        Assert.True(result.IsComplete, result.Error);
        Assert.Contains("conflict-body-secret", result.Text);
        Assert.Contains("link-secret", result.Text);
        Assert.DoesNotContain("historical-content", result.Text);
    }

    [Fact]
    public void OneNote_ExtractsStoredOcrAltTextAndInkRecognition()
    {
        var section = Section();
        var pixel = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jF1EAAAAASUVORK5CYII=");
        section.Pages[0].DirectContent.Add(new OneNoteImage
        {
            FileName = "pixel.png",
            MediaType = "image/png",
            WidthHalfInches = 1,
            HeightHalfInches = 1,
            AltText = "alt-secret",
            OcrText = "ocr-secret",
            Payload = OneNoteBinaryPayload.FromBytes(pixel)
        });
        var ink = new OneNoteInk();
        var stroke = new OfficeInkStroke { Width = 0.04, Height = 0.04, RecognizedText = "ink-secret" };
        stroke.AddPoint(0.1, 0.2, 0.4).AddPoint(0.8, 0.5, 1.0);
        ink.Ink.Add(stroke);
        section.Pages[0].DirectContent.Add(ink);
        using var bytes = new MemoryStream(section.ToByteArray());
        var result = new ContentExtractor().ExtractWithResult(bytes, ".one");
        Assert.True(result.IsComplete, result.Error);
        foreach (var token in new[] { "alt-secret", "ocr-secret", "ink-secret" }) Assert.Contains(token, result.Text);
    }

    [Fact]
    public void PowerPoint_TextLimitPreservesAvailableTextAndReportsIncomplete()
    {
        using var bytes = new MemoryStream();
        using (var document = PresentationDocument.Create(bytes, PresentationDocumentType.Presentation))
        {
            var presentation = document.AddPresentationPart();
            presentation.Presentation = new P.Presentation();
            var slide = presentation.AddNewPart<SlidePart>();
            var paragraph = new A.Paragraph(new A.Run(new A.Text("secret" + new string('x', 10 * 1024 * 1024))));
            var shape = new P.Shape(new P.TextBody(new A.BodyProperties(), new A.ListStyle(), paragraph));
            slide.Slide = new P.Slide(new P.CommonSlideData(new P.ShapeTree(shape)));
        }
        bytes.Position = 0;
        var result = new ContentExtractor().ExtractWithResult(bytes, ".pptx");
        Assert.False(result.IsComplete);
        Assert.StartsWith("secret", result.Text.TrimStart());
        Assert.Contains("text limit", result.Error!);
    }

    [Fact]
    public async Task LocalCli_IncompleteBinaryExtractionReturnsPartialAndDoesNotResumePastTheFile()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sift-binary-cli-" + Guid.NewGuid().ToString("N"));
        var inputs = Path.Combine(directory, "inputs");
        var rules = Path.Combine(directory, "rules");
        Directory.CreateDirectory(inputs);
        Directory.CreateDirectory(rules);
        try
        {
            File.WriteAllBytes(Path.Combine(inputs, "credentials.pptx"), [1, 2, 3]);
            File.WriteAllText(Path.Combine(rules, "test.json"),
                """{"Name":"Test","Severity":"High","EnableLlmValidation":false,"Matches":[{"Target":"Content","Patterns":["secret"],"ExtensionProfile":"Documents"}]}""");
            var output = Path.Combine(directory, "result.json");
            var args = new[] { "local", "--path", inputs, "--rules", rules, "--binary", "--no-banner", "--output", output,
                "--output-format", "json" };
            Assert.Equal(CliExitCodes.Partial, await Program.RunAsync(args));
            Assert.Equal(CliExitCodes.Partial, await Program.RunAsync(args.Append("--resume").ToArray()));
            using var saved = JsonDocument.Parse(File.ReadAllText(output));
            Assert.Equal(0, saved.RootElement.GetProperty("FilesScanned").GetInt32());
            Assert.True(saved.RootElement.GetProperty("Errors").GetInt32() > 0);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    internal static byte[] Document(string extension)
    {
        if (extension is ".one" or ".onepkg")
        {
            var section = Section();
            if (extension == ".one") return section.ToByteArray();
            var notebook = new OneNoteNotebook { Name = "notebook" };
            notebook.Sections.Add(section);
            return OneNotePackageWriter.Write(notebook);
        }
        if (extension is ".doc" or ".dot")
        {
            using var document = WordDocument.Create();
            document.AddParagraph("secret");
            return document.ToBytes(WordFileFormat.Doc);
        }
        if (extension is ".xls" or ".xlt")
        {
            using var document = ExcelDocument.Create();
            document.AddWorksheet("Secrets").CellValue(1, 1, "secret");
            return document.ToBytes(ExcelFileFormat.Xls);
        }
        if (extension is ".ppt" or ".pot" or ".pps")
        {
            using var document = PowerPointPresentation.Create();
            document.AddSlide().AddTextBox("secret", 0, 0, 1_000_000, 1_000_000);
            return document.ToBytes(PowerPointFileFormat.Ppt);
        }
        if (extension.StartsWith(".doc", StringComparison.Ordinal) || extension.StartsWith(".dot", StringComparison.Ordinal))
        {
            using var bytes = new MemoryStream();
            using (var document = WordprocessingDocument.Create(bytes, WordprocessingDocumentType.Document))
                document.AddMainDocumentPart().Document = new W.Document(new W.Body(new W.Paragraph(new W.Run(new W.Text("secret")))));
            return bytes.ToArray();
        }
        if (extension.StartsWith(".xl", StringComparison.Ordinal)) return ContentExtractorTests.InlineWorkbook(false);
        return Presentation();
    }

    private static OneNoteSection Section()
    {
        var section = new OneNoteSection { Name = "Notes" };
        var page = new OneNotePage { Title = "title-secret" };
        var paragraph = new OneNoteParagraph();
        paragraph.Runs.Add(new OneNoteTextRun { Text = "sec" });
        paragraph.Runs.Add(new OneNoteTextRun { Text = "ret" });
        page.DirectContent.Add(paragraph);
        section.Pages.Add(page);
        return section;
    }

    private static OneNoteParagraph Paragraph(string text)
    {
        var paragraph = new OneNoteParagraph();
        paragraph.Runs.Add(new OneNoteTextRun { Text = text });
        return paragraph;
    }

    private static byte[] Presentation()
    {
        using var bytes = new MemoryStream();
        using (var document = PresentationDocument.Create(bytes, PresentationDocumentType.Presentation))
        {
            var presentation = document.AddPresentationPart();
            presentation.Presentation = new P.Presentation(new P.SlideIdList());
            var slide = presentation.AddNewPart<SlidePart>();
            var paragraph = new A.Paragraph(new A.Run(new A.Text("sec")), new A.Run(new A.Text("ret")));
            var shape = new P.Shape(new P.TextBody(new A.BodyProperties(), new A.ListStyle(), paragraph));
            var cellText = new A.TextBody(new A.BodyProperties(), new A.ListStyle(),
                new A.Paragraph(new A.Run(new A.Text("cell-secret"))));
            var table = new A.Table(new A.TableRow(new A.TableCell(cellText)));
            var frame = new P.GraphicFrame(new A.Graphic(new A.GraphicData(table)));
            slide.Slide = new P.Slide(new P.CommonSlideData(new P.ShapeTree(shape, frame))) { Show = false };
            var note = new P.Shape(new P.TextBody(new A.BodyProperties(), new A.ListStyle(),
                new A.Paragraph(new A.Run(new A.Text("speaker-secret")))));
            slide.AddNewPart<NotesSlidePart>().NotesSlide = new P.NotesSlide(new P.CommonSlideData(new P.ShapeTree(note)));
            slide.AddNewPart<SlideCommentsPart>().CommentList = new P.CommentList(new P.Comment(new P.Text("comment-secret")));
            var hidden = presentation.AddNewPart<SlidePart>();
            var hiddenText = new P.Shape(new P.TextBody(new A.BodyProperties(), new A.ListStyle(),
                new A.Paragraph(new A.Run(new A.Text("hidden-secret")))));
            hidden.Slide = new P.Slide(new P.CommonSlideData(new P.ShapeTree(hiddenText))) { Show = false };
            presentation.Presentation.SlideIdList!.Append(new P.SlideId { Id = 256, RelationshipId = presentation.GetIdOfPart(slide) },
                new P.SlideId { Id = 257, RelationshipId = presentation.GetIdOfPart(hidden) });
        }
        return bytes.ToArray();
    }

    private static FileScanner Scanner() => new(NullLogger<FileScanner>.Instance, new ContentExtractor(),
        new ValidatorFactory(Enumerable.Empty<IValidator>()));

    private static (List<Classifier>, List<Policy>) Rules(string extension)
    {
        var classifier = new Classifier
        {
            Name = "Secret",
            EnableLlmValidation = false,
            Matches = [new ClassifierMatch { Target = RuleTarget.Content, Patterns = ["secret"], IncludedExtensions = [extension] }]
        };
        var policy = new Policy { Name = "Secrets", Severity = Severity.High };
        var link = new PolicyClassifier { Classifier = classifier, ClassifierId = classifier.Id, Policy = policy, PolicyId = policy.Id };
        classifier.PolicyClassifiers.Add(link);
        policy.PolicyClassifiers.Add(link);
        return ([classifier], [policy]);
    }
}
