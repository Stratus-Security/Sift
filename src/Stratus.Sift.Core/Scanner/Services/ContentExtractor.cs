using System.Buffers;
using System.Collections.Frozen;
using System.Text;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using Stratus.Sift.Scanner.Models;
using UglyToad.PdfPig;
using Excel = DocumentFormat.OpenXml.Spreadsheet;

namespace Stratus.Sift.Scanner.Services;

public partial class ContentExtractor
{
    private static readonly AsyncLocal<ExtractionState?> CurrentExtraction = new();
    private static int MaxFileSize => CurrentExtraction.Value?.MaximumInputBytes ?? 10 * 1024 * 1024;
    private static int MaxExtractedCharacters => CurrentExtraction.Value?.MaximumCharacters ?? 10 * 1024 * 1024;

    public static IReadOnlySet<string> SupportedExtensions { get; } = new[]
    {
        ".pdf", ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
        ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
        ".doc", ".dot", ".xls", ".xlt", ".xlsb", ".ppt", ".pot", ".pps", ".one", ".onepkg",
        ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif", ".webp"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    public bool Supports(string extension) => SupportedExtensions.Contains(extension);

    public string Extract(string filePath)
        => ExtractWithResult(filePath).Text;

    public ContentExtractionResult ExtractWithResult(string filePath, ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > (options?.MaxBinaryDocumentBytes ?? MaxFileSize))
            {
                return Failure("Document exceeds the extraction size limit.");
            }
            
            using var stream = File.OpenRead(filePath);
            return ExtractWithResult(stream, Path.GetExtension(filePath), options, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return Failure(ex.Message);
        }
    }

    public string Extract(Stream stream, string extension)
        => ExtractWithResult(stream, extension).Text;

    public ContentExtractionResult ExtractWithResult(Stream stream, string extension, ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        var previous = CurrentExtraction.Value;
        CurrentExtraction.Value = new ExtractionState(options ?? new ScanOptions(), cancellationToken);
        try { return ExtractDocument(stream, extension); }
        finally { CurrentExtraction.Value = previous; }
    }

    private static ContentExtractionResult ExtractDocument(Stream stream, string extension)
    {
        Stream streamToUse = stream;
        MemoryStream? bufferedStream = null;

        try
        {
            // If stream is not seekable (e.g. NetworkStream), copy to MemoryStream
            // PDF and OpenXml libraries usually require seekable streams
            if (!stream.CanSeek)
            {
                bufferedStream = new MemoryStream(capacity: 64 * 1024);
                if (!CopyToBounded(stream, bufferedStream, MaxFileSize))
                {
                    return Failure("Document exceeds the extraction size limit.");
                }
                bufferedStream.Position = 0;
                streamToUse = bufferedStream;
            }

            if (streamToUse.Length > MaxFileSize) return Failure("Document exceeds the extraction size limit.");

            CurrentExtraction.Value?.Cancellation.ThrowIfCancellationRequested();
            if (!SupportedExtensions.Contains(extension)) return Failure($"Unsupported document extension: {extension}.");
            streamToUse.Position = 0;
            switch (extension.ToLowerInvariant())
            {
                case ".pdf": return ExtractPdf(streamToUse);
                case ".docx": case ".docm": case ".dotx": case ".dotm": return ExtractDocx(streamToUse);
                case ".xlsx": case ".xlsm": case ".xltx": case ".xltm": return ExtractXlsx(streamToUse);
                case ".pptx": case ".pptm": case ".potx": case ".potm": case ".ppsx": case ".ppsm":
                    return ExtractPptx(streamToUse);
                case ".doc": case ".dot": return ExtractLegacyWord(streamToUse);
                case ".xls": case ".xlt": return ExtractLegacyExcel(streamToUse);
                case ".xlsb": return ExtractBinaryWorkbook(streamToUse);
                case ".ppt": case ".pot": case ".pps": return ExtractLegacyPowerPoint(streamToUse);
                case ".one": case ".onepkg": return ExtractOneNote(streamToUse, extension);
                default: return ExtractImageOcr(streamToUse, extension);
            }
        }
        catch (OperationCanceledException) when (CurrentExtraction.Value?.Cancellation.IsCancellationRequested == true) { throw; }
        catch (Exception ex)
        {
            return Failure(ex.Message);
        }
        finally
        {
            bufferedStream?.Dispose();
        }
    }

    private static ContentExtractionResult ExtractPdf(Stream stream)
    {
        using var document = PdfDocument.Open(stream);
        var sb = new StringBuilder();
        foreach (var page in document.GetPages())
        {
            CurrentExtraction.Value?.Cancellation.ThrowIfCancellationRequested();
            if (page.Number > 10_000 || CurrentExtraction.Value?.Elapsed.Elapsed > TimeSpan.FromMinutes(2))
                return new(sb.ToString(), false, "PDF exceeds its page or time limit.");
            if (!AppendBounded(sb, page.Text, appendNewLine: true)) return Truncated(sb);
        }
        return AppendPdfOcr(document, sb);
    }

    private static ContentExtractionResult ExtractDocx(Stream stream)
    {
        using var doc = WordprocessingDocument.Open(stream, false, ExtractionOpenSettings());
        return ExtractWordDocument(doc);
    }

    private static ContentExtractionResult ExtractWordDocument(WordprocessingDocument doc)
    {
        if (doc.MainDocumentPart == null) return Failure("Document has no main document part.");

        var sb = new StringBuilder();
        var hasEmbeddedContent = false;
        foreach (var part in EnumerateParts(doc.MainDocumentPart))
        {
            hasEmbeddedContent |= IsEmbeddedContent(part);
            if (!IsXmlPart(part)) continue;
            if (!AppendXmlText(part, sb, word: true)) return Truncated(sb);
        }
        return AppendPackageAttachments(doc.MainDocumentPart, sb, hasEmbeddedContent);
    }

    private static ContentExtractionResult ExtractXlsx(Stream stream)
    {
        using var doc = SpreadsheetDocument.Open(stream, false, ExtractionOpenSettings());
        return ExtractWorkbook(doc);
    }

    private static ContentExtractionResult ExtractWorkbook(SpreadsheetDocument doc)
    {
        if (doc.WorkbookPart == null) return Failure("Document has no workbook part.");
        var sb = new StringBuilder();
        var sharedStringTable = doc.WorkbookPart.SharedStringTablePart?.SharedStringTable;

        foreach (var worksheetPart in doc.WorkbookPart.WorksheetParts)
        {
            using var reader = OpenXmlReader.Create(worksheetPart);
            bool isSharedString = false;
            bool isInlineString = false;

            while (reader.Read())
            {
                if (reader.ElementType == typeof(Excel.Cell))
                {
                    if (reader.IsStartElement)
                    {
                        var typeAttr = reader.Attributes.FirstOrDefault(a => a.LocalName == "t");
                        isSharedString = typeAttr.Value == "s";
                        isInlineString = typeAttr.Value == "inlineStr";
                    }
                    else if (reader.IsEndElement)
                    {
                        if (!AppendBounded(sb, " ", appendNewLine: false)) return Truncated(sb);
                        isInlineString = false;
                    }
                }
                else if (reader.IsStartElement && reader.ElementType == typeof(Excel.CellFormula))
                {
                    if (!AppendBounded(sb, reader.GetText(), appendNewLine: true)) return Truncated(sb);
                }
                else if (reader.IsStartElement
                         && (reader.ElementType == typeof(Excel.CellValue)
                             || (isInlineString && reader.ElementType == typeof(Excel.Text))))
                {
                    var text = reader.GetText();
                    if (isSharedString)
                    {
                        if (!int.TryParse(text, out int index) || index < 0
                            || sharedStringTable?.ElementAtOrDefault(index) is not { } item)
                        {
                            return Failure("Cell refers to a missing shared string.");
                        }
                        text = item.InnerText;
                    }
                    if (!AppendBounded(sb, text, appendNewLine: false)) return Truncated(sb);
                }
            }
            if (!AppendBounded(sb, string.Empty, appendNewLine: true)) return Truncated(sb);
        }
        var hasEmbeddedContent = false;
        foreach (var part in EnumerateParts(doc.WorkbookPart))
        {
            hasEmbeddedContent |= IsEmbeddedContent(part);
            if (part is WorksheetCommentsPart && !AppendXmlText(part, sb, word: false)) return Truncated(sb);
        }
        return AppendPackageAttachments(doc.WorkbookPart, sb, hasEmbeddedContent);
    }

    private static ContentExtractionResult Failure(string error) => new(string.Empty, false, error);

    private static ContentExtractionResult Truncated(StringBuilder text)
        => new(text.ToString(), false, "Document exceeds the extracted text limit.");

    private static bool CopyToBounded(Stream source, Stream destination, long maximumBytes)
    {
        var pool = ArrayPool<byte>.Shared;
        var buffer = pool.Rent(64 * 1024);
        long totalBytes = 0;
        try
        {
            while (true)
            {
                var read = source.Read(buffer, 0, buffer.Length);
                CurrentExtraction.Value?.Cancellation.ThrowIfCancellationRequested();
                if (read <= 0) return true;
                totalBytes += read;
                if (totalBytes > maximumBytes) return false;
                destination.Write(buffer, 0, read);
            }
        }
        finally
        {
            pool.Return(buffer);
        }
    }

    private static bool AppendBounded(StringBuilder builder, string value, bool appendNewLine)
    {
        var newlineLength = appendNewLine ? Environment.NewLine.Length : 0;
        var remaining = MaxExtractedCharacters - builder.Length;
        if (remaining < newlineLength) return false;

        var charactersToAppend = Math.Min(value.Length, remaining - newlineLength);
        builder.Append(value.AsSpan(0, charactersToAppend));
        if (appendNewLine) builder.AppendLine();
        return charactersToAppend == value.Length;
    }
}
