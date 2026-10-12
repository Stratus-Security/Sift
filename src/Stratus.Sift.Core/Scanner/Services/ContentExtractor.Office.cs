using System.Text;
using System.Xml;
using DocumentFormat.OpenXml.Packaging;
using OfficeIMO;
using OfficeIMO.Excel;
using OfficeIMO.Excel.LegacyXls;
using OfficeIMO.PowerPoint;
using OfficeIMO.PowerPoint.LegacyPpt;
using OfficeIMO.Word;
using OfficeIMO.Word.LegacyDoc;
using Stratus.Sift.Scanner.Models;

namespace Stratus.Sift.Scanner.Services;

public partial class ContentExtractor
{
    private const long MaxXmlCharacters = 64 * 1024 * 1024;

    private static OpenSettings ExtractionOpenSettings() => new() { MaxCharactersInPart = MaxXmlCharacters };

    private static ContentExtractionResult ExtractPptx(Stream stream)
    {
        using var document = PresentationDocument.Open(stream, false, ExtractionOpenSettings());
        return ExtractPresentation(document);
    }

    private static ContentExtractionResult ExtractPresentation(PresentationDocument document)
    {
        if (document.PresentationPart == null) return Failure("Document has no presentation part.");
        var text = new StringBuilder();
        var hasEmbeddedContent = false;
        // Follow package relationships once, including hidden slides, notes, masters,
        // layouts, tables, charts, diagrams, and comments. External links are not opened.
        foreach (var part in EnumerateParts(document.PresentationPart))
        {
            hasEmbeddedContent |= IsEmbeddedContent(part);
            if (IsXmlPart(part) && !AppendXmlText(part, text, word: false)) return Truncated(text);
        }
        return AppendPackageAttachments(document.PresentationPart, text, hasEmbeddedContent);
    }

    private static bool IsEmbeddedContent(OpenXmlPart part)
        => part is EmbeddedPackagePart or EmbeddedObjectPart;

    private static ContentExtractionResult WithEmbeddedContentStatus(ContentExtractionResult result, bool hasEmbeddedContent)
        => hasEmbeddedContent ? result with
        {
            IsComplete = false,
            Error = result.Error ?? "Document contains embedded attachments that were not inspected."
        } : result;

    private static ContentExtractionResult ExtractLegacyWord(Stream stream)
    {
        using var imported = WordDocument.LoadLegacyDocWithReport(stream, new LegacyDocImportOptions
        {
            MaxInputBytes = MaxFileSize,
            MaxDecodedCharacters = MaxExtractedCharacters,
            MaxDecodedImageBytes = MaxFileSize,
            ReportUnsupportedContent = true
        });
        if (!imported.HasDocument) return Failure("Legacy Word content could not be projected.");
        imported.Document.OpenXmlDocument.Save();
        return WithImportStatus(ExtractWordDocument(imported.Document.OpenXmlDocument),
            imported.HasImportErrors || HasUninspectedContent(imported.FidelityDiagnostics), "Word");
    }

    private static ContentExtractionResult ExtractLegacyExcel(Stream stream)
    {
        using var imported = ExcelDocument.LoadLegacyXlsWithReport(stream, new LegacyXlsImportOptions
        {
            MaxInputBytes = MaxFileSize,
            MaxDecodedImageBytes = MaxFileSize,
            ReportUnsupportedContent = true
        });
        if (!imported.HasDocument) return Failure("Legacy Excel content could not be projected.");
        imported.Document.OpenXmlDocument.Save();
        return WithImportStatus(ExtractWorkbook(imported.Document.OpenXmlDocument),
            imported.HasImportErrors || HasUninspectedContent(imported.FidelityDiagnostics), "Excel");
    }

    private static ContentExtractionResult ExtractLegacyPowerPoint(Stream stream)
    {
        using var imported = PowerPointPresentation.LoadLegacyPptWithReport(stream, new LegacyPptImportOptions
        {
            MaxInputBytes = MaxFileSize,
            MaxDecodedStorageBytes = MaxFileSize,
            MaxRecordCount = 100_000,
            MaxSlideCount = 10_000,
            MaxRecordDepth = 64,
            ReportUnsupportedContent = true
        });
        if (!imported.HasDocument) return Failure("Legacy PowerPoint content could not be projected.");
        imported.Document.OpenXmlDocument.Save();
        var projected = ExtractPresentation(imported.Document.OpenXmlDocument);
        if (projected.Text.Length >= MaxExtractedCharacters) return projected;
        var text = new StringBuilder(projected.Text);
        try
        {
            if (!AppendLegacySlideListText(stream, text)) return Truncated(text);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or OverflowException)
        {
            return new(text.ToString(), false, $"Could not fully read PowerPoint's central slide text: {ex.Message}");
        }
        return WithImportStatus(projected with { Text = text.ToString() },
            imported.HasImportErrors || HasUninspectedContent(imported.FidelityDiagnostics), "PowerPoint");
    }

    // Formatting approximations preserve searchable text. Omitted, failed, or
    // unassessed content must not turn an import into a completed scan.
    private static bool HasUninspectedContent(IEnumerable<OfficeConversionFidelityDiagnostic> diagnostics)
        => diagnostics.Any(diagnostic => diagnostic.LossKind != OfficeConversionLossKind.None
            && diagnostic.LossKind != OfficeConversionLossKind.Approximation);

    private static ContentExtractionResult WithImportStatus(ContentExtractionResult result, bool hasLoss, string format)
        => hasLoss ? result with
        {
            IsComplete = false,
            Error = result.Error ?? $"Legacy {format} import reported errors or content that could not be fully projected."
        } : result;

    private static IEnumerable<OpenXmlPart> EnumerateParts(OpenXmlPart root)
    {
        var visited = new HashSet<OpenXmlPart>();
        var pending = new Stack<OpenXmlPart>();
        pending.Push(root);
        while (pending.TryPop(out var part))
        {
            if (!visited.Add(part)) continue;
            if (visited.Count > 4096) throw new InvalidDataException("Document exceeds the part count limit.");
            yield return part;
            foreach (var relationship in part.Parts) pending.Push(relationship.OpenXmlPart);
        }
    }

    private static bool IsXmlPart(OpenXmlPart part)
        => part.ContentType.EndsWith("xml", StringComparison.OrdinalIgnoreCase);

    private static bool AppendXmlText(OpenXmlPart part, StringBuilder text, bool word)
    {
        using var stream = part.GetStream(FileMode.Open, FileAccess.Read);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxXmlCharacters
        });
        var inText = false;
        while (reader.Read())
        {
            if (reader.NodeType == XmlNodeType.Element)
            {
                var knownNamespace = reader.NamespaceURI.Contains("openxmlformats.org", StringComparison.Ordinal)
                    || reader.NamespaceURI.StartsWith("http://schemas.microsoft.com/office/", StringComparison.Ordinal)
                    || reader.NamespaceURI.StartsWith("http://purl.oclc.org/ooxml/", StringComparison.Ordinal);
                inText = knownNamespace && (reader.LocalName is "t" or "text"
                    || (word && reader.LocalName is "instrText" or "delText")
                    || (!word && reader.LocalName == "v"));
                if (knownNamespace && reader.LocalName is "br" or "tab")
                {
                    if (!AppendBounded(text, reader.LocalName == "tab" ? "\t" : "\n", false)) return false;
                }
            }
            else if (reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace)
            {
                if (inText && !AppendBounded(text, reader.Value, false)) return false;
            }
            else if (reader.NodeType == XmlNodeType.EndElement)
            {
                inText = false;
                if (reader.LocalName is "p" or "text" or "v")
                {
                    if (!AppendBounded(text, string.Empty, true)) return false;
                }
            }
        }
        return AppendBounded(text, string.Empty, true);
    }
}
