using System.Text;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using UglyToad.PdfPig;
using Word = DocumentFormat.OpenXml.Wordprocessing;
using Excel = DocumentFormat.OpenXml.Spreadsheet;

namespace Stratus.Sift.Scanner.Services;

public class ContentExtractor
{
    private const long MaxFileSize = 10 * 1024 * 1024; // 10MB limit for extraction

    public bool Supports(string extension)
    {
        return extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase);
    }

    public string Extract(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > MaxFileSize)
            {
                return string.Empty;
            }
            
            using var stream = File.OpenRead(filePath);
            return Extract(stream, Path.GetExtension(filePath));
        }
        catch
        {
            return string.Empty;
        }
    }

    public string Extract(Stream stream, string extension)
    {
        Stream streamToUse = stream;
        bool shouldDispose = false;

        try
        {
            // If stream is not seekable (e.g. NetworkStream), copy to MemoryStream
            // PDF and OpenXml libraries usually require seekable streams
            if (!stream.CanSeek)
            {
                var ms = new MemoryStream();
                stream.CopyTo(ms);
                ms.Position = 0;
                streamToUse = ms;
                shouldDispose = true;
            }

            if (streamToUse.Length > MaxFileSize) return string.Empty;

            if (extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase))
            {
                return ExtractPdf(streamToUse);
            }
            if (extension.Equals(".docx", StringComparison.OrdinalIgnoreCase))
            {
                return ExtractDocx(streamToUse);
            }
            if (extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase))
            {
                return ExtractXlsx(streamToUse);
            }
            return string.Empty;
        }
        finally
        {
            if (shouldDispose)
            {
                streamToUse.Dispose();
            }
        }
    }

    private string ExtractPdf(Stream stream)
    {
        try
        {
            using var document = PdfDocument.Open(stream);
            var sb = new StringBuilder();
            foreach (var page in document.GetPages())
            {
                sb.AppendLine(page.Text);
            }
            return sb.ToString();
        }
        catch
        {
            return string.Empty;
        }
    }

    private string ExtractDocx(Stream stream)
    {
        try
        {
            using var doc = WordprocessingDocument.Open(stream, false);
            if (doc.MainDocumentPart?.Document?.Body == null) return string.Empty;

            var sb = new StringBuilder();
            // Iterate over paragraphs to ensure separation
            foreach (var paragraph in doc.MainDocumentPart.Document.Body.Descendants<Word.Paragraph>())
            {
                sb.AppendLine(paragraph.InnerText);
            }
            return sb.ToString();
        }
        catch
        {
            return string.Empty;
        }
    }

    private string ExtractXlsx(Stream stream)
    {
        try
        {
            using var doc = SpreadsheetDocument.Open(stream, false);
            var sb = new StringBuilder();
            var sharedStringTable = doc.WorkbookPart?.SharedStringTablePart?.SharedStringTable;

            if (doc.WorkbookPart != null)
            {
                foreach (var worksheetPart in doc.WorkbookPart.WorksheetParts)
                {
                    using var reader = OpenXmlReader.Create(worksheetPart);
                    bool isSharedString = false;

                    while (reader.Read())
                    {
                        if (reader.ElementType == typeof(Excel.Cell))
                        {
                            if (reader.IsStartElement)
                            {
                                var typeAttr = reader.Attributes.FirstOrDefault(a => a.LocalName == "t");
                                isSharedString = (typeAttr.Value == "s");
                            }
                        }
                        else if (reader.ElementType == typeof(Excel.CellValue))
                        {
                             if (reader.IsStartElement)
                             {
                                 string text = reader.GetText();
                                 if (!string.IsNullOrEmpty(text))
                                 {
                                     if (isSharedString && int.TryParse(text, out int index) && sharedStringTable != null)
                                     {
                                         var item = sharedStringTable.ElementAtOrDefault(index);
                                         if (item != null) text = item.InnerText;
                                     }
                                     sb.Append(text + " ");
                                 }
                             }
                        }
                    }
                    sb.AppendLine();
                }
            }
            return sb.ToString();
        }
        catch
        {
             return string.Empty;
        }
    }
}
