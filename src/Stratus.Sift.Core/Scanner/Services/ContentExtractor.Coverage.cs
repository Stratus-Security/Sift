using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using DocumentFormat.OpenXml.Packaging;
using ExcelDataReader;
using OpenMcdf;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Models;

namespace Stratus.Sift.Scanner.Services;

public partial class ContentExtractor
{
    private sealed class ExtractionState(ScanOptions options, CancellationToken cancellation)
    {
        internal ScanOptions Options { get; } = options;
        internal CancellationToken Cancellation { get; } = cancellation;
        internal int MaximumInputBytes { get; } = checked((int)Math.Clamp(options.MaxBinaryDocumentBytes, 1, 512L * 1024 * 1024));
        internal int MaximumCharacters { get; } = Math.Clamp(options.MaxExtractedCharacters, 1, 64 * 1024 * 1024);
        internal int Depth;
        internal int Parts;
        internal long ExpandedBytes;
        internal HashSet<string> Attachments { get; } = new(StringComparer.Ordinal);
        internal Stopwatch Elapsed { get; } = Stopwatch.StartNew();
        internal Exception? FailureException;
        internal bool HasUnexpectedFailure;
    }

    private static ContentExtractionResult ExtractBinaryWorkbook(Stream source)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var text = new StringBuilder();
        using (var workbook = ExcelReaderFactory.CreateReader(source, new ExcelReaderConfiguration { LeaveOpen = true }))
        {
            var rows = 0; var sheets = 0; var cells = 0;
            do
            {
                if (++sheets > 10_000) return new(text.ToString(), false, "Workbook exceeds its sheet limit.");
                if (!AppendBounded(text, workbook.Name, true)) return Truncated(text);
                while (workbook.Read())
                {
                    CurrentExtraction.Value?.Cancellation.ThrowIfCancellationRequested();
                    if (++rows > 1_000_000 || workbook.FieldCount > 16_384
                        || CurrentExtraction.Value?.Elapsed.Elapsed > TimeSpan.FromMinutes(2))
                        return new(text.ToString(), false, "Workbook exceeds its row or time limit.");
                    for (var column = 0; column < workbook.FieldCount; column++)
                    {
                        if (++cells > 1_000_000) return new(text.ToString(), false, "Workbook exceeds its cell limit.");
                        if (!AppendBounded(text, Convert.ToString(workbook.GetValue(column), CultureInfo.InvariantCulture) ?? "", true))
                            return Truncated(text);
                    }
                }
            } while (workbook.NextResult());
        }
        source.Position = 0;
        using var archive = new ZipArchive(source, ZipArchiveMode.Read, leaveOpen: true);
        var complete = true;
        foreach (var entry in archive.Entries)
        {
            if (entry.Length > 64 * 1024 * 1024) { complete = false; continue; }
            if (entry.FullName.Contains("comments", StringComparison.OrdinalIgnoreCase)
                && entry.FullName.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)) { complete = false; continue; }
            if (entry.FullName.Contains("comments", StringComparison.OrdinalIgnoreCase) && entry.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = entry.Open();
                using var reader = System.Xml.XmlReader.Create(stream, new System.Xml.XmlReaderSettings
                { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 64 * 1024 * 1024 });
                while (reader.Read()) if (reader.NodeType is System.Xml.XmlNodeType.Text or System.Xml.XmlNodeType.CDATA)
                    if (!AppendBounded(text, reader.Value, true)) return Truncated(text);
            }
            else if (entry.FullName.StartsWith("xl/worksheets/", StringComparison.OrdinalIgnoreCase) && entry.FullName.EndsWith(".bin", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = entry.Open();
                // ExcelDataReader returns cached formula values, not expression text.
                while (true)
                {
                    CurrentExtraction.Value?.Cancellation.ThrowIfCancellationRequested();
                    var first = stream.ReadByte(); if (first < 0) break;
                    var type = first & 0x7f;
                    if ((first & 0x80) != 0) { var next = stream.ReadByte(); if (next < 0) throw new InvalidDataException("Truncated XLSB record."); type |= (next & 0x7f) << 7; }
                    var length = 0; var shift = 0;
                    while (true)
                    {
                        var next = stream.ReadByte(); if (next < 0 || shift > 21) throw new InvalidDataException("Invalid XLSB record length.");
                        length |= (next & 0x7f) << shift;
                        if ((next & 0x80) == 0) break;
                        shift += 7;
                    }
                    if (type is >= 8 and <= 11) complete = false;
                    var buffer = new byte[Math.Min(length, 64 * 1024)];
                    var remaining = length;
                    while (remaining > 0) { var read = stream.Read(buffer, 0, Math.Min(buffer.Length, remaining)); if (read == 0) throw new InvalidDataException("Truncated XLSB record."); remaining -= read; }
                }
            }
            else if (entry.FullName.Contains("embeddings/", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = entry.Open();
                var attachment = ExtractAttachment(stream, Path.GetExtension(entry.FullName));
                complete &= attachment.IsComplete;
                if (!AppendBounded(text, attachment.Text, true)) return Truncated(text);
            }
        }
        return new(text.ToString(), complete, complete ? null : "Some XLSB formula expressions, binary comments or embedded content could not be inspected.");
    }

    private static ContentExtractionResult AppendPackageAttachments(OpenXmlPart root, StringBuilder text, bool hasEmbeddedContent)
    {
        var complete = true;
        foreach (var part in EnumerateParts(root))
        {
            var embedded = IsEmbeddedContent(part);
            var image = part is ImagePart && CurrentExtraction.Value?.Options.EnableOcr == true;
            if (!embedded && !image) continue;
            using var stream = part.GetStream(FileMode.Open, FileAccess.Read);
            var extension = Path.GetExtension(part.Uri.OriginalString);
            if (part.ContentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase)
                && !ContentExtensionProfiles.Resolve(ContentExtensionProfiles.SourceAndConfig).Contains(extension)) extension = ".txt";
            var result = ExtractAttachment(stream, extension);
            complete &= result.IsComplete;
            if (!AppendBounded(text, result.Text, true)) return Truncated(text);
        }
        return new(text.ToString(), complete, complete ? null : "Some embedded attachments or images could not be inspected.");
    }

    private static ContentExtractionResult ExtractAttachment(Stream input, string extension)
    {
        try { return ExtractAttachmentCore(input, extension); }
        catch (Exception ex) when (!(ex is OperationCanceledException && CurrentExtraction.Value?.Cancellation.IsCancellationRequested == true))
        { return Failure(ex); }
    }

    private static ContentExtractionResult ExtractAttachmentCore(Stream input, string extension)
    {
        var state = CurrentExtraction.Value;
        if (state == null) return Failure("Embedded content has no extraction budget.");
        state.Cancellation.ThrowIfCancellationRequested();
        if (state.Depth >= Math.Clamp(state.Options.MaxEmbeddedDocumentDepth, 1, 8) || ++state.Parts > 1000
            || state.Elapsed.Elapsed > TimeSpan.FromMinutes(2)) return Failure("Embedded content exceeded its traversal limit.");
        using var buffer = new MemoryStream();
        if (!CopyToBounded(input, buffer, state.MaximumInputBytes)) return Failure("Embedded content exceeded its size limit.");
        state.ExpandedBytes += buffer.Length;
        if (state.ExpandedBytes > 512L * 1024 * 1024) return Failure("Embedded content exceeded the shared expansion limit.");
        var bytes = buffer.GetBuffer().AsSpan(0, checked((int)buffer.Length));
        var identity = Convert.ToHexString(SHA256.HashData(bytes));
        if (!state.Attachments.Add(identity)) return new("", true);
        buffer.Position = 0;
        if (bytes.Length >= 8 && bytes[..8].SequenceEqual(new byte[] { 208, 207, 17, 224, 161, 177, 26, 225 }))
        {
            using var storage = RootStorage.Open(buffer, StorageModeFlags.LeaveOpen);
            if (storage.TryOpenStream("Package", out var package))
            {
                using (package)
                {
                    state.Depth++;
                    try { return ExtractAttachment(package, ".bin"); }
                    finally { state.Depth--; }
                }
            }
            if (storage.TryOpenStream("\u0001Ole10Native", out var native))
            {
                using (native) return ExtractOleNative(native);
            }
            buffer.Position = 0;
        }
        if (!SupportedExtensions.Contains(extension)) extension = DetectEmbeddedExtension(buffer, extension);
        state.Depth++;
        try
        {
            if (SupportedExtensions.Contains(extension)) return ExtractDocument(buffer, extension);
            if (FileScanner.IsSupportedArchive(extension)) return ExtractEmbeddedArchive(buffer, extension);
            if (ContentExtensionProfiles.Resolve(ContentExtensionProfiles.SourceAndConfig).Contains(extension))
            {
                buffer.Position = 0;
                using var reader = new StreamReader(buffer, Encoding.UTF8, true, leaveOpen: true);
                var chars = new char[Math.Min(64 * 1024, MaxExtractedCharacters)];
                var text = new StringBuilder(); int read;
                while ((read = reader.Read(chars, 0, chars.Length)) > 0)
                    if (!AppendBounded(text, new string(chars, 0, read), false)) return Truncated(text);
                return new(text.ToString(), true);
            }
            return Failure("Embedded content format is unsupported.");
        }
        catch (Exception ex) when (!(ex is OperationCanceledException && state.Cancellation.IsCancellationRequested)) { return Failure(ex); }
        finally { state.Depth--; }
    }

    private static ContentExtractionResult ExtractOleNative(Stream source)
    {
        using var reader = new BinaryReader(source, Encoding.UTF8, leaveOpen: true);
        var total = reader.ReadUInt32();
        if (total > MaxFileSize || total > source.Length - source.Position) return Failure("OLE native payload is truncated or oversized.");
        var flags = reader.ReadUInt16();
        if (flags != 2) return Failure("OLE native package variant is unsupported.");
        string CString()
        {
            using var value = new MemoryStream();
            for (var count = 0; count < 4096; count++)
            {
                var next = reader.ReadByte();
                if (next == 0) return Encoding.UTF8.GetString(value.ToArray());
                value.WriteByte(next);
            }
            throw new InvalidDataException("OLE native filename exceeds its limit.");
        }
        var label = CString();
        var filename = CString();
        reader.ReadUInt16(); reader.ReadUInt16(); CString();
        var length = reader.ReadUInt32();
        if (length > MaxFileSize || length > source.Length - source.Position) return Failure("OLE native payload is truncated or oversized.");
        using var payload = new MemoryStream(reader.ReadBytes(checked((int)length)), false);
        CurrentExtraction.Value!.Depth++;
        try { return ExtractAttachment(payload, Path.GetExtension(string.IsNullOrEmpty(label) ? filename : label)); }
        finally { CurrentExtraction.Value.Depth--; }
    }

    private static string DetectEmbeddedExtension(Stream stream, string fallback)
    {
        Span<byte> signature = stackalloc byte[8];
        stream.Position = 0; var length = stream.Read(signature); stream.Position = 0;
        if (length >= 4 && signature[..4].SequenceEqual("%PDF"u8)) return ".pdf";
        if (length >= 8 && signature.SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 })) return ".png";
        if (length >= 3 && signature[0] == 255 && signature[1] == 216 && signature[2] == 255) return ".jpg";
        if (length >= 2 && signature[0] == 'P' && signature[1] == 'K')
        {
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, true);
            if (archive.GetEntry("word/document.xml") != null) return ".docx";
            if (archive.GetEntry("xl/workbook.xml") != null) return ".xlsx";
            if (archive.GetEntry("xl/workbook.bin") != null) return ".xlsb";
            if (archive.GetEntry("ppt/presentation.xml") != null) return ".pptx";
            return ".zip";
        }
        if (length == 8 && signature.SequenceEqual(new byte[] { 208, 207, 17, 224, 161, 177, 26, 225 }))
        {
            using var storage = RootStorage.Open(stream, StorageModeFlags.LeaveOpen);
            foreach (var (name, extension) in new[] { ("WordDocument", ".doc"), ("Workbook", ".xls"), ("Book", ".xls"), ("PowerPoint Document", ".ppt") })
                if (storage.TryOpenStream(name, out var part)) { part.Dispose(); return extension; }
        }
        return fallback;
    }
}
