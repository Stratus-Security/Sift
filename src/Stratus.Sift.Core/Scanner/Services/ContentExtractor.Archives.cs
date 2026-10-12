using System.Text;
using SharpCompress.Archives;
using SharpCompress.Readers;
using Stratus.Sift.Scanner.Models;

namespace Stratus.Sift.Scanner.Services;

public partial class ContentExtractor
{
    private static ContentExtractionResult ExtractEmbeddedArchive(Stream source, string extension)
    {
        var text = new StringBuilder();
        var complete = true;
        IArchive? archive = null;
        IReader? reader = null;
        try
        {
            source.Position = 0;
            var options = new ReaderOptions { LeaveStreamOpen = true, ExtensionHint = extension, RewindableBufferSize = 1024 * 1024 };
            if (extension.Equals(".7z", StringComparison.OrdinalIgnoreCase))
            { archive = ArchiveFactory.OpenArchive(source, options); reader = archive.ExtractAllEntries(); }
            else reader = ReaderFactory.OpenReader(source, options);
            var names = new HashSet<string>(StringComparer.Ordinal);
            var count = 0;
            while (reader.MoveToNextEntry())
            {
                CurrentExtraction.Value!.Cancellation.ThrowIfCancellationRequested();
                var entry = reader.Entry;
                if (++count > 1000 || CurrentExtraction.Value.Elapsed.Elapsed > TimeSpan.FromMinutes(2))
                    return new(text.ToString(), false, "Embedded archive exceeds its entry or time limit.");
                if (entry.IsDirectory) continue;
                if (entry.IsEncrypted || entry.IsSplitAfter || !string.IsNullOrEmpty(entry.LinkTarget)
                    || entry.Size > MaxFileSize || !FileScanner.TryNormalizeZipEntryName(entry.Key ?? "", out var name) || !names.Add(name))
                    return new(text.ToString(), false, "Embedded archive contains unsupported or unsafe entries.");
                using var payload = reader.OpenEntryStream();
                var result = ExtractAttachment(payload, Path.GetExtension(name));
                complete &= result.IsComplete;
                if (!AppendBounded(text, result.Text, true)) return Truncated(text);
            }
        }
        catch (Exception ex) when (!(ex is OperationCanceledException && CurrentExtraction.Value!.Cancellation.IsCancellationRequested))
        { return new(text.ToString(), false, ex.Message); }
        finally { reader?.Dispose(); archive?.Dispose(); }
        return new(text.ToString(), complete, complete ? null : "Some embedded archive entries could not be inspected.");
    }
}
