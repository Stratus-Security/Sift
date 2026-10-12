using System.Text;
using OfficeIMO.OneNote;
using Stratus.Sift.Scanner.Models;

namespace Stratus.Sift.Scanner.Services;

public partial class ContentExtractor
{
    private static ContentExtractionResult ExtractOneNote(Stream stream, string extension)
    {
        var options = new OneNoteReaderOptions
        {
            MaxInputBytes = MaxFileSize,
            MaxAssetBytes = MaxFileSize,
            MaxTotalAssetBytes = MaxFileSize,
            MaxFileNodes = 100_000,
            MaxObjects = 100_000,
            MaxStreamObjects = 100_000,
            MaxPropertySetDepth = 64,
            MaxPageRelationshipDepth = 64,
            MaxPageGraphNodes = 10_000
        };
        var projection = new OneNoteTextProjection();
        if (extension.Equals(".onepkg", StringComparison.OrdinalIgnoreCase))
        {
            var notebook = OneNotePackageReader.Read(stream, options: new OneNoteNotebookReaderOptions
            {
                OneNoteOptions = options,
                ContinueOnSectionError = true,
                MaxPackageEntries = 10_000,
                MaxPackageEntryBytes = MaxFileSize,
                MaxPackageExpandedBytes = 64L * 1024 * 1024,
                MaxSectionGroupDepth = 32
            });
            projection.CheckDiagnostics(notebook.Diagnostics);
            projection.Append(notebook.Name);
            projection.Sections(notebook.Sections);
            projection.Groups(notebook.SectionGroups, 0);
        }
        else
        {
            projection.Section(OneNoteSectionReader.Read(stream, options));
        }
        return projection.Result();
    }

    private sealed class OneNoteTextProjection
    {
        private readonly StringBuilder _text = new();
        private readonly HashSet<object> _visited = new(ReferenceEqualityComparer.Instance);
        private string? _error;
        private bool _truncated;

        public ContentExtractionResult Result() => new(_text.ToString(), _error == null, _error);

        public void CheckDiagnostics(IEnumerable<OneNoteDiagnostic> diagnostics)
        {
            var diagnostic = diagnostics.FirstOrDefault(d => d.Severity >= OneNoteDiagnosticSeverity.Warning);
            if (diagnostic != null) _error ??= $"OneNote parser reported {diagnostic.Code}: {diagnostic.Message}";
        }

        public void Append(string? value, bool newline = true)
        {
            if (_truncated) return;
            // Native RichEdit paragraph and line separators must become searchable text boundaries.
            value = (value ?? string.Empty).Replace('\r', '\n').Replace('\u2028', '\n').Replace('\u2029', '\n');
            if (!AppendBounded(_text, value, newline))
            {
                _truncated = true;
                _error = "Document exceeds the extracted text limit.";
            }
        }

        private bool Visit(object node, int depth)
        {
            if (_truncated) return false;
            if (depth > 64 || _visited.Count >= 100_000 || !_visited.Add(node))
            {
                _error ??= "OneNote content graph exceeds traversal limits or repeats an object.";
                return false;
            }
            return true;
        }

        public void Sections(IEnumerable<OneNoteSection> sections)
        {
            foreach (var section in sections) Section(section);
        }

        public void Groups(IEnumerable<OneNoteSectionGroup> groups, int depth)
        {
            foreach (var group in groups)
            {
                if (!Visit(group, depth)) continue;
                if (group.IsRecycleBin && CurrentExtraction.Value?.Options.IncludeDocumentHistory != true) continue;
                Append(group.Name);
                Sections(group.Sections);
                Groups(group.SectionGroups, depth + 1);
            }
        }

        public void Section(OneNoteSection section)
        {
            if (!Visit(section, 0)) return;
            CheckDiagnostics(section.Diagnostics);
            if (section.UnknownObjects.Count > 0) _error ??= "OneNote section contains unprojected objects.";
            Append(section.Name);
            foreach (var page in section.Pages) Page(page, 0);
        }

        private void Page(OneNotePage page, int depth)
        {
            if (!Visit(page, depth) || ((page.IsDeleted || page.IsVersionHistoryPage)
                && CurrentExtraction.Value?.Options.IncludeDocumentHistory != true)) return;
            CheckDiagnostics(page.Diagnostics);
            if (page.UnknownObjects.Count > 0) _error ??= "OneNote page contains unprojected objects.";
            Append(page.Title);
            Elements(page.Outlines, 0);
            Elements(page.DirectContent, 0);
            foreach (var conflict in page.ConflictPages) Page(conflict, depth + 1);
            if (CurrentExtraction.Value?.Options.IncludeDocumentHistory == true)
                foreach (var history in page.VersionHistory) Page(history, depth + 1);
        }

        private void Elements(IEnumerable<OneNoteElement> elements, int depth)
        {
            foreach (var element in elements)
            {
                if (!Visit(element, depth)) continue;
                switch (element)
                {
                    case OneNoteOutline outline:
                        Elements(outline.Children, depth + 1);
                        break;
                    case OneNoteParagraph paragraph:
                        foreach (var run in paragraph.Runs) Append(run.Text, newline: false);
                        Append(string.Empty);
                        foreach (var run in paragraph.Runs)
                            if (!string.IsNullOrEmpty(run.Hyperlink)) Append(run.Hyperlink);
                        Elements(paragraph.Children, depth + 1);
                        break;
                    case OneNoteTable table:
                        foreach (var row in table.Rows)
                        {
                            foreach (var cell in row.Cells) Elements(cell.Content, depth + 1);
                            Append(string.Empty);
                        }
                        break;
                    case OneNoteImage image:
                        Append(image.AltText);
                        Append(image.OcrText);
                        Append(image.Hyperlink);
                        if (CurrentExtraction.Value?.Options.EnableOcr == true && string.IsNullOrWhiteSpace(image.OcrText))
                        {
                            if (image.Payload == null) { _error ??= "OneNote image has no payload."; break; }
                            using var payload = image.Payload.OpenRead();
                            var result = ExtractAttachment(payload, Path.GetExtension(image.FileName ?? image.SourcePath ?? "image.bin"));
                            Append(result.Text);
                            if (!result.IsComplete) _error ??= result.Error;
                        }
                        break;
                    case OneNoteInk ink:
                        foreach (var stroke in ink.Strokes) Append(stroke.RecognizedText);
                        break;
                    case OneNoteMath math:
                        Append(math.Text);
                        break;
                    case OneNoteEmbeddedFile file:
                        Append(file.SourcePath);
                        if (file.Payload == null) { _error ??= "OneNote attachment has no payload."; break; }
                        using (var payload = file.Payload.OpenRead())
                        {
                            var result = ExtractAttachment(payload, Path.GetExtension(file.FileName ?? file.SourcePath ?? "attachment.bin"));
                            Append(result.Text);
                            if (!result.IsComplete) _error ??= result.Error;
                        }
                        break;
                    case OneNoteMedia media:
                        Append(media.SourcePath);
                        _error ??= "OneNote contains audio or video whose contents were not inspected.";
                        break;
                    default:
                        _error ??= "OneNote contains an unsupported content element.";
                        break;
                }
            }
        }
    }
}
