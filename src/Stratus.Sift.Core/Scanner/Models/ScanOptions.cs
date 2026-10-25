using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Scanner.Models;

public class ScanOptions
{
    private const long MiB = 1024 * 1024;

    public long MaxFileSize { get; set; } = 10 * 1024 * 1024; // 10MB
    public int HeadSize { get; set; } = 1024 * 1024; // 1MB
    public int TailSize { get; set; } = 1024 * 1024; // 1MB

    public List<string> IncludedExtensions { get; set; } = new();

    /// <summary>
    /// Enable text extraction from PDF, modern and legacy Office documents, and OneNote files.
    /// Defaults to false.
    /// </summary>
    public bool EnableBinaryDocuments { get; set; } = false;
    public long MaxBinaryDocumentBytes { get; set; } = 10 * MiB;
    public int MaxExtractedCharacters { get; set; } = 10 * 1024 * 1024;
    public bool EnableOcr { get; set; }
    public string TesseractPath { get; set; } = "tesseract";
    public string OcrLanguage { get; set; } = "eng";
    public int OcrTimeoutSeconds { get; set; } = 30;
    public int MaxOcrPages { get; set; } = 200;
    public int MaxEmbeddedDocumentDepth { get; set; } = 3;
    public bool IncludeDocumentHistory { get; set; }

    /// <summary>
    /// Skip files that are stored in the cloud (OneDrive, Dropbox, etc.) to prevent hydration.
    /// Defaults to true.
    /// </summary>
    public bool SkipCloudFiles { get; set; } = true;

    /// <summary>
    /// Enable scanning of external files (shared from other organizations) found via links/shortcuts.
    /// Defaults to false.
    /// </summary>
    public bool ScanExternalFiles { get; set; } = false;

    public List<string> ExcludedDirectories { get; set; } = new();

    public bool EnableLlmValidation { get; set; }

    public string OllamaUrl { get; set; } = "http://localhost:11434";

    public string OllamaModel { get; set; } = string.Empty;

    public int LlmTimeoutSeconds { get; set; } = 20;

    public LlmThinkingLevel LlmThinkingLevel { get; set; } = LlmThinkingLevel.Off;

    public long MaxDiskReadBytesPerSecond { get; set; }

    /// <summary>
    /// Scan supported ZIP, RAR, 7z, TAR and compressed-stream archives. Archive-provided paths are never written to disk.
    /// </summary>
    public bool EnableZipArchives { get; set; }

    /// <summary>
    /// Maximum ZIP depth, including the root archive. The scanner clamps this value to 1-3.
    /// A value of 2 inspects one nested archive layer.
    /// </summary>
    public int MaxZipDepth { get; set; } = 2;

    /// <summary>
    /// Maximum number of file entries inspected across one ZIP archive tree.
    /// </summary>
    public int MaxZipEntries { get; set; } = 10_000;

    /// <summary>
    /// Maximum cumulative central-directory size loaded across one ZIP archive tree.
    /// </summary>
    public long MaxZipCentralDirectoryBytes { get; set; } = 32 * MiB;

    /// <summary>
    /// Maximum cumulative archive data buffered to delete-on-close temporary files across one
    /// ZIP archive tree when a connector or nested entry supplies a non-seekable stream.
    /// </summary>
    public long MaxZipBufferedContainerBytes { get; set; } = 512 * MiB;

    /// <summary>
    /// Maximum declared uncompressed size of a single ZIP entry.
    /// </summary>
    public long MaxZipEntryBytes { get; set; } = 256 * MiB;

    /// <summary>
    /// Maximum cumulative declared uncompressed size inspected across one ZIP archive tree.
    /// </summary>
    public long MaxZipExpandedBytes { get; set; } = 512 * MiB;

    /// <summary>
    /// Maximum allowed uncompressed-to-compressed ratio for an entry.
    /// </summary>
    public double MaxZipCompressionRatio { get; set; } = 200;

    public ScanDiagnostics? Diagnostics { get; set; }
}
