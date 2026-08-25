namespace Stratus.Sift.Scanner.Models;

public class ScanOptions
{
    private const long MiB = 1024 * 1024;

    public long MaxFileSize { get; set; } = 10 * 1024 * 1024; // 10MB
    public int HeadSize { get; set; } = 1024 * 1024; // 1MB
    public int TailSize { get; set; } = 1024 * 1024; // 1MB

    public List<string> IncludedExtensions { get; set; } = new();

    /// <summary>
    /// Enable scanning of binary documents (PDF, DOCX, XLSX, etc.) via content extraction.
    /// Defaults to false.
    /// </summary>
    public bool EnableBinaryDocuments { get; set; } = false;

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

    public long MaxDiskReadBytesPerSecond { get; set; }

    /// <summary>
    /// Scan files stored inside ZIP archives. Entries are streamed and are never extracted to disk.
    /// </summary>
    public bool EnableZipArchives { get; set; }

    /// <summary>
    /// Maximum number of file entries inspected in one ZIP archive.
    /// </summary>
    public int MaxZipEntries { get; set; } = 10_000;

    /// <summary>
    /// Maximum central-directory size loaded into memory for one ZIP archive.
    /// </summary>
    public long MaxZipCentralDirectoryBytes { get; set; } = 32 * MiB;

    /// <summary>
    /// Maximum compressed archive size buffered to a delete-on-close temporary file when a
    /// connector supplies a non-seekable stream.
    /// </summary>
    public long MaxZipBufferedContainerBytes { get; set; } = 512 * MiB;

    /// <summary>
    /// Maximum declared uncompressed size of a single ZIP entry.
    /// </summary>
    public long MaxZipEntryBytes { get; set; } = 256 * MiB;

    /// <summary>
    /// Maximum cumulative declared uncompressed size inspected in one ZIP archive.
    /// </summary>
    public long MaxZipExpandedBytes { get; set; } = 512 * MiB;

    /// <summary>
    /// Maximum allowed uncompressed-to-compressed ratio for an entry.
    /// </summary>
    public double MaxZipCompressionRatio { get; set; } = 200;

    public ScanDiagnostics? Diagnostics { get; set; }
}
