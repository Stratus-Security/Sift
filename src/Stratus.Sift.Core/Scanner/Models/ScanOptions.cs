namespace Stratus.Sift.Scanner.Models;

public class ScanOptions
{
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

    public long MaxDiskReadBytesPerSecond { get; set; } = 10 * 1024 * 1024;
}
