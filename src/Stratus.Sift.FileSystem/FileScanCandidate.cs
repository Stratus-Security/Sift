namespace Stratus.Sift.FileSystem;

/// <summary>
/// Minimal filesystem metadata needed by the scanning pipeline.
/// </summary>
public readonly record struct FileScanCandidate(
    string Path,
    string Name,
    bool IsDirectory,
    long Size,
    DateTime Modified);
