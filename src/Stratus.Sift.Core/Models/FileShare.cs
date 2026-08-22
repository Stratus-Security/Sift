using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Core.Models;

/// <summary>Portable cached remote-drive descriptor used by connector resume state.</summary>
public sealed class FileShare
{
    public string Path { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? WebUrl { get; set; }
    public long TotalSizeBytes { get; set; }
    public DatastoreType Type { get; set; }
}
