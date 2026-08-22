using System.Text.Json.Serialization;

namespace Stratus.Sift.Core.Enums;

/// <summary>
/// Defines which part of the file system entry to apply the patterns against.
/// This allows the RuleOptimizer to sort rules into "Fast" (Metadata) and "Slow" (Content) buckets.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<RuleTarget>))]
public enum RuleTarget
{
    /// <summary>
    /// Scans the file content (body).
    /// Cost: High (Requires File I/O + Regex).
    /// </summary>
    Content = 0,

    /// <summary>
    /// Matches the full filename (e.g., "id_rsa", "config.json").
    /// Cost: Very Low (HashSet Lookup).
    /// </summary>
    FileName = 1,

    /// <summary>
    /// Matches the file extension (e.g., ".log", ".mp4").
    /// Cost: Very Low (HashSet Lookup).
    /// </summary>
    FileExtension = 2,

    /// <summary>
    /// Matches the exact folder name (e.g., "node_modules", ".git").
    /// Cost: Very Low (HashSet Lookup).
    /// </summary>
    DirectoryName = 3,

    /// <summary>
    /// Matches the start of the full path (e.g., "C:\Windows", "/mnt/backup").
    /// Cost: Low (String StartsWith).
    /// </summary>
    DirectoryPath = 4,

    /// <summary>
    /// Matches the share name in a UNC path (e.g., "IPC$", "C$").
    /// Cost: Low (String Parsing).
    /// </summary>
    ShareName = 5
}
