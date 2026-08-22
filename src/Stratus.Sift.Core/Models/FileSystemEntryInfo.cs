using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Core.Models;

public readonly record struct FileSystemEntryInfo(
    string Path,
    string Name,
    string ParentPath,
    bool IsDirectory,
    long Size,
    DateTime Created,
    DateTime Modified,
    DateTime Accessed,
    FileAttributes Attributes,
    List<AclEntry>? AclEntries,
    string Owner,
    string Exposure,
    Guid? FileShareId = null,
    List<string>? Classifiers = null,
    Guid? SnapshotId = null,
    FileSystemObservationKind ObservationKind = FileSystemObservationKind.Upsert);
