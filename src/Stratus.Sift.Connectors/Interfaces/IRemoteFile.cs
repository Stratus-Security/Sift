using System.IO;

namespace Stratus.Sift.Connectors.Interfaces;

public interface IRemoteFile
{
    string Id { get; }
    /// <summary>Distinguishes items reached through different backing drives during resume.</summary>
    string ResumeIdentity => Id;
    string Name { get; }
    /// <summary>Name describing the bytes supplied for scanning, when the service converts a file.</summary>
    string ContentName => Name;
    string Path { get; }
    string WebUrl { get; }
    long? Size { get; }
    /// <summary>An opaque server version used to distinguish same-size edits during resume.</summary>
    string? Version => null;
    /// <summary>False when the API can expose metadata but cannot supply the complete requested content.</summary>
    bool IsContentComplete => true;
    bool SampleLargeContent => true;
    string? ContentType { get; }
    bool IsDeleted { get; }
    bool IsDirectory { get; }

    // Link/External file handling
    bool IsLink { get; }
    bool IsExternal { get; }

    Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default);
    Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default);
}
