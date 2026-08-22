using System.IO;

namespace Stratus.Sift.Connectors.Interfaces;

public interface IRemoteFile
{
    string Id { get; }
    string Name { get; }
    string Path { get; }
    string WebUrl { get; }
    long? Size { get; }
    string? ContentType { get; }
    bool IsDeleted { get; }
    bool IsDirectory { get; }

    // Link/External file handling
    bool IsLink { get; }
    bool IsExternal { get; }

    Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default);
    Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default);
}
