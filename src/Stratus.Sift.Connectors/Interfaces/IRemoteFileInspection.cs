using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Connectors.Interfaces;

public interface IRemoteFileInspection
{
    Task PrepareAsync(CancellationToken cancellationToken);
    string Exposure { get; }
    string Owner { get; }
    IReadOnlyList<AclEntry> AclEntries { get; }
}

public interface IRemoteFileSupplementProvider
{
    IAsyncEnumerable<IRemoteFile> GetSupplementalFilesAsync(CancellationToken cancellationToken);
}
