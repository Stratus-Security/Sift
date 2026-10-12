namespace Stratus.Sift.Connectors.Interfaces;

/// <summary>Resolves shortcuts and enumerates their target hierarchy using stable item identities.</summary>
public interface IRemoteFileTraversal
{
    string TraversalIdentity { get; }
    Task<IRemoteFile?> ResolveLinkAsync(bool includeExternal, CancellationToken cancellationToken = default);
    IAsyncEnumerable<IRemoteFile> GetChildrenAsync(CancellationToken cancellationToken = default);
}
