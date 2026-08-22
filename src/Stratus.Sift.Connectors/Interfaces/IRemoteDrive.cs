using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Connectors.Interfaces;

public interface IRemoteDrive
{
    string Id { get; }
    string Name { get; }
    string ConnectionId { get; }
    string WebUrl { get; }
    DatastoreType DriveType { get; }
    long? TotalSize { get; }
    long? UsedSize { get; }

    Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(string? deltaToken, CancellationToken cancellationToken = default);

    async Task<string> ProcessChangesAsync(
        string? deltaToken,
        Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint = null,
        CancellationToken cancellationToken = default)
    {
        var (changes, newDeltaToken) = await GetChangesAsync(deltaToken, cancellationToken);
        foreach (var change in changes)
        {
            await onChange(change);
        }

        return newDeltaToken;
    }
}
