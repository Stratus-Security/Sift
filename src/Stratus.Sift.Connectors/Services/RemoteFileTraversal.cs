using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Connectors.Services;

internal sealed class RemoteFileTraversal(bool includeExternal, IReadOnlyList<IgnoreRule> ignoreRules)
{
    private const int MaximumDepth = 128;
    private const int MaximumLinks = 10_000;
    private readonly HashSet<(string Identity, string? Version)> _visitedLinks = [];
    private readonly HashSet<(string Identity, string? Version)> _visitedFiles = [];
    private readonly HashSet<string> _expandedFolders = new(StringComparer.Ordinal);

    internal bool HasFollowedLinks { get; private set; }

    internal void Reset()
    {
        _visitedLinks.Clear();
        _visitedFiles.Clear();
        _expandedFolders.Clear();
        HasFollowedLinks = false;
    }

    internal Task ProcessAsync(IRemoteFile item, Func<IRemoteFile, Task> onItem,
        Action<IRemoteFile, Exception> onFailure, CancellationToken cancellationToken)
        => VisitAsync(item, onItem, onFailure, expandFolder: false, depth: 0, cancellationToken);

    private async Task VisitAsync(IRemoteFile item, Func<IRemoteFile, Task> onItem,
        Action<IRemoteFile, Exception> onFailure, bool expandFolder, int depth, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (item.IsDeleted || IgnoreRuleEvaluator.ShouldIgnore(item.Path, ignoreRules))
        {
            await onItem(item);
            return;
        }
        if (item is not IRemoteFileTraversal hierarchy)
        {
            await EmitAsync(item, onItem, onFailure, cancellationToken);
            return;
        }

        if (item.IsLink)
        {
            var identity = (hierarchy.TraversalIdentity, item.Version);
            if (_visitedLinks.Contains(identity)) return;
            if (depth >= MaximumDepth)
            {
                onFailure(item, new InvalidDataException("Remote shortcut traversal exceeds its depth or link limit."));
                return;
            }
            IRemoteFile? target;
            try { target = await hierarchy.ResolveLinkAsync(includeExternal, cancellationToken); }
            catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
            {
                onFailure(item, ex);
                return;
            }
            if (target == null) return; // External targets intentionally excluded by scan options.
            _visitedLinks.Add(identity);
            if (_visitedLinks.Count > MaximumLinks)
            {
                onFailure(item, new InvalidDataException("Remote shortcut traversal exceeds its link limit."));
                return;
            }
            HasFollowedLinks = true;
            // The shortcut's version does not describe its target. Resume is checked on the target itself.
            await VisitAsync(target, onItem, onFailure, expandFolder: true, depth + 1, cancellationToken);
            return;
        }

        if (!item.IsDirectory)
        {
            var identity = (hierarchy.TraversalIdentity, item.Version);
            // Track linked targets only; ordinary delta files keep the pipeline's bounded memory usage.
            if (expandFolder ? _visitedFiles.Add(identity) : !_visitedFiles.Contains(identity))
            {
                await EmitAsync(item, onItem, onFailure, cancellationToken);
            }
            return;
        }

        if (!_expandedFolders.Add(hierarchy.TraversalIdentity)) return;
        await onItem(item);
        // The owning drive's delta already enumerates ordinary folders recursively.
        if (!expandFolder) return;
        if (depth >= MaximumDepth)
        {
            onFailure(item, new InvalidDataException("Remote shortcut folder traversal exceeds its depth limit."));
            return;
        }

        await using var children = hierarchy.GetChildrenAsync(cancellationToken).GetAsyncEnumerator(cancellationToken);
        while (true)
        {
            bool hasChild;
            try { hasChild = await children.MoveNextAsync(); }
            catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
            {
                onFailure(item, ex);
                return;
            }
            if (!hasChild) return;
            await VisitAsync(children.Current, onItem, onFailure, expandFolder: true, depth + 1, cancellationToken);
        }
    }

    private static async Task EmitAsync(IRemoteFile item, Func<IRemoteFile, Task> onItem,
        Action<IRemoteFile, Exception> onFailure, CancellationToken cancellationToken)
    {
        await onItem(item);
        if (item.IsDirectory || item.IsDeleted || item.IsLink || item is not IRemoteFileSupplementProvider supplements) return;
        await using var additional = supplements.GetSupplementalFilesAsync(cancellationToken).GetAsyncEnumerator(cancellationToken);
        while (true)
        {
            bool hasAdditional;
            try { hasAdditional = await additional.MoveNextAsync(); }
            catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
            { onFailure(item, ex); break; }
            if (!hasAdditional) break;
            await onItem(additional.Current);
        }
    }
}
