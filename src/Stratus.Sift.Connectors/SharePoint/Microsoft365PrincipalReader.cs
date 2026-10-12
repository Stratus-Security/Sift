using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Microsoft.Graph;

namespace Stratus.Sift.Connectors.SharePoint;

internal static class Microsoft365PrincipalReader
{
    private static readonly ConditionalWeakTable<GraphServiceClient, ConcurrentDictionary<string, Lazy<Task<bool>>>> Caches = new();
    internal static void Reset(GraphServiceClient client) => Caches.Remove(client);

    internal static async Task<bool> IsGuestAsync(GraphServiceClient client, string kind, string id, CancellationToken cancellationToken)
    {
        var cache = Caches.GetValue(client, _ => new(StringComparer.Ordinal));
        var key = kind + ":" + id;
        if (!cache.TryGetValue(key, out var task))
        {
            task = new(() => ReadAsync(new Microsoft365GraphReader(client), kind, id, cancellationToken));
            if (cache.Count < 100_000) task = cache.GetOrAdd(key, task);
        }
        try { return await task.Value.WaitAsync(cancellationToken); }
        catch { cache.TryRemove(new KeyValuePair<string, Lazy<Task<bool>>>(key, task)); throw; }
    }

    private static async Task<bool> ReadAsync(Microsoft365GraphReader reader, string kind, string id, CancellationToken cancellationToken)
    {
        if (kind == "user")
        {
            using var user = await reader.GetAsync($"users/{Microsoft365GraphReader.Segment(id)}?$select=id,userType", cancellationToken);
            return Microsoft365GraphReader.String(user.RootElement, "userType") switch
            {
                "Guest" => true,
                "Member" => false,
                _ => throw new InvalidDataException("Directory principal had no userType.")
            };
        }
        var count = 0;
        var membership = kind == "groupOwners" ? "owners" : "transitiveMembers";
        await foreach (var member in reader.EnumerateAsync($"groups/{Microsoft365GraphReader.Segment(id)}/{membership}/microsoft.graph.user?$select=id,userType", cancellationToken))
        {
            if (++count > 100_000) throw new InvalidDataException("Sharing group membership exceeds its inspection limit.");
            var type = Microsoft365GraphReader.String(member, "userType");
            if (type == "Guest") return true;
            if (type != "Member") throw new InvalidDataException("Group member had no userType.");
        }
        return false;
    }
}
