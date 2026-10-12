using Microsoft.Kiota.Abstractions;
using System.Text.Json;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed partial class Microsoft365GraphWorkloadDrive
{
    private readonly Dictionary<string, List<(string Id, string Path)>> _referenceLibraries = new(StringComparer.OrdinalIgnoreCase);

    private async Task<JsonDocument> ResolveReference(Uri uri, string sharingId, CancellationToken ct)
    {
        if (!uri.IsDefaultPort || uri.UserInfo.Length != 0)
            throw new InvalidDataException("Attachment reference is not a standard SharePoint URL.");
        var path = Uri.UnescapeDataString(uri.AbsolutePath);
        if (path.Length > 6 && path[0] == '/' && path[1] == ':' && path[3] == ':' && path[4] == '/' && path[5] == 'r')
            path = path[6..];
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length > 64) throw new InvalidDataException("Attachment reference exceeded its path depth limit.");
        // The shares API documents write permissions even for resolving a URL.
        // Prefer site/library/path reads, so ordinary references work with read scopes.
        for (var depth = segments.Length - 1; depth >= 0; depth--)
        {
            var sitePath = string.Join("/", segments.Take(depth).Select(Segment));
            var siteRequest = "sites/" + Segment(uri.Host) + (depth == 0 ? "" : ":/" + sitePath);
            if (!_referenceLibraries.TryGetValue(siteRequest, out var libraries))
            {
                libraries = [];
                try
                {
                    using var site = await graph.GetAsync(siteRequest + "?$select=id", ct);
                    await foreach (var drive in graph.EnumerateAsync("sites/" + Segment(Id(site.RootElement)) + "/drives?$select=id,webUrl,system", ct))
                    {
                        if (libraries.Count >= MaxItems) throw new InvalidDataException("Reference library inventory exceeded MaxWorkloadItems.");
                        if (String(drive, "webUrl") is { } web && Uri.TryCreate(web, UriKind.Absolute, out var library)
                            && SameOrigin(library, uri))
                            libraries.Add((Id(drive), Uri.UnescapeDataString(library.AbsolutePath).TrimEnd('/') + "/"));
                    }
                }
                catch (ApiException ex) when (ex.ResponseStatusCode == 404) { }
                _referenceLibraries[siteRequest] = libraries;
                if (_referenceLibraries.Count > MaxItems) throw new InvalidDataException("Reference site inventory exceeded MaxWorkloadItems.");
            }
            var match = libraries.OrderByDescending(library => library.Path.Length)
                .FirstOrDefault(library => path.StartsWith(library.Path, StringComparison.OrdinalIgnoreCase));
            if (match.Id == null) continue;
            var relative = string.Join("/", path[match.Path.Length..].Split('/').Select(Segment));
            return await graph.GetAsync("drives/" + Segment(match.Id) + "/root:/" + relative, ct);
        }
        // Opaque sharing links cannot be mapped to a file path. If the caller's
        // existing grants cannot resolve one, report it incomplete without elevating.
        return await graph.GetAsync("shares/" + sharingId + "/driveItem", ct);
    }
}
