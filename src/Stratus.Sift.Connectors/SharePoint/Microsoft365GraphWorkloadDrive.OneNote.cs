using System.Text.RegularExpressions;
using Stratus.Sift.Connectors.Interfaces;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed partial class Microsoft365GraphWorkloadDrive
{
    private async Task ReadOneNote(Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        if (appOnly) throw new InvalidDataException("Microsoft retired OneNote app-only API authentication in March 2025. Use delegated Notes.Read.All; stored .one/.onepkg files remain covered separately.");
        if (graph.Root.Host != "graph.microsoft.com") throw new InvalidDataException("OneNote service APIs are not available in this Microsoft cloud.");
        async Task Pages(string scope)
        {
            if (!_roots.Add("onenote:" + scope)) return;
            await foreach (var page in graph.EnumerateAsync(scope + "/onenote/pages?$top=100", ct))
            {
                var id = Id(page);
                await Attempt(scope + "/onenote/pages/" + id, async () =>
                {
                    var path = scope + "/onenote/pages/" + Segment(id) + "/content";
                    var html = await graph.GetTextAsync(path, ct);
                    var url = page.TryGetProperty("links", out var links) && links.TryGetProperty("oneNoteWebUrl", out var web)
                        ? String(web, "href") : null;
                    await Emit(Microsoft365ContentFile.Text("onenote:" + scope + ":" + id, (String(page, "title") ?? id) + ".page.json",
                        url ?? Link(WebUrl, id), SearchableText(page) + "\n" + html + "\n" + HtmlText(html)), emit, ct);
                    foreach (var resource in HtmlResources(html))
                        await Attempt(resource.Url, async () =>
                        {
                            if (!Uri.TryCreate(graph.Url(path), System.Net.WebUtility.HtmlDecode(resource.Url), out var uri)
                                || !SameOrigin(uri, graph.Root) || !uri.AbsolutePath.Contains("/onenote/resources/", StringComparison.OrdinalIgnoreCase))
                                throw new InvalidDataException("OneNote embedded resource changed service origin or is not a resource content URL.");
                            await Emit(new Microsoft365ContentFile("onenote:resource:" + uri.AbsoluteUri, resource.Name,
                                url ?? Link(WebUrl, id), String(page, "lastModifiedDateTime"), null,
                                async (_, token) => await graph.OpenAsync(uri, token)), emit, ct);
                        }, ct);
                }, ct);
            }
        }
        await Users(Pages, ct);
        await Attempt("OneNote group discovery", () => Groups(group => Pages("groups/" + Segment(group)), ct), ct);
        foreach (var site in options.OneNoteSites) await Attempt("OneNote site " + site, () => Pages("sites/" + Segment(site)), ct);
    }
    internal static bool SameOrigin(Uri uri, Uri root) => uri.Scheme == root.Scheme && uri.Host.Equals(root.Host, StringComparison.OrdinalIgnoreCase) && uri.Port == root.Port;
    internal static string HtmlText(string html) => System.Net.WebUtility.HtmlDecode(Regex.Replace(html, "<[^>]*>", " ", RegexOptions.None, TimeSpan.FromSeconds(2)));
    internal static IEnumerable<(string Url, string Name)> HtmlResources(string html)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match tag in Regex.Matches(html, "<(img|object)\\b[^>]*>", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)))
        {
            var attrs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match attr in Regex.Matches(tag.Value, "([\\w-]+)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')", RegexOptions.None, TimeSpan.FromSeconds(2)))
                attrs[attr.Groups[1].Value] = System.Net.WebUtility.HtmlDecode(attr.Groups[2].Success ? attr.Groups[2].Value : attr.Groups[3].Value);
            var url = attrs.GetValueOrDefault("data-fullres-src") ?? attrs.GetValueOrDefault(tag.Groups[1].Value.Equals("object", StringComparison.OrdinalIgnoreCase) ? "data" : "src");
            if (url == null || !seen.Add(url)) continue;
            var name = attrs.GetValueOrDefault("data-attachment") ?? "image" + Extension(attrs.GetValueOrDefault("type") ?? attrs.GetValueOrDefault("data-fullres-src-type"));
            yield return (url, name);
        }
    }
    internal static string Extension(string? mime) => mime?.ToLowerInvariant() switch
    {
        "image/jpeg" => ".jpg", "image/gif" => ".gif", "image/tiff" => ".tif", "application/pdf" => ".pdf", _ => ".png"
    };
}
