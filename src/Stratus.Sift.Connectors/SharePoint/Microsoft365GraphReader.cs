using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Graph;
using Microsoft.Kiota.Abstractions;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class Microsoft365GraphReader(GraphServiceClient client)
{
    internal Uri Root { get; } = new((client.RequestAdapter.BaseUrl ?? "https://graph.microsoft.com/v1.0").TrimEnd('/') + "/");
    internal Uri Url(string path) => Uri.TryCreate(path, UriKind.Absolute, out var absolute)
        ? absolute : new(Root.AbsoluteUri + path.TrimStart('/'));
    internal Task<Stream?> ProjectContentAsync(string drive, string item, CancellationToken ct)
        => Microsoft365ContentProjection.Open(client, drive, item, ct);

    internal async Task<JsonDocument> GetAsync(string path, CancellationToken cancellationToken)
    {
        using var stream = await OpenAsync(Url(path), cancellationToken);
        return await ReadJsonAsync(stream, cancellationToken);
    }

    internal async Task<string> GetTextAsync(string path, CancellationToken cancellationToken)
    {
        using var stream = await OpenAsync(Url(path), cancellationToken);
        return new UTF8Encoding(false, true).GetString(await ReadBytesAsync(stream, cancellationToken));
    }

    internal async Task<JsonDocument> PostAsync(string path, string json, CancellationToken cancellationToken)
    {
        using var body = new MemoryStream(Encoding.UTF8.GetBytes(json));
        var request = new RequestInformation { HttpMethod = Method.POST, URI = Url(path), Content = body };
        request.Headers.Add("Content-Type", "application/json");
        using var stream = await client.RequestAdapter.SendPrimitiveAsync<Stream>(request, cancellationToken: cancellationToken)
            ?? throw new InvalidDataException("Graph response was empty.");
        return await ReadJsonAsync(stream, cancellationToken);
    }

    internal async Task<Stream> OpenAsync(Uri uri, CancellationToken cancellationToken, string? range = null, bool eventualConsistency = false)
    {
        if (uri.Scheme != Root.Scheme || !uri.Host.Equals(Root.Host, StringComparison.OrdinalIgnoreCase) || uri.Port != Root.Port || uri.UserInfo.Length > 0)
            throw new InvalidDataException("Graph continuation or content URL changed service origin.");
        var request = new RequestInformation { HttpMethod = Method.GET, URI = uri };
        if (range != null) request.Headers.Add("Range", range);
        if (eventualConsistency) request.Headers.Add("ConsistencyLevel", "eventual");
        return await client.RequestAdapter.SendPrimitiveAsync<Stream>(request, cancellationToken: cancellationToken)
            ?? throw new InvalidDataException("Graph response was empty.");
    }

    internal async IAsyncEnumerable<JsonElement> EnumerateAsync(string path,
        [EnumeratorCancellation] CancellationToken cancellationToken, bool eventualConsistency = false)
    {
        var next = Url(path);
        var collectionPath = CollectionPath(next);
        var visited = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            if (visited.Count >= Microsoft365CoverageOptions.MaxPages || !visited.Add(next.AbsoluteUri))
                throw new InvalidDataException("Graph collection exceeded its page limit or repeated a continuation link.");
            using var stream = await OpenAsync(next, cancellationToken, eventualConsistency: eventualConsistency);
            using var document = await ReadJsonAsync(stream, cancellationToken);
            if (!document.RootElement.TryGetProperty("value", out var values) || values.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Graph collection response did not contain an array.");
            foreach (var value in values.EnumerateArray()) yield return value.Clone();
            var link = String(document.RootElement, "@odata.nextLink");
            if (string.IsNullOrWhiteSpace(link)) yield break;
            next = new Uri(next, link);
            if (!CollectionPath(next).Equals(collectionPath, StringComparison.Ordinal))
                throw new InvalidDataException("Graph collection continuation changed its resource path.");
        }
    }

    internal static string CollectionPath(Uri uri)
    {
        // Graph can return OData key syntax for a collection requested with slash
        // syntax. Decode after splitting so an escaped slash remains part of an ID.
        return string.Join("/", uri.AbsolutePath.Split('/').Select(segment =>
        {
            var decoded = Uri.UnescapeDataString(segment);
            var key = System.Text.RegularExpressions.Regex.Match(decoded, @"^([A-Za-z][A-Za-z0-9.]*)\('((?:[^']|'')+)'\)$",
                System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(2));
            return key.Success ? key.Groups[1].Value + "/" + Segment(key.Groups[2].Value.Replace("''", "'"))
                : Segment(decoded);
        }));
    }

    private static async Task<JsonDocument> ReadJsonAsync(Stream source, CancellationToken cancellationToken)
        => JsonDocument.Parse(await ReadBytesAsync(source, cancellationToken), new JsonDocumentOptions { MaxDepth = 128 });

    internal static async Task<byte[]> ReadBytesAsync(Stream source, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[64 * 1024];
        int read;
        while ((read = await source.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > 64 * 1024 * 1024) throw new InvalidDataException("Graph JSON response exceeds its size limit.");
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    internal static string? String(JsonElement value, string key)
        => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var property)
            ? property.ValueKind == JsonValueKind.String ? property.GetString()
                : property.ValueKind == JsonValueKind.Number ? property.GetRawText() : null : null;
    internal static string Id(JsonElement value) => String(value, "id")
        ?? throw new InvalidDataException("Graph item has no ID.");
    internal static string Segment(string value) => Uri.EscapeDataString(value);

    internal static string SearchableText(JsonElement value)
    {
        var text = new StringBuilder();
        void Append(string content)
        {
            if (text.Length + content.Length + 1 > 64 * 1024 * 1024)
                throw new InvalidDataException("Structured content exceeded the text limit.");
            text.AppendLine(content);
        }
        void Visit(JsonElement node)
        {
            switch (node.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in node.EnumerateObject()) { Append(property.Name); Visit(property.Value); }
                    break;
                case JsonValueKind.Array:
                    foreach (var child in node.EnumerateArray()) Visit(child);
                    break;
                case JsonValueKind.String:
                    var decoded = node.GetString() ?? "";
                    Append(decoded);
                    if (decoded.Contains('<') || decoded.Contains('&'))
                        Append(System.Net.WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Replace(decoded,
                            "<[^>]*>", "", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(2))));
                    break;
                default: Append(node.GetRawText()); break;
            }
        }
        Visit(value);
        return text.ToString();
    }
}
