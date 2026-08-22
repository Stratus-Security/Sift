using System.Text.Json;

namespace Stratus.Sift.Connectors.Slack;

public sealed record SlackExportFileReference(
    string Id,
    string Name,
    Uri DownloadUri,
    string? ContentType,
    long? Size);

public static class SlackExportInspector
{
    public static async Task<IReadOnlyList<SlackExportFileReference>> GetFileReferencesAsync(
        string inputPath,
        CancellationToken cancellationToken = default)
    {
        using var source = SlackExportSource.Open(inputPath);
        var references = new Dictionary<string, SlackExportFileReference>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in source.Entries.Where(path => path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var document = await source.ReadJsonAsync(entry, cancellationToken);
                CollectReferences(document.RootElement, references);
            }
            catch (JsonException)
            {
                // Non-JSON or truncated export entries are still scanned as raw metadata by the connector.
            }
        }

        return references.Values.OrderBy(reference => reference.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void CollectReferences(JsonElement element, IDictionary<string, SlackExportFileReference> references)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            if (TryCreateReference(element, out var reference)) references.TryAdd(reference.Id + "|" + reference.DownloadUri, reference);
            foreach (var property in element.EnumerateObject()) CollectReferences(property.Value, references);
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) CollectReferences(item, references);
        }
    }

    private static bool TryCreateReference(JsonElement element, out SlackExportFileReference reference)
    {
        reference = null!;
        var url = GetString(element, "url_private_download") ?? GetString(element, "url_private");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps
            || !(uri.Host.Equals("slack.com", StringComparison.OrdinalIgnoreCase)
                 || uri.Host.EndsWith(".slack.com", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        var id = GetScalar(element, "id") ?? Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(uri.AbsoluteUri)))[..24];
        var name = GetString(element, "name") ?? GetString(element, "title") ?? id;
        var contentType = GetString(element, "mimetype");
        long? size = element.TryGetProperty("size", out var sizeElement) && sizeElement.TryGetInt64(out var parsedSize) ? parsedSize : null;
        reference = new SlackExportFileReference(id, name, uri, contentType, size);
        return true;
    }

    private static string? GetString(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string? GetScalar(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) ? value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null
        } : null;
}
