using System.Text;
using Microsoft.Graph;
using Microsoft.Kiota.Abstractions;
using Stratus.Sift.Connectors.Services;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal static class Microsoft365ContentProjection
{
    internal static bool Supports(string name) => Path.GetExtension(name).ToLowerInvariant() is ".loop" or ".fluid" or ".whiteboard" or ".wbtx";
    internal const string VersionSuffix = ":projection:html:v1";

    internal static async Task<Stream?> Open(GraphServiceClient? client, string drive, string item, CancellationToken ct, string? version = null)
    {
        if (client == null) throw Unavailable("Graph access is needed to convert this file.");
        try
        {
            var reader = new Microsoft365GraphReader(client);
            var path = "drives/" + Segment(drive) + "/items/" + Segment(item);
            if (version != null) path += "/versions/" + Segment(version);
            var html = await reader.GetTextAsync(path + "/content?format=html", ct);
            // Preserve attributes/raw markup as well as readable text. Do not crawl
            // embedded links: conversion cannot create a second traversal tree.
            var text = html + "\n" + Microsoft365GraphWorkloadDrive.HtmlText(html);
            var bytes = Encoding.UTF8.GetBytes(text);
            if (bytes.Length > 64 * 1024 * 1024) throw Unavailable("Converted content exceeded its text limit.");
            return new MemoryStream(bytes, writable: false);
        }
        catch (ApiException ex) when (ex.ResponseStatusCode is 400 or 401 or 403 or 404 or 406 or 415 or 422 or 501)
        { throw Unavailable("The service could not convert this file using the current access.", ex.ResponseStatusCode, ex); }
        catch (DecoderFallbackException ex)
        { throw Unavailable("Converted content could not be decoded.", inner: ex); }
        catch (InvalidDataException ex) when (ex.Message == "Graph JSON response exceeds its size limit.")
        { throw Unavailable("Converted content exceeded its text limit.", inner: ex); }
    }

    internal static RemoteContentUnavailableException Unavailable(string message, int? status = null, Exception? inner = null)
        => new(message, shouldRetry: false, isExpected: true, statusCode: status, innerException: inner);

    internal static async Task<(string Drive, string Item)> ResolveNativeFile(GraphServiceClient client, Uri siteUrl, string relative, CancellationToken ct)
    {
        var graph = new Microsoft365GraphReader(client);
        var sitePath = string.Join("/", Uri.UnescapeDataString(siteUrl.AbsolutePath).Trim('/').Split('/').Select(Segment));
        using var site = await graph.GetAsync("sites/" + Segment(siteUrl.Host) + (sitePath.Length == 0 ? "" : ":/" + sitePath) + "?$select=id", ct);
        (string Id, string Path) match = default;
        await foreach (var library in graph.EnumerateAsync("sites/" + Segment(Id(site.RootElement)) + "/drives?$select=id,webUrl,system", ct))
        {
            if (String(library, "webUrl") is not { } web || !Uri.TryCreate(web, UriKind.Absolute, out var uri)
                || !Microsoft365GraphWorkloadDrive.SameOrigin(uri, siteUrl)) continue;
            var path = Uri.UnescapeDataString(uri.AbsolutePath).TrimEnd('/') + "/";
            if (relative.StartsWith(path, StringComparison.OrdinalIgnoreCase) && (match.Path == null || path.Length > match.Path.Length))
                match = (Id(library), path);
        }
        if (match.Id == null || match.Path == null) throw Unavailable("The backing drive for conversion could not be resolved.");
        var filePath = string.Join("/", relative[match.Path.Length..].Split('/').Select(Segment));
        using var file = await graph.GetAsync("drives/" + Segment(match.Id) + "/root:/" + filePath + "?$select=id,file", ct);
        if (!file.RootElement.TryGetProperty("file", out _)) throw Unavailable("The conversion target is not a file.");
        return (match.Id, Id(file.RootElement));
    }
}
