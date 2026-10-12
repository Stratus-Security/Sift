using Azure.Identity;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed record Microsoft365Cloud(Uri GraphRoot, Uri Authority)
{
    internal static Microsoft365Cloud Resolve(string? name) => name?.Trim().ToLowerInvariant() switch
    {
        null or "" or "worldwide" or "public" or "gcc" => new(new("https://graph.microsoft.com/v1.0"), AzureAuthorityHosts.AzurePublicCloud),
        "gcchigh" or "usgov" => new(new("https://graph.microsoft.us/v1.0"), AzureAuthorityHosts.AzureGovernment),
        "dod" => new(new("https://dod-graph.microsoft.us/v1.0"), AzureAuthorityHosts.AzureGovernment),
        "china" or "21vianet" => new(new("https://microsoftgraph.chinacloudapi.cn/v1.0"), AzureAuthorityHosts.AzureChina),
        _ => throw new ArgumentException("Cloud must be Worldwide, GccHigh, DoD, or China.")
    };

    internal static bool IsSharePointHost(string host)
        => new[] { ".sharepoint.com", ".sharepoint.us", ".sharepoint-mil.us", ".sharepoint.cn" }
            .Any(suffix => host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));
}
