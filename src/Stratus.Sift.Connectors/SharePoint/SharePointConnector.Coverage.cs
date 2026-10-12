using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Graph.Models;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using System.Security.Cryptography.X509Certificates;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

public partial class SharePointConnector
{
    private TokenCredential CreateCertificateCredential(IReadOnlyDictionary<string, string> config, string clientId, Uri authority)
    {
        var path = config["CertificatePath"];
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(path, config.GetValueOrDefault("CertificatePassword"),
            X509KeyStorageFlags.EphemeralKeySet);
        if (!certificate.HasPrivateKey) throw new ArgumentException("CertificatePath must contain a private key.");
        return new ClientCertificateCredential(_tenantId, clientId, certificate,
            new ClientCertificateCredentialOptions { AuthorityHost = authority });
    }

    private async Task<IReadOnlyCollection<Site>> ExpandSitesAsync(IEnumerable<Site> roots, CancellationToken ct)
    {
        var result = new List<Site>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var queue = new Queue<(Site Site, int Depth)>();
        foreach (var site in roots) if (site.Id != null && seen.Add(site.Id)) queue.Enqueue((site, 0));
        var reader = new Microsoft365GraphReader(_graphClient!);
        while (queue.TryDequeue(out var current))
        {
            ct.ThrowIfCancellationRequested();
            result.Add(current.Site);
            if (!_coverage.RecurseSubsites) continue;
            try
            {
                await foreach (var child in reader.EnumerateAsync($"sites/{Segment(current.Site.Id!)}/sites?$select=id,name,webUrl,displayName", ct))
                {
                    var id = Microsoft365GraphReader.Id(child);
                    if (seen.Contains(id)) continue;
                    if (current.Depth >= Microsoft365CoverageOptions.MaxSiteDepth || seen.Count >= Microsoft365CoverageOptions.MaxSites)
                        throw new InvalidDataException("Subsite traversal exceeded its site or depth limit.");
                    seen.Add(id);
                    queue.Enqueue((new Site
                    {
                        Id = id,
                        Name = String(child, "name"),
                        WebUrl = String(child, "webUrl"),
                        DisplayName = String(child, "displayName")
                    }, current.Depth + 1));
                }
            }
            catch (Exception ex) when (!(ex is OperationCanceledException && ct.IsCancellationRequested))
            { ReportSubsiteDiscoveryFailure(current.Site.WebUrl ?? current.Site.Id!, ex); }
        }
        return result;
    }

    private async Task<IReadOnlyCollection<SharePointRestClient.RestSite>> ExpandRestSitesAsync(
        IEnumerable<SharePointRestClient.RestSite> roots, CancellationToken ct)
    {
        var result = new List<SharePointRestClient.RestSite>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<(SharePointRestClient.RestSite Site, int Depth)>();
        foreach (var site in roots) if (seen.Add(site.Url.AbsoluteUri.TrimEnd('/'))) queue.Enqueue((site, 0));
        while (queue.TryDequeue(out var current))
        {
            ct.ThrowIfCancellationRequested();
            result.Add(current.Site);
            if (!_coverage.RecurseSubsites) continue;
            try
            {
                await foreach (var child in _sharePointRestClient!.EnumerateJsonAsync(
                    SharePointRestClient.Api(current.Site.Url, "web/webs?$select=Id,Title,Url&$top=200"), ct))
                {
                    var url = new Uri(String(child, "Url") ?? throw new InvalidDataException("Subsite has no URL."));
                    if (!url.Host.Equals(current.Site.Url.Host, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Subsite changed origin.");
                    if (seen.Contains(url.AbsoluteUri.TrimEnd('/'))) continue;
                    if (current.Depth >= Microsoft365CoverageOptions.MaxSiteDepth || seen.Count >= Microsoft365CoverageOptions.MaxSites)
                        throw new InvalidDataException("Subsite traversal exceeded its site or depth limit.");
                    seen.Add(url.AbsoluteUri.TrimEnd('/'));
                    queue.Enqueue((new(String(child, "Title") ?? url.AbsolutePath, url), current.Depth + 1));
                }
            }
            catch (Exception ex) when (!(ex is OperationCanceledException && ct.IsCancellationRequested))
            { ReportSubsiteDiscoveryFailure(current.Site.Url.AbsoluteUri, ex); }
        }
        return result;
    }

    private void ReportSubsiteDiscoveryFailure(string site, Exception exception)
    {
        if (Stratus.Sift.Connectors.Services.RemoteScanExceptionClassifier.IsExpectedForEnumeration(exception))
        {
            AddExpectedDiscoveryFailure("inaccessible subsite inventories");
            _logger?.LogDebug(exception, "Subsite discovery was unavailable for {SiteUrl}.", site);
            return;
        }
        var status = exception switch
        {
            HttpRequestException { StatusCode: { } code } => $"HTTP {(int)code}: ",
            Microsoft.Kiota.Abstractions.ApiException { ResponseStatusCode: > 0 } api => $"HTTP {api.ResponseStatusCode}: ",
            _ => ""
        };
        var reason = exception.Message.Replace('\r', ' ').Replace('\n', ' ');
        if (reason.Length > 768) reason = reason[..768] + "...";
        AddDiscoveryFailure($"Subsites could not be fully enumerated for {site}. {status}{reason}");
        _logger?.LogDebug(exception, "Subsite discovery failed for {SiteUrl}.", site);
    }

    private async Task AddPersonalDrivesAsync(List<IRemoteDrive> drives, CancellationToken ct)
    {
        if (!_coverage.DiscoverPersonalDrives || _graphClient == null) return;
        var reader = new Microsoft365GraphReader(_graphClient);
        async Task ReadDrive(string path)
        {
            try
            {
                using var json = await reader.GetAsync(path + "?$select=id,name,webUrl", ct);
                var item = json.RootElement;
                drives.Add(new SharePointDrive(_graphClient, new Drive
                {
                    Id = Microsoft365GraphReader.Id(item),
                    Name = String(item, "name"),
                    WebUrl = String(item, "webUrl")
                }, _tenantId, DatastoreType.OneDrive, _coverage));
            }
            catch (Microsoft.Kiota.Abstractions.ApiException ex) when (ex.ResponseStatusCode == 404) { /* Unprovisioned drive. */ }
            catch (Exception ex) when (!(ex is OperationCanceledException && ct.IsCancellationRequested))
            { AddDiscoveryFailure($"Personal drive discovery failed for {path}."); }
        }
        if (_useConfiguredTargets) await ReadDrive("me/drive");
        else
        {
            try
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                await foreach (var user in reader.EnumerateAsync("users?$select=id&$top=999", ct))
                {
                    var id = Microsoft365GraphReader.Id(user);
                    if (!seen.Add(id)) continue;
                    if (seen.Count > Microsoft365CoverageOptions.MaxSites) throw new InvalidDataException("Personal drive discovery exceeded its user limit.");
                    await ReadDrive($"users/{Segment(id)}/drive");
                }
            }
            catch (Exception ex) when (!(ex is OperationCanceledException && ct.IsCancellationRequested))
            { AddDiscoveryFailure("Personal drive reconciliation could not be completed; User.Read.All is required."); }
        }
    }
}
