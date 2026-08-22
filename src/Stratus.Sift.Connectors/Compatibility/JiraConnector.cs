using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.Interfaces;

namespace Stratus.Sift.Connectors.Jira;

/// <summary>
/// Compatibility name for the connector that scans both Jira and Confluence.
/// </summary>
[Obsolete("Use Stratus.Sift.Connectors.Atlassian.AtlassianConnector instead.")]
public sealed class JiraConnector : IConnector
{
    private readonly Atlassian.AtlassianConnector _inner;

    public JiraConnector(HttpClient httpClient, ILogger<JiraConnector>? logger = null)
    {
        _inner = new Atlassian.AtlassianConnector(httpClient, logger);
    }

    public string ProviderName => _inner.ProviderName;

    public Task InitializeAsync(
        Dictionary<string, string> configuration,
        CancellationToken cancellationToken = default)
        => _inner.InitializeAsync(configuration, cancellationToken);

    public Task<IEnumerable<IRemoteDrive>> GetDrivesAsync(CancellationToken cancellationToken = default)
        => _inner.GetDrivesAsync(cancellationToken);
}
