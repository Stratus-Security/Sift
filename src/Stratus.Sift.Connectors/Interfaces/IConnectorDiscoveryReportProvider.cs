namespace Stratus.Sift.Connectors.Interfaces;

public interface IConnectorDiscoveryReportProvider
{
    ConnectorDiscoveryReport DiscoveryReport { get; }
}

public sealed record ConnectorDiscoveryReport(
    string Coverage,
    IReadOnlyDictionary<string, int> SourceCounts,
    IReadOnlyList<string> Warnings)
{
    public static ConnectorDiscoveryReport Empty { get; } = new(
        "unknown",
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase),
        []);
}
