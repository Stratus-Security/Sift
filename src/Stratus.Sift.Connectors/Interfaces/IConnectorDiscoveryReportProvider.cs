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
    public bool IsComplete { get; init; } = true;
    /// <summary>Expected coverage limitations, displayed together without per-source warnings.</summary>
    public IReadOnlyList<string> CoverageNotes { get; init; } = [];

    public static ConnectorDiscoveryReport Empty { get; } = new(
        "unknown",
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase),
        []);
}
