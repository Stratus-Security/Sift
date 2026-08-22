namespace Stratus.Sift.Core.Models;

public sealed class PolicyConfiguration
{
    public string Description { get; set; } = string.Empty;
    public List<string> IncludePaths { get; set; } = [];
    public List<string> ExcludePaths { get; set; } = [];
    public int MinMatchCount { get; set; } = 1;
    public string FindingCorrelationKey { get; set; } = string.Empty;

    public void EnsureMaterializedCollections()
    {
        IncludePaths ??= [];
        ExcludePaths ??= [];
    }
}
