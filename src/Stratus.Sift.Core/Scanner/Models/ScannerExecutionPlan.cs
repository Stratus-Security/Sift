using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Scanner.Models;

/// <summary>
/// Immutable, reusable scanner state compiled once for a scan run.
/// </summary>
public sealed class ScannerExecutionPlan
{
    private ScannerExecutionPlan(
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        IReadOnlyList<IgnoreRule> ignoreRules)
    {
        Optimizer = optimizer;
        PolicyMap = policyMap
            .Select(pair => new KeyValuePair<Guid, List<Policy>>(
                pair.Key,
                pair.Value.Where(policy => policy.Active).ToList()))
            .Where(pair => pair.Value.Count > 0)
            .ToDictionary(pair => pair.Key, pair => pair.Value);
        IgnoreRules = ignoreRules;
        PolicyNameLookup = PolicyMap.Values
            .SelectMany(static policies => policies)
            .GroupBy(static policy => policy.Name, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.First(), StringComparer.Ordinal);
        HasPathScopedPolicies = PolicyMap.Values
            .SelectMany(static policies => policies)
            .Any(static policy => policy.Configuration is
            {
                IncludePaths.Count: > 0
            } or
            {
                ExcludePaths.Count: > 0
            });
    }

    public ClassifierOptimizer Optimizer { get; }

    public IReadOnlyList<IgnoreRule> IgnoreRules { get; }

    internal Dictionary<Guid, List<Policy>> PolicyMap { get; }

    internal Dictionary<string, Policy> PolicyNameLookup { get; }

    internal bool HasPathScopedPolicies { get; }

    public static ScannerExecutionPlan Create(
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        IEnumerable<IgnoreRule>? ignoreRules = null)
    {
        ArgumentNullException.ThrowIfNull(optimizer);
        ArgumentNullException.ThrowIfNull(policyMap);

        return new ScannerExecutionPlan(
            optimizer,
            policyMap,
            ignoreRules?.ToArray() ?? []);
    }
}
