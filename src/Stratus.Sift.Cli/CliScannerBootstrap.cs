using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;
using Stratus.Sift.Scanner.Models;

namespace Stratus.Sift.Cli;

internal sealed class CliScannerSession : IAsyncDisposable
{
    public CliScannerSession(
        IHost host,
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        List<IgnoreRule> ignoreRules,
        string ruleFingerprint)
    {
        Host = host;
        Optimizer = optimizer;
        PolicyMap = policyMap;
        IgnoreRules = ignoreRules;
        Plan = ScannerExecutionPlan.Create(optimizer, policyMap, ignoreRules);
        RuleFingerprint = ruleFingerprint;
    }

    public IHost Host { get; }
    public ClassifierOptimizer Optimizer { get; }
    public Dictionary<Guid, List<Policy>> PolicyMap { get; }
    public List<IgnoreRule> IgnoreRules { get; }
    public ScannerExecutionPlan Plan { get; }
    public string RuleFingerprint { get; }

    public async ValueTask DisposeAsync()
    {
        if (Host is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
            return;
        }

        Host.Dispose();
    }
}

internal static class CliScannerBootstrap
{
    internal static async Task<CliScannerSession> InitializeScannerAsync(
        string? rulesPath,
        Func<IHost> hostFactory,
        CancellationToken cancellationToken = default)
    {
        var host = hostFactory();

        try
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var catalog = await CliRuleCatalogLoader.LoadAsync(rulesPath, logger, cancellationToken);
            var classifiers = ClassifierRuntimeValidator
                .FilterValidClassifiers(catalog.Classifiers, logger)
                .Where(classifier => classifier.IsEnabled)
                .ToList();
            var policies = catalog.Policies;
            var ignoreRules = catalog.IgnoreRules;

            var optimizer = new ClassifierOptimizer();
            optimizer.LoadClassifiers(classifiers);

            return new CliScannerSession(
                host,
                optimizer,
                BuildPolicyMap(policies),
                ignoreRules,
                CliResumeIdentity.CreateRuleFingerprint(rulesPath));
        }
        catch
        {
            if (host is IAsyncDisposable asyncDisposable)
            {
                await asyncDisposable.DisposeAsync();
            }
            else
            {
                host.Dispose();
            }

            throw;
        }
    }

    internal static Dictionary<Guid, List<Policy>> BuildPolicyMap(IEnumerable<Policy> policies)
    {
        var policyMap = new Dictionary<Guid, List<Policy>>();
        foreach (var policy in policies)
        {
            if (!policy.Active || policy.PolicyClassifiers == null)
            {
                continue;
            }

            foreach (var policyClassifier in policy.PolicyClassifiers)
            {
                if (!policyMap.TryGetValue(policyClassifier.ClassifierId, out var classifierPolicies))
                {
                    classifierPolicies = [];
                    policyMap[policyClassifier.ClassifierId] = classifierPolicies;
                }

                classifierPolicies.Add(policy);
            }
        }

        return policyMap;
    }
}
