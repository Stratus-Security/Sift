using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli;

internal sealed class CliScannerSession : IAsyncDisposable
{
    public CliScannerSession(
        IHost host,
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        List<IgnoreRule> ignoreRules)
    {
        Host = host;
        Optimizer = optimizer;
        PolicyMap = policyMap;
        IgnoreRules = ignoreRules;
    }

    public IHost Host { get; }
    public ClassifierOptimizer Optimizer { get; }
    public Dictionary<Guid, List<Policy>> PolicyMap { get; }
    public List<IgnoreRule> IgnoreRules { get; }

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
            var classifiers = catalog.Classifiers;
            var policies = catalog.Policies;
            var ignoreRules = catalog.IgnoreRules;

            var optimizer = new ClassifierOptimizer();
            optimizer.LoadClassifiers(classifiers);

            return new CliScannerSession(host, optimizer, BuildPolicyMap(policies), ignoreRules);
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

    private static Dictionary<Guid, List<Policy>> BuildPolicyMap(IEnumerable<Policy> policies)
    {
        var policyMap = new Dictionary<Guid, List<Policy>>();
        foreach (var policy in policies)
        {
            if (policy.PolicyClassifiers == null)
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
