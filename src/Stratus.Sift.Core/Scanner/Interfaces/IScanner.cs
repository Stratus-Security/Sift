using Stratus.Sift.Core.Models;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Scanner.Services;
using Stratus.Sift.Scanner.Models;
using System.Security.AccessControl;

namespace Stratus.Sift.Scanner.Interfaces;

public interface IScanner
{
    // Updated signature for stream scanning with Classifiers/Policies
    Task<ScanResult> ScanStreamAsync(Stream stream, string fileName, IEnumerable<Classifier> classifiers, IEnumerable<Policy> policies, IEnumerable<IgnoreRule>? ignoreRules = null, string exposure = "Unknown", string owner = "Unknown", List<AclEntry>? aclEntries = null, CancellationToken cancellationToken = default, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null);

    // Optimized signature for pre-built optimizer/policies
    Task<ScanResult> ScanStreamAsync(Stream stream, string fileName, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, IEnumerable<IgnoreRule>? ignoreRules = null, string exposure = "Unknown", string owner = "Unknown", List<AclEntry>? aclEntries = null, CancellationToken cancellationToken = default, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null);
}
