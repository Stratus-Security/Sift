using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Core.Defaults;

public static class PolicyDefaultResourceConventions
{
    public static PolicyDomain? InferPolicyDomainFromResourceName(string resourceName)
    {
        if (string.IsNullOrWhiteSpace(resourceName))
        {
            return null;
        }

        return resourceName switch
        {
            _ when resourceName.Contains(".Defaults.Data.Policies.", StringComparison.OrdinalIgnoreCase) => PolicyDomain.Data,
            _ => null,
        };
    }

    public static void ApplyPolicyDefaultsFromResourceName(Policy policy, string resourceName)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var inferredDomain = InferPolicyDomainFromResourceName(resourceName);
        if (inferredDomain.HasValue)
        {
            policy.Domain = inferredDomain.Value;
        }
    }
}
