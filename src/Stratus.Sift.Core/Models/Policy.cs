using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Core.Models;

/// <summary>Maps one or more classifiers to standalone scan behaviour.</summary>
public sealed class Policy
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Active { get; set; } = true;
    public bool IsReportOnly { get; set; }
    public PolicyDomain Domain { get; set; } = PolicyDomain.Data;
    public List<string> Frameworks { get; set; } = [];
    public PolicyConfiguration Configuration { get; set; } = new();
    public Severity Severity { get; set; } = Severity.Medium;
    public bool StopOnMatch { get; set; }
    public ICollection<PolicyClassifier> PolicyClassifiers { get; set; } = [];
    public List<string> ClassifierNames { get; set; } = [];
}
