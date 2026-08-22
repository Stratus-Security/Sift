namespace Stratus.Sift.Core.Models;

public sealed class PolicyClassifier
{
    public Guid PolicyId { get; set; }
    public Policy Policy { get; set; } = null!;
    public Guid ClassifierId { get; set; }
    public Classifier Classifier { get; set; } = null!;
}
