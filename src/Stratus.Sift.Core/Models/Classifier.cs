namespace Stratus.Sift.Core.Models;

/// <summary>Describes a tenant-neutral detection rule.</summary>
public sealed class Classifier
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public bool IsEnabled { get; set; } = true;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Label { get; set; } = string.Empty;
    public List<ClassifierMatch> Matches { get; set; } = [];
    public string? Validator { get; set; }
    public double EntropyThreshold { get; set; }
    public bool EnableLlmValidation { get; set; } = true;
    public List<Classifier> SubClassifiers { get; set; } = [];
    public ICollection<PolicyClassifier> PolicyClassifiers { get; set; } = [];
}
