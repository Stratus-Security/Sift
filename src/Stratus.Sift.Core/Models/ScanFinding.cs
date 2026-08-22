using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Core.Models;

/// <summary>A local scan result. Matched values remain visible for authorised testing.</summary>
public sealed class ScanFinding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string RuleName { get; set; } = string.Empty;
    public string PolicyName { get; set; } = string.Empty;
    public string ClassifierName { get; set; } = string.Empty;
    public string ResourcePath { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public double Confidence { get; set; } = 1;
    public ConfidenceLevel ConfidenceLevel { get; set; } = ConfidenceLevel.Medium;
    public string RedactedValue { get; set; } = string.Empty;
    public string ValueHash { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public int InstanceCount { get; set; } = 1;
    public bool IsReportOnly { get; set; }
    public string Exposure { get; set; } = "Unknown";
    public string Owner { get; set; } = "Unknown";
    public string Snippet { get; set; } = string.Empty;
    public List<AclEntry> AclEntries { get; set; } = [];
    public string EvidenceJson { get; set; } = string.Empty;
    public string LlmValidationCandidate { get; set; } = string.Empty;
    public string LlmValidationContext { get; set; } = string.Empty;
    public string LlmPromptVersion { get; set; } = string.Empty;
    public string LlmDeterministicValidator { get; set; } = string.Empty;
    public LlmValidationStatus? LlmValidationStatus { get; set; }
    public string LlmValidationModel { get; set; } = string.Empty;
    public string LlmValidationReason { get; set; } = string.Empty;
    public string LlmValidationEvidenceSummary { get; set; } = string.Empty;
    public bool? LlmIsSensitive { get; set; }
    public string LlmSensitivityReason { get; set; } = string.Empty;
    public DateTime? LlmValidatedAt { get; set; }
}
