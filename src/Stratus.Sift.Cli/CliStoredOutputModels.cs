using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Cli;

internal static class CliStoredOutputVersions
{
    internal const string V1 = "1.0";
    internal const string Current = V1;
}

internal sealed class CliJsonOutputDocument
{
    public string SchemaVersion { get; set; } = CliStoredOutputVersions.Current;
    public string Title { get; set; } = string.Empty;
    public string SummaryTitle { get; set; } = string.Empty;
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset GeneratedAtUtc { get; set; }
    public TimeSpan Elapsed { get; set; }
    public long FilesDiscovered { get; set; }
    public long FilesScanned { get; set; }
    public long Findings { get; set; }
    public long Errors { get; set; }
    public List<CliOutputEventRecord> Events { get; set; } = [];
    public List<CliOutputFindingRecord> FindingsList { get; set; } = [];
}

internal sealed class CliOutputEventRecord
{
    public string Kind { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public DateTimeOffset TimestampUtc { get; set; }
}

internal sealed class CliOutputFindingRecord
{
    public string RuleName { get; set; } = string.Empty;
    public string ClassifierName { get; set; } = string.Empty;
    public string ResourcePath { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string ConfidenceLevel { get; set; } = string.Empty;
    public string Exposure { get; set; } = string.Empty;
    public string Owner { get; set; } = string.Empty;
    public bool IsMetadata { get; set; }
    public string? Evidence { get; set; }
    public string RedactedValue { get; set; } = string.Empty;
    public string Snippet { get; set; } = string.Empty;
    public DateTime DetectedAtUtc { get; set; }
    public string? EvidenceJson { get; set; }
    public LlmValidationStatus? LlmValidationStatus { get; set; }
    public string? ValidationStatus { get; set; }
    public string? LlmValidationModel { get; set; }
    public string? LlmValidationReason { get; set; }
    public string? LlmValidationEvidenceSummary { get; set; }
    public bool? LlmIsSensitive { get; set; }
    public string? LlmSensitivityReason { get; set; }
    public DateTime? LlmValidatedAtUtc { get; set; }
}
