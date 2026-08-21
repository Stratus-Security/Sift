namespace Stratus.Sift.Contracts;

public static class SiftContractVersions
{
    public const string V2 = "2.0";
}

public sealed record ContentScanRequest(
    string RequestId,
    IReadOnlyList<ContentScanTarget> Targets,
    ContentScanOptions Options);

public sealed record ContentScanTarget(
    string TargetId,
    ContentScanTargetKind Kind,
    string Location,
    IReadOnlyDictionary<string, string>? Settings = null);

public enum ContentScanTargetKind
{
    FileSystem,
    Smb,
}

public sealed record ContentScanOptions(
    bool IncludeBinaryContent = false,
    bool EnumerateOnly = false,
    bool FullScan = true,
    int? MaximumParallelism = null,
    long MaximumFileSizeBytes = 10 * 1024 * 1024);

public sealed record ContentObservation(
    string ObservationId,
    string RuleId,
    string RuleName,
    string ResourcePath,
    int? LineNumber,
    string Severity,
    string Confidence,
    string Value,
    string Snippet,
    DateTimeOffset DetectedAtUtc);

public sealed record ContentScanProgress(
    string RequestId,
    string Phase,
    long TargetsCompleted,
    long TargetsTotal,
    long ObjectsDiscovered,
    long ObjectsScanned,
    long Observations,
    long Errors,
    DateTimeOffset ReportedAtUtc);

public sealed record ContentScanSummary(
    string RequestId,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    long ObjectsDiscovered,
    long ObjectsScanned,
    long Observations,
    long Errors,
    bool Partial);
