using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Core.Validation;

public sealed class LlmValidationResult
{
    public static LlmValidationResult Skipped(string reason, string promptVersion) => new()
    {
        Status = LlmValidationStatus.Skipped,
        Reason = reason,
        PromptVersion = promptVersion
    };

    public static LlmValidationResult Error(string reason, string promptVersion, string? model = null) => new()
    {
        Status = LlmValidationStatus.Error,
        Reason = reason,
        PromptVersion = promptVersion,
        Model = model ?? string.Empty
    };

    public LlmValidationStatus Status { get; set; } = LlmValidationStatus.Skipped;
    public string Model { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public string EvidenceSummary { get; set; } = string.Empty;
    public bool? IsSensitive { get; set; }
    public string SensitivityReason { get; set; } = string.Empty;
    public string PromptVersion { get; set; } = string.Empty;
    public string RawResponse { get; set; } = string.Empty;
    public DateTime ValidatedAtUtc { get; set; } = DateTime.UtcNow;
    public bool IsMatch => Status == LlmValidationStatus.Accepted;
}
