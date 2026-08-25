using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Core.Models;

/// <summary>A self-contained Sift detection and reporting rule.</summary>
public sealed class SiftingRule
{
    public bool Enabled { get; set; } = true;
    public bool ReportFinding { get; set; } = true;
    public string Name { get; set; } = string.Empty;
    public string? FindingName { get; set; }
    public string? Description { get; set; }
    public string Label { get; set; } = "Custom";
    public Severity? Severity { get; set; }
    public List<ClassifierMatch> Matches { get; set; } = [];
    public string? Validator { get; set; }
    public double EntropyThreshold { get; set; }
    public bool EnableLlmValidation { get; set; } = true;
    public int MinMatchCount { get; set; } = 1;
    public List<string> IncludePaths { get; set; } = [];
    public List<string> ExcludePaths { get; set; } = [];
    public bool StopOnMatch { get; set; }
    public List<SiftingRule> SubRules { get; set; } = [];
}
