using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Core.Models;

public sealed class IgnoreRule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Pattern { get; set; } = string.Empty;
    public RuleTarget MatchTarget { get; set; } = RuleTarget.FileName;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
}
