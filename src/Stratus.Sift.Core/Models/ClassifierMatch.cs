using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Core.Models;

public sealed class ClassifierMatch
{
    public RuleTarget Target { get; set; } = RuleTarget.Content;
    public List<string> Patterns { get; set; } = [];
    public bool IsLiteral { get; set; }
    public bool CaseSensitive { get; set; }
    public List<string> Keywords { get; set; } = [];
    public string? ExtensionProfile { get; set; }
    public List<string> IncludedExtensions { get; set; } = [];
}
