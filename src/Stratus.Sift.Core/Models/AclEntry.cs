namespace Stratus.Sift.Core.Models;

public sealed class AclEntry
{
    public string Identity { get; set; } = string.Empty;
    public string Permissions { get; set; } = string.Empty;
    public string AccessControlType { get; set; } = string.Empty;
    public bool IsInherited { get; set; }
}
