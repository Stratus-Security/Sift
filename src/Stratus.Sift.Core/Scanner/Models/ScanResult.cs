using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Scanner.Models;

public class ScanResult
{
    public IEnumerable<ScanFinding> Issues { get; set; } = Enumerable.Empty<ScanFinding>();
    
    /// <summary>
    /// List of unique classifier names found in the file, regardless of policy actions.
    /// </summary>
    public HashSet<string> MatchedClassifiers { get; set; } = new();
}
