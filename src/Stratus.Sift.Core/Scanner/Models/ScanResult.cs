using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Scanner.Models;

public class ScanResult
{
    private HashSet<string>? _matchedClassifiers;

    public IEnumerable<ScanFinding> Issues { get; set; } = Array.Empty<ScanFinding>();
    
    /// <summary>
    /// List of unique classifier names found in the file, regardless of policy actions.
    /// </summary>
    public HashSet<string> MatchedClassifiers
    {
        get => _matchedClassifiers ??= new HashSet<string>(StringComparer.Ordinal);
        set => _matchedClassifiers = value;
    }

    internal void AddMatchedClassifier(string name) =>
        (_matchedClassifiers ??= new HashSet<string>(StringComparer.Ordinal)).Add(name);

    internal IEnumerable<string> EnumerateMatchedClassifiers() =>
        _matchedClassifiers ?? Enumerable.Empty<string>();
}
