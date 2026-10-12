namespace Stratus.Sift.Scanner.Models;

public sealed record ContentExtractionResult(string Text, bool IsComplete, string? Error = null)
{
    internal Exception? FailureException { get; init; }
    internal bool HasUnexpectedFailure { get; init; }
}
