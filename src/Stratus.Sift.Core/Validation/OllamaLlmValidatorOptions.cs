namespace Stratus.Sift.Core.Validation;

public sealed class OllamaLlmValidatorOptions
{
    public string BaseUrl { get; set; } = "http://localhost:11434";
    public string Model { get; set; } = string.Empty;
    public int TimeoutSeconds { get; set; } = 20;
    public int MaxCandidateLength { get; set; } = 512;
    public int MaxSnippetLength { get; set; } = 1200;
    public int MaxContextLength { get; set; } = 1800;
    public int MaxConcurrentRequests { get; set; } = 2;
}
