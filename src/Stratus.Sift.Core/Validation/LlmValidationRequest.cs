namespace Stratus.Sift.Core.Validation;

public sealed class LlmValidationRequest
{
    public Guid? ClassifierId { get; set; }
    public string ClassifierName { get; set; } = string.Empty;
    public string ClassifierLabel { get; set; } = string.Empty;
    public string ClassifierDescription { get; set; } = string.Empty;
    public string Candidate { get; set; } = string.Empty;
    public string Snippet { get; set; } = string.Empty;
    public string Context { get; set; } = string.Empty;
    public string ResourcePath { get; set; } = string.Empty;
    public string Extension { get; set; } = string.Empty;
    public string DeterministicValidatorName { get; set; } = string.Empty;
    public double? DeterministicConfidence { get; set; }
    public string PromptVersion { get; set; } = OllamaLlmClassifierValidator.PromptVersion;
    public string ValueHash { get; set; } = string.Empty;
    public string SnippetHash { get; set; } = string.Empty;
}
