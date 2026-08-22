namespace Stratus.Sift.Core.Validation;

public interface ILlmClassifierValidator
{
    Task<IReadOnlyList<string>> ListModelsAsync(CancellationToken cancellationToken = default);
    Task<LlmValidationResult> ValidateAsync(LlmValidationRequest request, CancellationToken cancellationToken = default);
}
