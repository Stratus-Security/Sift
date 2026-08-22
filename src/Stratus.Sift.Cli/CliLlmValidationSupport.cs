using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Core.Validation;

namespace Stratus.Sift.Cli;

internal static class CliLlmValidationSupport
{
    internal static async Task<ILlmClassifierValidator?> CreateValidatorAsync(
        IServiceProvider services,
        CliLlmOptions? options,
        CliProgressDisplay? display = null,
        CancellationToken cancellationToken = default)
    {
        if (options is null || !options.Enabled)
        {
            return null;
        }

        var httpClientFactory = services.GetRequiredService<IHttpClientFactory>();
        var httpClient = httpClientFactory.CreateClient();
        var model = options.OllamaModel;
        var discoveryValidator = new OllamaLlmClassifierValidator(
            httpClient,
            new OllamaLlmValidatorOptions
            {
                BaseUrl = options.OllamaUrl,
                TimeoutSeconds = options.TimeoutSeconds,
                Model = model
            });

        if (string.IsNullOrWhiteSpace(model))
        {
            if (Console.IsInputRedirected)
            {
                throw new InvalidOperationException("Specify --ollama-model when --llm-validate is used in a non-interactive session.");
            }

            var models = await discoveryValidator.ListModelsAsync(cancellationToken);
            if (models.Count == 0)
            {
                throw new InvalidOperationException($"No local Ollama models were returned from {options.OllamaUrl}.");
            }

            model = display == null
                ? PromptForModelSelection(models, Console.ReadLine, Console.WriteLine, Console.Write)
                : await display.RunInteractivePromptAsync(() => Task.FromResult(
                    PromptForModelSelection(models, Console.ReadLine, Console.WriteLine, Console.Write)));

            if (!string.IsNullOrWhiteSpace(model))
            {
                display?.WriteEvent($"Using Ollama model: {model}", ConsoleColor.Cyan);
            }
        }

        return new OllamaLlmClassifierValidator(
            httpClient,
            new OllamaLlmValidatorOptions
            {
                BaseUrl = options.OllamaUrl,
                TimeoutSeconds = options.TimeoutSeconds,
                Model = model
            });
    }

    internal static string PromptForModelSelection(
        IReadOnlyList<string> models,
        Func<string?> readLine,
        Action<string> writeLine,
        Action<string> write)
    {
        writeLine("Select an Ollama model for classifier validation:");
        for (var index = 0; index < models.Count; index++)
        {
            writeLine($"{index + 1}. {models[index]}");
        }

        while (true)
        {
            write("Model number (or q to cancel): ");
            var input = readLine();
            if (input == null)
            {
                throw new InvalidOperationException("Interactive model selection was canceled.");
            }

            var trimmed = input.Trim();
            if (string.Equals(trimmed, "q", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(trimmed, "quit", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(trimmed, "exit", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Interactive model selection was canceled.");
            }

            if (int.TryParse(trimmed, out var selection) && selection >= 1 && selection <= models.Count)
            {
                return models[selection - 1];
            }

            writeLine($"Invalid selection '{trimmed}'. Enter a number between 1 and {models.Count}, or 'q' to cancel.");
        }
    }

    internal static async Task<ScanFinding?> ValidateFindingAsync(ILlmClassifierValidator? validator, ScanFinding issue, CliLlmOptions? options = null, CancellationToken cancellationToken = default)
    {
        if (validator == null || string.IsNullOrWhiteSpace(issue.LlmValidationCandidate))
        {
            return issue;
        }

        var result = await validator.ValidateAsync(new LlmValidationRequest
        {
            ClassifierName = issue.ClassifierName,
            ClassifierLabel = issue.RuleName,
            Candidate = issue.LlmValidationCandidate,
            Snippet = issue.Snippet,
            Context = issue.LlmValidationContext,
            ResourcePath = issue.ResourcePath,
            Extension = Path.GetExtension(issue.ResourcePath),
            DeterministicValidatorName = issue.LlmDeterministicValidator,
            DeterministicConfidence = issue.Confidence,
            PromptVersion = string.IsNullOrWhiteSpace(issue.LlmPromptVersion) ? OllamaLlmClassifierValidator.PromptVersion : issue.LlmPromptVersion,
            ValueHash = issue.ValueHash
        }, cancellationToken);

        issue.LlmValidationStatus = result.Status;
        issue.LlmValidationModel = result.Model;
        issue.LlmValidationReason = result.Reason;
        issue.LlmValidationEvidenceSummary = result.EvidenceSummary;
        issue.LlmIsSensitive = result.IsSensitive;
        issue.LlmSensitivityReason = result.SensitivityReason;
        issue.LlmValidatedAt = result.ValidatedAtUtc;
        if (result.Status is Stratus.Sift.Core.Enums.LlmValidationStatus.Accepted or Stratus.Sift.Core.Enums.LlmValidationStatus.Rejected)
        {
            var llmEvidence = new JsonObject
            {
                ["llmValidation"] = new JsonObject
                {
                    ["status"] = result.Status.ToString(),
                    ["isSensitive"] = result.IsSensitive,
                    ["model"] = result.Model,
                    ["reason"] = result.Reason,
                    ["evidenceSummary"] = result.EvidenceSummary,
                    ["sensitivityReason"] = result.SensitivityReason,
                    ["validatedAtUtc"] = result.ValidatedAtUtc,
                    ["promptVersion"] = result.PromptVersion
                }
            };
            issue.EvidenceJson = MergeEvidenceJson(issue.EvidenceJson, llmEvidence);
        }

        if (options?.SensitiveOnly == true && result.IsSensitive != true)
        {
            return null;
        }

        return result.Status == Stratus.Sift.Core.Enums.LlmValidationStatus.Rejected ? null : issue;
    }

    private static string MergeEvidenceJson(string? existingEvidenceJson, JsonNode? llmEvidence)
    {
        if (llmEvidence is null)
        {
            return existingEvidenceJson ?? string.Empty;
        }

        if (string.IsNullOrWhiteSpace(existingEvidenceJson))
        {
            return llmEvidence.ToJsonString();
        }

        try
        {
            var existingNode = JsonNode.Parse(existingEvidenceJson);
            if (existingNode is JsonObject existingObject && llmEvidence is JsonObject llmObject)
            {
                foreach (var property in llmObject)
                {
                    existingObject[property.Key] = property.Value?.DeepClone();
                }

                return existingObject.ToJsonString();
            }
        }
        catch (JsonException)
        {
        }

        return llmEvidence.ToJsonString();
    }
}
