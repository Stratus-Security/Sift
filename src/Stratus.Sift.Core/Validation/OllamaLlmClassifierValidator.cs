using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Core.Validation;

public sealed partial class OllamaLlmClassifierValidator : ILlmClassifierValidator
{
    public const string PromptVersion = "classifier-validation.v4";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly OllamaJsonContext JsonContext = new(JsonOptions);
    private static readonly JsonElement StructuredOutputSchema = BuildStructuredOutputSchema();
    private readonly HttpClient _httpClient;
    private readonly OllamaLlmValidatorOptions _options;
    private readonly SemaphoreSlim _requestGate;
    private readonly ConcurrentDictionary<string, LlmValidationResult> _resultCache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Lazy<Task<LlmValidationResult>>> _inflight = new(StringComparer.Ordinal);

    public OllamaLlmClassifierValidator(HttpClient httpClient, OllamaLlmValidatorOptions options)
    {
        _httpClient = httpClient;
        _options = options;
        _requestGate = new SemaphoreSlim(Math.Max(1, options.MaxConcurrentRequests));
    }

    public async Task<IReadOnlyList<string>> ListModelsAsync(CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, BuildUri("/api/tags"));
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var payload = await JsonSerializer.DeserializeAsync(stream, JsonContext.OllamaTagsResponse, cancellationToken);
        return payload?.Models?
            .Select(item => item.Name)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList() ?? [];
    }

    public Task<LlmValidationResult> ValidateAsync(LlmValidationRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.Model))
        {
            return Task.FromResult(LlmValidationResult.Skipped("No Ollama model configured.", request.PromptVersion));
        }

        if (string.IsNullOrWhiteSpace(request.Candidate))
        {
            return Task.FromResult(LlmValidationResult.Skipped("No candidate value available for classifier-level LLM validation.", request.PromptVersion));
        }

        var cacheKey = BuildCacheKey(request);
        if (_resultCache.TryGetValue(cacheKey, out var cached))
        {
            return Task.FromResult(cached);
        }

        var lazy = _inflight.GetOrAdd(cacheKey, _ => new Lazy<Task<LlmValidationResult>>(() => ExecuteValidationAsync(request, cancellationToken)));
        return CompleteAsync(cacheKey, lazy);
    }

    private async Task<LlmValidationResult> CompleteAsync(string cacheKey, Lazy<Task<LlmValidationResult>> lazyTask)
    {
        try
        {
            var result = await lazyTask.Value;
            _resultCache[cacheKey] = result;
            return result;
        }
        finally
        {
            _inflight.TryRemove(cacheKey, out _);
        }
    }

    private async Task<LlmValidationResult> ExecuteValidationAsync(LlmValidationRequest request, CancellationToken cancellationToken)
    {
        await _requestGate.WaitAsync(cancellationToken);
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _options.TimeoutSeconds)));

            var prompt = BuildPrompt(request);
            var payload = new OllamaGenerateRequest
            {
                Model = _options.Model,
                Prompt = prompt,
                Stream = false,
                Format = StructuredOutputSchema,
                Options = new OllamaGenerateOptions
                {
                    Temperature = 0
                }
            };

            using var response = await _httpClient.PostAsJsonAsync(BuildUri("/api/generate"), payload, JsonContext.OllamaGenerateRequest, timeoutCts.Token);
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(timeoutCts.Token);
            var ollamaResponse = await JsonSerializer.DeserializeAsync(stream, JsonContext.OllamaGenerateResponse, timeoutCts.Token);
            var raw = ollamaResponse?.Response?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(raw))
            {
                return LlmValidationResult.Error("Ollama returned an empty response.", request.PromptVersion, _options.Model);
            }

            var verdict = ParseVerdict(raw);
            if (verdict == null)
            {
                var error = LlmValidationResult.Error("Ollama returned invalid JSON for classifier validation.", request.PromptVersion, _options.Model);
                error.RawResponse = raw;
                error.ValidatedAtUtc = DateTime.UtcNow;
                return error;
            }

            return new LlmValidationResult
            {
                Status = verdict.IsMatch ? LlmValidationStatus.Accepted : LlmValidationStatus.Rejected,
                Model = _options.Model,
                Reason = verdict.EvidenceSummary ?? verdict.Reason ?? string.Empty,
                EvidenceSummary = verdict.EvidenceSummary ?? string.Empty,
                IsSensitive = verdict.IsSensitive,
                SensitivityReason = ResolveSensitivityReason(verdict),
                PromptVersion = request.PromptVersion,
                RawResponse = raw,
                ValidatedAtUtc = DateTime.UtcNow
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return LlmValidationResult.Error("Ollama validation timed out.", request.PromptVersion, _options.Model);
        }
        catch (Exception ex)
        {
            return LlmValidationResult.Error(ex.GetBaseException().Message, request.PromptVersion, _options.Model);
        }
        finally
        {
            _requestGate.Release();
        }
    }

    private string BuildPrompt(LlmValidationRequest request)
    {
        var candidate = TrimForPrompt(request.Candidate, _options.MaxCandidateLength);
        var snippet = TrimForPrompt(request.Snippet, _options.MaxSnippetLength);
        var context = TrimForPrompt(request.Context, _options.MaxContextLength);
        var builder = new StringBuilder();
        builder.AppendLine("You validate whether a detected secret/data match really belongs to the named classifier.");
        builder.AppendLine("You must return structured JSON matching the provided schema.");
        builder.AppendLine("Assess two separate questions:");
        builder.AppendLine("1. Does the candidate actually match the named classifier?");
        builder.AppendLine("2. Should this finding be treated as sensitive?");
        builder.AppendLine("Treat the classifier decision as 'real instance of the data', not merely 'string matches the format'.");
        builder.AppendLine("A finding is sensitive when it exposes or strongly indicates real credentials, identity documents, financial/regulated data, or insecure credential storage/configuration.");
        builder.AppendLine("This can include scripts or configs with inline credentials, stored secrets, reversible password blobs, or nearby context indicating insecure secret handling.");
        builder.AppendLine("If the content looks like documentation, samples, placeholders, templates, demo/test fixtures, tutorials, mocked values, or inert metadata, set isMatch=false even if the token format looks valid.");
        builder.AppendLine("Only set isMatch=true when the candidate and surrounding context indicate an actual instance of the named data type rather than an example or placeholder.");
        builder.AppendLine("Keep evidenceSummary concise.");
        builder.AppendLine("If isSensitive=true, sensitivityReason must be short and concise, with no more than 1-2 sentences.");
        builder.AppendLine("If isSensitive=false, sensitivityReason should be empty unless a brief clarification is truly necessary.");
        builder.AppendLine();
        builder.AppendLine($"ClassifierName: {request.ClassifierName}");
        builder.AppendLine($"ClassifierLabel: {request.ClassifierLabel}");
        builder.AppendLine($"ClassifierDescription: {request.ClassifierDescription}");
        builder.AppendLine($"ResourcePath: {request.ResourcePath}");
        builder.AppendLine($"Extension: {request.Extension}");
        if (!string.IsNullOrWhiteSpace(request.DeterministicValidatorName))
        {
            builder.AppendLine($"DeterministicValidator: {request.DeterministicValidatorName}");
        }

        if (request.DeterministicConfidence.HasValue)
        {
            builder.AppendLine($"DeterministicConfidence: {request.DeterministicConfidence.Value:0.###}");
        }

        builder.AppendLine("CandidateValue:");
        builder.AppendLine(candidate);
        builder.AppendLine("Snippet:");
        builder.AppendLine(snippet);
        if (!string.Equals(context, snippet, StringComparison.Ordinal))
        {
            builder.AppendLine("Context:");
            builder.AppendLine(context);
        }

        builder.AppendLine("Question: Does the candidate actually look like the named classifier, given the surrounding context, and should the resulting finding be treated as sensitive?");
        return builder.ToString();
    }

    private static string TrimForPrompt(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        return normalized.Length <= maxLength ? normalized : normalized[..maxLength];
    }

    private static OllamaValidationVerdict? ParseVerdict(string rawResponse)
    {
        var candidate = rawResponse.Trim();
        var start = candidate.IndexOf('{');
        var end = candidate.LastIndexOf('}');
        if (start >= 0 && end > start)
        {
            candidate = candidate[start..(end + 1)];
        }

        try
        {
            return JsonSerializer.Deserialize(candidate, JsonContext.OllamaValidationVerdict);
        }
        catch
        {
            return null;
        }
    }

    private static string ResolveSensitivityReason(OllamaValidationVerdict verdict)
    {
        if (!string.IsNullOrWhiteSpace(verdict.SensitivityReason))
        {
            return verdict.SensitivityReason;
        }

        if (!string.IsNullOrWhiteSpace(verdict.EvidenceSummary))
        {
            return verdict.EvidenceSummary;
        }

        return verdict.Reason ?? string.Empty;
    }

    private string BuildCacheKey(LlmValidationRequest request)
    {
        var valueHash = string.IsNullOrWhiteSpace(request.ValueHash) ? ComputeSha256(request.Candidate) : request.ValueHash;
        var snippetHash = string.IsNullOrWhiteSpace(request.SnippetHash) ? ComputeSha256(request.Snippet) : request.SnippetHash;
        return string.Join('|', request.ClassifierName, valueHash, snippetHash, _options.Model, request.PromptVersion);
    }

    private Uri BuildUri(string relativePath)
    {
        return new Uri(new Uri(_options.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute), relativePath.TrimStart('/'));
    }

    private static string ComputeSha256(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes);
    }

    private sealed class OllamaTagsResponse
    {
        public List<OllamaTagModel>? Models { get; set; }
    }

    private sealed class OllamaTagModel
    {
        public string Name { get; set; } = string.Empty;
    }

    private sealed class OllamaGenerateRequest
    {
        public string Model { get; set; } = string.Empty;
        public string Prompt { get; set; } = string.Empty;
        public bool Stream { get; set; }
        public JsonElement Format { get; set; }
        public OllamaGenerateOptions? Options { get; set; }
    }

    private sealed class OllamaGenerateOptions
    {
        public int Temperature { get; set; }
    }

    private sealed class OllamaGenerateResponse
    {
        public string Response { get; set; } = string.Empty;
    }

    private sealed class OllamaValidationVerdict
    {
        public bool IsMatch { get; set; }
        public bool IsSensitive { get; set; }
        public string? Reason { get; set; }
        public string? EvidenceSummary { get; set; }
        public string? SensitivityReason { get; set; }
    }

    [JsonSerializable(typeof(OllamaTagsResponse))]
    [JsonSerializable(typeof(OllamaGenerateRequest))]
    [JsonSerializable(typeof(OllamaGenerateResponse))]
    [JsonSerializable(typeof(OllamaValidationVerdict))]
    private sealed partial class OllamaJsonContext : JsonSerializerContext;

    private static JsonElement BuildStructuredOutputSchema()
    {
        using var document = JsonDocument.Parse("""
        {
          "type": "object",
          "properties": {
            "isMatch": { "type": "boolean" },
            "isSensitive": { "type": "boolean" },
            "evidenceSummary": { "type": "string" },
            "sensitivityReason": { "type": "string" }
          },
          "required": [ "isMatch", "isSensitive", "evidenceSummary", "sensitivityReason" ],
          "additionalProperties": false
        }
        """);

        return document.RootElement.Clone();
    }
}
