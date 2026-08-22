using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Core.Validation;

namespace Stratus.Sift.Cli;

internal static class CliAnalysisRunner
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };

    internal static async Task<int> RunAnalyzeAsync(
        string inputPath,
        bool sensitiveOnly,
        CliLlmOptions? llmOptions = null,
        CliOutputOptions? outputOptions = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(inputPath))
        {
            return CliExitCodes.Failed;
        }

        CliJsonOutputDocument? document;
        try
        {
            document = await LoadAsync(inputPath, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await using var errorDisplay = new CliProgressDisplay($"Analyze {Path.GetFileName(inputPath)}", outputOptions);
            errorDisplay.WriteEvent($"Error: failed to read analysis input '{inputPath}': {ex.GetBaseException().Message}", ConsoleColor.Red);
            errorDisplay.IncrementErrors();
            errorDisplay.Complete("Analysis failed");
            return CliExitCodes.Failed;
        }

        await using var display = new CliProgressDisplay(
            string.IsNullOrWhiteSpace(document.Title) ? $"Analyze {Path.GetFileName(inputPath)}" : $"Analyze {document.Title}",
            outputOptions);

        display.SetPhase("Loading saved findings");
        display.WriteEvent($"Loaded {document.FindingsList.Count:N0} finding(s) from {inputPath}", ConsoleColor.Cyan);

        ILlmClassifierValidator? llmValidator = null;
        IHost? llmHost = null;
        var effectiveLlmOptions = llmOptions;

        try
        {
            if (llmOptions?.Enabled == true)
            {
                llmHost = Program.CreateHost();
                llmValidator = await CliLlmValidationSupport.CreateValidatorAsync(llmHost.Services, llmOptions, display, cancellationToken);
                effectiveLlmOptions = llmOptions with { SensitiveOnly = sensitiveOnly };
                display.SetPhase("Re-analyzing findings with Ollama");
            }
            else
            {
                display.SetPhase("Replaying saved findings");
            }

            var replayedCount = 0;
            var filteredCount = 0;
            var llmSkippedCount = 0;

            foreach (var storedFinding in document.FindingsList)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var finding = ToIssue(storedFinding);
                finding.ResourcePath = CliCloudResourceLinkNormalizer.Normalize(finding.ResourcePath, document.Events);
                display.SetCurrentPath(finding.ResourcePath);
                display.IncrementFiles();
                if (llmValidator != null)
                {
                    ArgumentNullException.ThrowIfNull(effectiveLlmOptions);
                    PopulateReplayValidationPayload(finding, storedFinding);
                    if (string.IsNullOrWhiteSpace(finding.LlmValidationCandidate))
                    {
                        llmSkippedCount++;
                        if (sensitiveOnly)
                        {
                            filteredCount++;
                            continue;
                        }
                    }

                    var validated = await CliLlmValidationSupport.ValidateFindingAsync(
                        llmValidator,
                        finding,
                        effectiveLlmOptions,
                        cancellationToken);

                    if (validated == null)
                    {
                        filteredCount++;
                        continue;
                    }

                    finding = validated;
                }
                else if (sensitiveOnly && finding.LlmIsSensitive != true)
                {
                    filteredCount++;
                    continue;
                }

                replayedCount++;
                display.AddFindings(1);
                display.WriteFinding(finding, finding.ResourcePath);
            }

            display.ClearCurrentPath();

            if (llmValidator != null && llmSkippedCount > 0)
            {
                display.WriteEvent(
                    $"Info: skipped LLM re-analysis for {llmSkippedCount:N0} finding(s) because the saved JSON did not preserve enough candidate data.",
                    ConsoleColor.Cyan);
            }

            if (filteredCount > 0)
            {
                display.WriteEvent($"Filtered out {filteredCount:N0} finding(s).", ConsoleColor.Cyan);
            }

            display.WriteEvent($"Rendered {replayedCount:N0} finding(s).", ConsoleColor.Cyan);
            display.Complete("Analysis complete");
            return CliExitCodes.Success;
        }
        finally
        {
            llmHost?.Dispose();
        }
    }

    internal static async Task<CliJsonOutputDocument> LoadAsync(string inputPath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(inputPath))
        {
            throw new FileNotFoundException("Input file was not found.", inputPath);
        }

        var content = await File.ReadAllTextAsync(inputPath, cancellationToken);
        if (string.IsNullOrWhiteSpace(content))
        {
            throw new InvalidOperationException("Input file was empty.");
        }

        var inferredTitle = Path.GetFileNameWithoutExtension(inputPath);
        if (TryParseJsonDocument(content, out var jsonDocument) && jsonDocument != null)
        {
            return jsonDocument;
        }

        if (TryParseDefaultCliDocument(content, inferredTitle, out var defaultDocument) && defaultDocument != null)
        {
            return defaultDocument;
        }

        if (TryParseSnafflerCliDocument(content, inferredTitle, out var snafflerDocument) && snafflerDocument != null)
        {
            return snafflerDocument;
        }

        throw new InvalidOperationException(
            "Input file was not recognized as CLI JSON, standard CLI text output, or Snaffler-style CLI text output.");
    }

    internal static ScanFinding ToIssue(CliOutputFindingRecord finding)
    {
        return new ScanFinding
        {
            Id = Guid.NewGuid(),
            RuleName = finding.RuleName,
            ClassifierName = finding.ClassifierName,
            ResourcePath = finding.ResourcePath,
            Severity = Enum.TryParse<Severity>(finding.Severity, ignoreCase: true, out var severity) ? severity : Severity.Medium,
            ConfidenceLevel = Enum.TryParse<ConfidenceLevel>(finding.ConfidenceLevel, ignoreCase: true, out var confidenceLevel) ? confidenceLevel : ConfidenceLevel.Medium,
            Exposure = finding.Exposure,
            Owner = finding.Owner,
            RedactedValue = finding.RedactedValue,
            Snippet = finding.Snippet,
            DetectedAt = finding.DetectedAtUtc,
            EvidenceJson = finding.EvidenceJson ?? string.Empty,
            LlmValidationStatus = finding.LlmValidationStatus,
            LlmValidationModel = finding.LlmValidationModel ?? string.Empty,
            LlmValidationReason = finding.LlmValidationReason ?? string.Empty,
            LlmValidationEvidenceSummary = finding.LlmValidationEvidenceSummary ?? string.Empty,
            LlmIsSensitive = finding.LlmIsSensitive,
            LlmSensitivityReason = finding.LlmSensitivityReason ?? string.Empty,
            LlmValidatedAt = finding.LlmValidatedAtUtc
        };
    }

    internal static void PopulateReplayValidationPayload(ScanFinding finding, CliOutputFindingRecord storedFinding)
    {
        if (storedFinding.IsMetadata)
        {
            return;
        }

        string? candidate = null;
        if (!string.IsNullOrWhiteSpace(storedFinding.RedactedValue))
        {
            candidate = CliFindingFormatter.ExtractDisplayMatchValue(finding, storedFinding.ResourcePath);
        }

        if (string.IsNullOrWhiteSpace(candidate) &&
            !string.IsNullOrWhiteSpace(storedFinding.RedactedValue) &&
            !storedFinding.RedactedValue.Contains('*', StringComparison.Ordinal))
        {
            candidate = storedFinding.RedactedValue;
        }

        if (string.IsNullOrWhiteSpace(candidate) && !string.IsNullOrWhiteSpace(storedFinding.Evidence))
        {
            candidate = storedFinding.Evidence;
        }

        if (string.IsNullOrWhiteSpace(candidate) && !string.IsNullOrWhiteSpace(storedFinding.Snippet))
        {
            candidate = storedFinding.Snippet;
        }

        finding.LlmValidationCandidate = candidate ?? string.Empty;
        finding.LlmValidationContext = string.IsNullOrWhiteSpace(storedFinding.Snippet)
            ? storedFinding.Evidence ?? string.Empty
            : storedFinding.Snippet;
        finding.LlmPromptVersion = OllamaLlmClassifierValidator.PromptVersion;
    }

    private static bool TryParseJsonDocument(string content, out CliJsonOutputDocument? document)
    {
        document = null;

        try
        {
            document = JsonSerializer.Deserialize(content, CliJsonContext.Default.CliJsonOutputDocument);
            return document != null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryParseDefaultCliDocument(string content, string inferredTitle, out CliJsonOutputDocument? document)
    {
        document = null;
        var lines = SplitLines(content);
        if (!lines.Any(static line => line.StartsWith("Finding: ", StringComparison.Ordinal)))
        {
            return false;
        }

        var findings = new List<CliOutputFindingRecord>();
        for (var index = 0; index < lines.Count; index++)
        {
            var line = lines[index];
            if (!line.StartsWith("Finding: ", StringComparison.Ordinal))
            {
                continue;
            }

            var ruleName = line["Finding: ".Length..].Trim();
            if (string.IsNullOrWhiteSpace(ruleName))
            {
                continue;
            }

            var finding = new CliOutputFindingRecord
            {
                RuleName = ruleName,
                ClassifierName = ruleName,
                Severity = Severity.Medium.ToString(),
                ConfidenceLevel = ConfidenceLevel.Medium.ToString(),
                Exposure = "Unknown",
                Owner = "Unknown",
                DetectedAtUtc = DateTime.UtcNow
            };

            while (index + 1 < lines.Count && lines[index + 1].StartsWith("  ", StringComparison.Ordinal))
            {
                index++;
                ParseDefaultCliFindingLine(lines[index].Trim(), finding);
            }

            finding.IsMetadata = string.IsNullOrWhiteSpace(finding.Evidence);
            finding.RedactedValue = finding.IsMetadata ? "[METADATA MATCH]" : string.Empty;
            finding.Snippet = finding.IsMetadata ? string.Empty : finding.Evidence ?? string.Empty;
            findings.Add(finding);
        }

        if (findings.Count == 0)
        {
            return false;
        }

        document = new CliJsonOutputDocument
        {
            Title = InferDefaultCliTitle(lines, inferredTitle),
            SummaryTitle = InferSummaryTitle(lines),
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            Findings = ParseSummaryCount(lines, "Findings:", findings.Count),
            FilesDiscovered = ParseSummaryCount(lines, "Files discovered:", 0),
            FilesScanned = ParseSummaryCount(lines, "Files scanned:", 0),
            Errors = ParseSummaryCount(lines, "Errors:", 0),
            Events = CliCloudResourceLinkNormalizer.ExtractDiscoveryEvents(lines),
            FindingsList = findings
        };

        return true;
    }

    private static bool TryParseSnafflerCliDocument(string content, string inferredTitle, out CliJsonOutputDocument? document)
    {
        document = null;
        var lines = SplitLines(content);
        if (!lines.Any(static line => line.Contains("[File]", StringComparison.Ordinal)))
        {
            return false;
        }

        var findings = new List<CliOutputFindingRecord>();
        foreach (var line in lines)
        {
            if (TryParseSnafflerFinding(line, out var finding))
            {
                findings.Add(finding);
            }
        }

        if (findings.Count == 0)
        {
            return false;
        }

        document = new CliJsonOutputDocument
        {
            Title = InferSnafflerTitle(lines, inferredTitle),
            SummaryTitle = InferSummaryTitle(lines),
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            Findings = findings.Count,
            Events = CliCloudResourceLinkNormalizer.ExtractDiscoveryEvents(lines),
            FindingsList = findings
        };

        return true;
    }

    private static void ParseDefaultCliFindingLine(string line, CliOutputFindingRecord finding)
    {
        if (line.StartsWith("Risk: ", StringComparison.Ordinal))
        {
            finding.Severity = line["Risk: ".Length..].Trim();
            return;
        }

        if (line.StartsWith("Path: ", StringComparison.Ordinal))
        {
            finding.ResourcePath = line["Path: ".Length..].Trim();
            return;
        }

        if (line.StartsWith("Evidence: ", StringComparison.Ordinal))
        {
            finding.Evidence = line["Evidence: ".Length..].Trim();
            return;
        }

        if (line.StartsWith("LLM: ", StringComparison.Ordinal))
        {
            ParseDefaultCliLlmLine(line["LLM: ".Length..].Trim(), finding);
            return;
        }

        if (line.StartsWith("Sensitive reason: ", StringComparison.Ordinal))
        {
            finding.LlmSensitivityReason = line["Sensitive reason: ".Length..].Trim();
            return;
        }

        if (line.StartsWith("Reason: ", StringComparison.Ordinal))
        {
            finding.LlmValidationReason = line["Reason: ".Length..].Trim();
            if (finding.LlmValidationStatus is null)
            {
                finding.LlmValidationStatus = LlmValidationStatus.Accepted;
            }
        }
    }

    private static void ParseDefaultCliLlmLine(string llmText, CliOutputFindingRecord finding)
    {
        if (!llmText.StartsWith("match,", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        finding.LlmValidationStatus = LlmValidationStatus.Accepted;

        var remainder = llmText["match,".Length..].Trim();
        if (remainder.StartsWith("sensitive", StringComparison.OrdinalIgnoreCase))
        {
            finding.LlmIsSensitive = true;
            remainder = remainder["sensitive".Length..].Trim();
        }
        else if (remainder.StartsWith("not sensitive", StringComparison.OrdinalIgnoreCase))
        {
            finding.LlmIsSensitive = false;
            remainder = remainder["not sensitive".Length..].Trim();
        }
        else if (remainder.StartsWith("sensitivity unknown", StringComparison.OrdinalIgnoreCase))
        {
            finding.LlmIsSensitive = null;
            remainder = remainder["sensitivity unknown".Length..].Trim();
        }

        if (remainder.StartsWith("via ", StringComparison.OrdinalIgnoreCase))
        {
            remainder = remainder["via ".Length..];
            var reasonDelimiter = remainder.IndexOf(": ", StringComparison.Ordinal);
            if (reasonDelimiter >= 0)
            {
                finding.LlmValidationModel = remainder[..reasonDelimiter].Trim();
                finding.LlmSensitivityReason = remainder[(reasonDelimiter + 2)..].Trim();
            }
            else
            {
                finding.LlmValidationModel = remainder.Trim();
            }
        }
        else if (remainder.StartsWith(": ", StringComparison.Ordinal))
        {
            finding.LlmSensitivityReason = remainder[2..].Trim();
        }
    }

    private static bool TryParseSnafflerFinding(string line, out CliOutputFindingRecord finding)
    {
        finding = new CliOutputFindingRecord();

        var fileTagIndex = line.IndexOf("[File]", StringComparison.Ordinal);
        if (fileTagIndex < 0)
        {
            return false;
        }

        var triageStart = line.IndexOf('{', fileTagIndex);
        var triageEnd = triageStart >= 0 ? line.IndexOf('}', triageStart + 1) : -1;
        var detailStart = triageEnd >= 0 ? line.IndexOf('<', triageEnd + 1) : -1;
        var detailEnd = detailStart >= 0 ? line.IndexOf('>', detailStart + 1) : -1;
        var pathStart = detailEnd >= 0 ? line.IndexOf('(', detailEnd + 1) : -1;
        var pathEnd = pathStart >= 0 ? line.IndexOf(')', pathStart + 1) : -1;
        if (triageStart < 0 || triageEnd < 0 || detailStart < 0 || detailEnd < 0 || pathStart < 0 || pathEnd < 0)
        {
            return false;
        }

        var triage = line[(triageStart + 1)..triageEnd].Trim();
        var detail = line[(detailStart + 1)..detailEnd];
        var parts = detail.Split('|');
        if (parts.Length < 3)
        {
            return false;
        }

        var classifierName = parts[0].Trim();
        var matchedValue = parts[2].Trim();
        var resourcePath = line[(pathStart + 1)..pathEnd].Trim();
        var snippet = pathEnd + 1 < line.Length ? line[(pathEnd + 1)..].Trim() : string.Empty;
        if (string.IsNullOrWhiteSpace(classifierName) || string.IsNullOrWhiteSpace(resourcePath))
        {
            return false;
        }

        finding = new CliOutputFindingRecord
        {
            RuleName = classifierName,
            ClassifierName = classifierName,
            ResourcePath = resourcePath,
            Severity = MapSnafflerTriageToSeverity(triage),
            ConfidenceLevel = ConfidenceLevel.Medium.ToString(),
            Exposure = "Unknown",
            Owner = "Unknown",
            IsMetadata = string.IsNullOrWhiteSpace(snippet),
            Evidence = string.IsNullOrWhiteSpace(snippet) ? null : snippet,
            RedactedValue = string.IsNullOrWhiteSpace(matchedValue) ? string.Empty : matchedValue,
            Snippet = snippet,
            DetectedAtUtc = TryParseSnafflerTimestamp(line, out var detectedAtUtc) ? detectedAtUtc : DateTime.UtcNow
        };

        if (finding.IsMetadata && string.IsNullOrWhiteSpace(finding.RedactedValue))
        {
            finding.RedactedValue = "[METADATA MATCH]";
        }

        return true;
    }

    private static string MapSnafflerTriageToSeverity(string triage)
    {
        return triage switch
        {
            "Red" => Severity.High.ToString(),
            "Yellow" => Severity.Medium.ToString(),
            "Green" => Severity.Low.ToString(),
            "Black" => Severity.Info.ToString(),
            _ => Severity.Medium.ToString()
        };
    }

    private static bool TryParseSnafflerTimestamp(string line, out DateTime detectedAtUtc)
    {
        detectedAtUtc = default;
        var hostEnd = line.IndexOf(']');
        if (hostEnd < 0 || hostEnd + 2 >= line.Length)
        {
            return false;
        }

        var tagStart = line.IndexOf('[', hostEnd + 2);
        if (tagStart < 0)
        {
            return false;
        }

        var timestampText = line[(hostEnd + 2)..tagStart].Trim();
        return DateTime.TryParse(timestampText, out detectedAtUtc);
    }

    private static List<string> SplitLines(string content)
    {
        return content
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n')
            .Select(static line => line.TrimEnd())
            .ToList();
    }

    private static string InferDefaultCliTitle(IReadOnlyList<string> lines, string inferredTitle)
    {
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (line.StartsWith("Finding: ", StringComparison.Ordinal) ||
                line.StartsWith("Elapsed:", StringComparison.Ordinal) ||
                line.StartsWith("Files ", StringComparison.Ordinal) ||
                line.StartsWith("Errors:", StringComparison.Ordinal))
            {
                break;
            }

            return line.Trim();
        }

        return inferredTitle;
    }

    private static string InferSnafflerTitle(IReadOnlyList<string> lines, string inferredTitle)
    {
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                continue;
            }

            if (trimmed.StartsWith(".", StringComparison.Ordinal) ||
                trimmed.StartsWith("by l0ss", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Contains("[Info]", StringComparison.Ordinal) ||
                trimmed.Contains("[File]", StringComparison.Ordinal))
            {
                if (trimmed.Contains("[Info]", StringComparison.Ordinal))
                {
                    var infoIndex = trimmed.IndexOf("[Info]", StringComparison.Ordinal);
                    return trimmed[(infoIndex + "[Info]".Length)..].Trim();
                }

                continue;
            }

            return trimmed;
        }

        return inferredTitle;
    }

    private static string InferSummaryTitle(IReadOnlyList<string> lines)
    {
        for (var index = lines.Count - 1; index >= 0; index--)
        {
            var line = lines[index].Trim();
            if (line.EndsWith("complete", StringComparison.OrdinalIgnoreCase))
            {
                return line;
            }
        }

        return "Analysis import";
    }

    private static long ParseSummaryCount(IReadOnlyList<string> lines, string prefix, long defaultValue)
    {
        foreach (var line in lines)
        {
            if (!line.StartsWith(prefix, StringComparison.Ordinal))
            {
                continue;
            }

            var rawValue = line[prefix.Length..].Trim().Replace(",", string.Empty, StringComparison.Ordinal);
            if (long.TryParse(rawValue, out var parsed))
            {
                return parsed;
            }
        }

        return defaultValue;
    }
}
