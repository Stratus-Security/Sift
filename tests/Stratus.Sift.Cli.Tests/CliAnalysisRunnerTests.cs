using System.Text.Json;
using Stratus.Sift.Cli;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Cli.Tests;

public sealed class CliAnalysisRunnerTests : IDisposable
{
    private readonly string _tempDirectory = Path.Combine(Path.GetTempPath(), "snare-cli-analysis-tests", Guid.NewGuid().ToString("n"));

    public CliAnalysisRunnerTests()
    {
        Directory.CreateDirectory(_tempDirectory);
    }

    [Fact]
    public async Task RunAnalyzeAsync_ReplaysJsonFindingsToOutputFile()
    {
        var inputPath = Path.Combine(_tempDirectory, "input.json");
        var outputPath = Path.Combine(_tempDirectory, "output.json");
        await File.WriteAllTextAsync(inputPath, JsonSerializer.Serialize(new CliJsonOutputDocument
        {
            Title = "Saved scan",
            SummaryTitle = "Scan complete",
            FilesDiscovered = 3,
            FilesScanned = 2,
            Findings = 1,
            FindingsList =
            [
                new CliOutputFindingRecord
                {
                    RuleName = "OpenAI API Key",
                    ClassifierName = "OpenAI API Key",
                    ResourcePath = "/repo/.env",
                    Severity = "High",
                    ConfidenceLevel = "High",
                    Exposure = "Unknown",
                    Owner = "Unknown",
                    RedactedValue = "sk********",
                    Snippet = "OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456",
                    DetectedAtUtc = DateTime.UtcNow
                }
            ]
        }));

        await CliAnalysisRunner.RunAnalyzeAsync(
            inputPath,
            sensitiveOnly: false,
            llmOptions: null,
            outputOptions: new CliOutputOptions(outputPath, CliOutputFormat.Json, CliOutputStyle.Default));

        var replayed = await CliAnalysisRunner.LoadAsync(outputPath);
        var finding = Assert.Single(replayed.FindingsList);
        Assert.Equal("OpenAI API Key", finding.RuleName);
        Assert.Equal("/repo/.env", finding.ResourcePath);
    }

    [Fact]
    public async Task LoadAsync_AutoDetectsStandardCliTextOutput()
    {
        var inputPath = Path.Combine(_tempDirectory, "saved.cli");
        await File.WriteAllTextAsync(inputPath, """
            Saved scan
            Finding: OpenAI API Key
              Risk: High
              Path: /repo/.env
              Evidence: OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456
              Reason: Looks like a real secret in an environment file.
              Sensitive reason: likely live credential in env file

            Analysis complete
            Elapsed: 00:00:03
            Files scanned: 1
            Findings: 1
            """);

        var document = await CliAnalysisRunner.LoadAsync(inputPath);

        Assert.Equal("Saved scan", document.Title);
        Assert.Equal(1, document.Findings);

        var finding = Assert.Single(document.FindingsList);
        Assert.Equal("OpenAI API Key", finding.RuleName);
        Assert.Equal("/repo/.env", finding.ResourcePath);
        Assert.Equal("OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456", finding.Snippet);
        Assert.Equal(LlmValidationStatus.Accepted, finding.LlmValidationStatus);
        Assert.Equal("Looks like a real secret in an environment file.", finding.LlmValidationReason);
        Assert.Equal("likely live credential in env file", finding.LlmSensitivityReason);
    }

    [Fact]
    public async Task RunAnalyzeAsync_SensitiveFinding_ReplaysDedicatedSensitiveReasonLine()
    {
        var inputPath = Path.Combine(_tempDirectory, "input.json");
        var outputPath = Path.Combine(_tempDirectory, "output.cli");
        await File.WriteAllTextAsync(inputPath, JsonSerializer.Serialize(new CliJsonOutputDocument
        {
            Title = "Saved scan",
            Findings = 1,
            FindingsList =
            [
                new CliOutputFindingRecord
                {
                    RuleName = "OpenAI API Key",
                    ClassifierName = "OpenAI API Key",
                    ResourcePath = "/repo/.env",
                    Severity = "High",
                    ConfidenceLevel = "High",
                    Exposure = "Unknown",
                    Owner = "Unknown",
                    RedactedValue = "sk********",
                    Snippet = "OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456",
                    LlmValidationStatus = LlmValidationStatus.Accepted,
                    LlmValidationModel = "llama3.2:latest",
                    LlmIsSensitive = true,
                    LlmSensitivityReason = "likely live credential in env file",
                    DetectedAtUtc = DateTime.UtcNow
                }
            ]
        }));

        await CliAnalysisRunner.RunAnalyzeAsync(
            inputPath,
            sensitiveOnly: true,
            llmOptions: null,
            outputOptions: new CliOutputOptions(outputPath, CliOutputFormat.Cli, CliOutputStyle.Default));

        var replayedText = await File.ReadAllTextAsync(outputPath);
        Assert.DoesNotContain("LLM:", replayedText);
        Assert.Contains("Sensitive reason: likely live credential in env file", replayedText);
    }

    [Fact]
    public async Task RunAnalyzeAsync_SensitiveFinding_FallsBackToEvidenceSummaryWhenSensitivityReasonMissing()
    {
        var inputPath = Path.Combine(_tempDirectory, "input-fallback.json");
        var outputPath = Path.Combine(_tempDirectory, "output-fallback.cli");
        await File.WriteAllTextAsync(inputPath, JsonSerializer.Serialize(new CliJsonOutputDocument
        {
            Title = "Saved scan",
            Findings = 1,
            FindingsList =
            [
                new CliOutputFindingRecord
                {
                    RuleName = "PowerShell Credential Usage",
                    ClassifierName = "PowerShell Credential Usage",
                    ResourcePath = "/repo/build.ps1",
                    Severity = "High",
                    ConfidenceLevel = "High",
                    Exposure = "Unknown",
                    Owner = "Unknown",
                    Snippet = "$cred = ConvertTo-SecureString \"hunter2\" -AsPlainText -Force",
                    LlmValidationStatus = LlmValidationStatus.Accepted,
                    LlmValidationModel = "gpt-oss:120b-cloud",
                    LlmValidationReason = "Looks valid",
                    LlmValidationEvidenceSummary = "Inline credential appears live in script",
                    LlmIsSensitive = true,
                    LlmSensitivityReason = string.Empty,
                    DetectedAtUtc = DateTime.UtcNow
                }
            ]
        }));

        await CliAnalysisRunner.RunAnalyzeAsync(
            inputPath,
            sensitiveOnly: true,
            llmOptions: null,
            outputOptions: new CliOutputOptions(outputPath, CliOutputFormat.Cli, CliOutputStyle.Default));

        var replayedText = await File.ReadAllTextAsync(outputPath);
        Assert.DoesNotContain("LLM:", replayedText);
        Assert.Contains("Sensitive reason: Inline credential appears live in script", replayedText);
    }

    [Fact]
    public async Task RunAnalyzeAsync_DoesNotRenderLegacyReasonLineForAcceptedFinding()
    {
        var inputPath = Path.Combine(_tempDirectory, "accepted.json");
        var outputPath = Path.Combine(_tempDirectory, "accepted.cli");
        await File.WriteAllTextAsync(inputPath, JsonSerializer.Serialize(new CliJsonOutputDocument
        {
            Title = "Saved scan",
            Findings = 1,
            FindingsList =
            [
                new CliOutputFindingRecord
                {
                    RuleName = "HTTP Basic Auth Header",
                    ClassifierName = "HTTP Basic Auth Header",
                    ResourcePath = "/repo/request.txt",
                    Severity = "Medium",
                    ConfidenceLevel = "High",
                    Exposure = "Unknown",
                    Owner = "Unknown",
                    Snippet = "Authorization: Basic ZGVtbzpzZWNyZXQ=",
                    LlmValidationStatus = LlmValidationStatus.Accepted,
                    LlmValidationModel = "gpt-oss:120b-cloud",
                    LlmValidationReason = "Decoded credentials and surrounding context indicate a real basic auth header.",
                    LlmIsSensitive = false,
                    DetectedAtUtc = DateTime.UtcNow
                }
            ]
        }));

        await CliAnalysisRunner.RunAnalyzeAsync(
            inputPath,
            sensitiveOnly: false,
            llmOptions: null,
            outputOptions: new CliOutputOptions(outputPath, CliOutputFormat.Cli, CliOutputStyle.Default));

        var replayedText = await File.ReadAllTextAsync(outputPath);
        Assert.DoesNotContain("LLM:", replayedText);
        Assert.DoesNotContain("Reason:", replayedText);
    }

    [Fact]
    public async Task RunAnalyzeAsync_TracksProcessedFindingCountInSummary()
    {
        var inputPath = Path.Combine(_tempDirectory, "progress.json");
        var outputPath = Path.Combine(_tempDirectory, "progress.cli");
        await File.WriteAllTextAsync(inputPath, JsonSerializer.Serialize(new CliJsonOutputDocument
        {
            Title = "Saved scan",
            FindingsList =
            [
                new CliOutputFindingRecord
                {
                    RuleName = "OpenAI API Key",
                    ClassifierName = "OpenAI API Key",
                    ResourcePath = "/repo/.env",
                    Severity = "High",
                    ConfidenceLevel = "High",
                    Exposure = "Unknown",
                    Owner = "Unknown",
                    Snippet = "OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456",
                    DetectedAtUtc = DateTime.UtcNow
                }
            ]
        }));

        await CliAnalysisRunner.RunAnalyzeAsync(
            inputPath,
            sensitiveOnly: false,
            llmOptions: null,
            outputOptions: new CliOutputOptions(outputPath, CliOutputFormat.Cli, CliOutputStyle.Default));

        var replayedText = await File.ReadAllTextAsync(outputPath);
        Assert.Contains("Files scanned: 1", replayedText);
        Assert.Contains("Findings: 1", replayedText);
    }

    [Fact]
    public async Task RunAnalyzeAsync_StandardCliInput_ReplaysEvidenceToCliOutput()
    {
        var inputPath = Path.Combine(_tempDirectory, "saved.cli");
        var outputPath = Path.Combine(_tempDirectory, "replayed.cli");
        await File.WriteAllTextAsync(inputPath, """
            Saved scan
            Finding: OpenAI API Key
              Risk: High
              Path: /repo/.env
              Evidence: OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456

            Analysis complete
            Elapsed: 00:00:03
            Files scanned: 1
            Findings: 1
            """);

        await CliAnalysisRunner.RunAnalyzeAsync(
            inputPath,
            sensitiveOnly: false,
            llmOptions: null,
            outputOptions: new CliOutputOptions(outputPath, CliOutputFormat.Cli, CliOutputStyle.Default));

        var replayedText = await File.ReadAllTextAsync(outputPath);
        Assert.Contains("Evidence:", replayedText);
        Assert.Contains("OPENAI_API_KEY=", replayedText);
    }

    [Fact]
    public async Task LoadAsync_AutoDetectsSnafflerCliTextOutput()
    {
        var inputPath = Path.Combine(_tempDirectory, "saved-snaffler.cli");
        await File.WriteAllTextAsync(inputPath, """
            [tester@HOST] 2026-04-08 10:00:00Z [Info] Saved scan
            [tester@HOST] 2026-04-08 10:00:01Z [File] {Red}<OpenAI API Key|R|sk-prod-abcdefghijklmnopqrstuvwxyz123456|52B|2026-04-08 09:59:00Z>(/repo/.env) OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456
            [tester@HOST] 2026-04-08 10:00:02Z [Info] Snaffler out.
            """);

        var document = await CliAnalysisRunner.LoadAsync(inputPath);

        Assert.Equal("Saved scan", document.Title);

        var finding = Assert.Single(document.FindingsList);
        Assert.Equal("OpenAI API Key", finding.ClassifierName);
        Assert.Equal("High", finding.Severity);
        Assert.Equal("/repo/.env", finding.ResourcePath);
        Assert.Equal("sk-prod-abcdefghijklmnopqrstuvwxyz123456", finding.RedactedValue);
        Assert.Equal("OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456", finding.Snippet);
    }

    [Fact]
    public void PopulateReplayValidationPayload_ExtractsCandidateFromSavedSnippet()
    {
        var storedFinding = new CliOutputFindingRecord
        {
            RuleName = "OpenAI API Key",
            ClassifierName = "OpenAI API Key",
            ResourcePath = "/repo/.env",
            Severity = "High",
            ConfidenceLevel = "High",
            Exposure = "Unknown",
            Owner = "Unknown",
            RedactedValue = "sk********",
            Snippet = "OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456",
            DetectedAtUtc = DateTime.UtcNow
        };

        var issue = CliAnalysisRunner.ToIssue(storedFinding);
        CliAnalysisRunner.PopulateReplayValidationPayload(issue, storedFinding);

        Assert.Equal("sk-prod-abcdefghijklmnopqrstuvwxyz123456", issue.LlmValidationCandidate);
        Assert.Equal(storedFinding.Snippet, issue.LlmValidationContext);
        Assert.Equal("classifier-validation.v4", issue.LlmPromptVersion);
    }

    [Fact]
    public void PopulateReplayValidationPayload_FallsBackToSavedEvidenceWhenRedactedValueIsUnavailable()
    {
        var storedFinding = new CliOutputFindingRecord
        {
            RuleName = "OpenAI API Key",
            ClassifierName = "OpenAI API Key",
            ResourcePath = "/repo/.env",
            Severity = "High",
            ConfidenceLevel = "High",
            Exposure = "Unknown",
            Owner = "Unknown",
            Evidence = "OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456",
            Snippet = "OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456",
            DetectedAtUtc = DateTime.UtcNow
        };

        var issue = CliAnalysisRunner.ToIssue(storedFinding);
        CliAnalysisRunner.PopulateReplayValidationPayload(issue, storedFinding);

        Assert.Equal("OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456", issue.LlmValidationCandidate);
        Assert.Equal(storedFinding.Snippet, issue.LlmValidationContext);
    }

    [Fact]
    public void IsMetadataFinding_ReturnsFalseForReplayContentFindingWithoutRedactedValue()
    {
        var finding = new Stratus.Sift.Core.Models.ScanFinding
        {
            ResourcePath = "/repo/.env",
            RedactedValue = string.Empty,
            Snippet = "OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz123456"
        };

        Assert.False(CliFindingFormatter.IsMetadataFinding(finding));
    }

    [Fact]
    public void BuildRootCommand_IncludesAnalyzeCommand()
    {
        var parseResult = CliCommandFactory.BuildRootCommand().Parse("analyze --input saved.json");

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void PromptForModelSelection_ReturnsSelectedModel()
    {
        var outputs = new List<string>();
        var prompts = new List<string>();
        var reads = new Queue<string?>(["2"]);

        var selected = CliLlmValidationSupport.PromptForModelSelection(
            ["llama3.2:latest", "qwen3:8b"],
            () => reads.Dequeue(),
            outputs.Add,
            prompts.Add);

        Assert.Equal("qwen3:8b", selected);
        Assert.Contains("Select an Ollama model for classifier validation:", outputs);
        Assert.Contains("Model number (or q to cancel): ", prompts);
    }

    [Fact]
    public void PromptForModelSelection_RepromptsAfterInvalidInput()
    {
        var outputs = new List<string>();
        var prompts = new List<string>();
        var reads = new Queue<string?>(["9", "1"]);

        var selected = CliLlmValidationSupport.PromptForModelSelection(
            ["llama3.2:latest"],
            () => reads.Dequeue(),
            outputs.Add,
            prompts.Add);

        Assert.Equal("llama3.2:latest", selected);
        Assert.Contains(outputs, line => line.Contains("Invalid selection '9'.", StringComparison.Ordinal));
        Assert.Equal(2, prompts.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("q")]
    [InlineData("quit")]
    [InlineData("exit")]
    public void PromptForModelSelection_CancelsCleanly(string? input)
    {
        var reads = new Queue<string?>([input]);

        var exception = Assert.Throws<InvalidOperationException>(() => CliLlmValidationSupport.PromptForModelSelection(
            ["llama3.2:latest"],
            () => reads.Dequeue(),
            _ => { },
            _ => { }));

        Assert.Equal("Interactive model selection was canceled.", exception.Message);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory))
        {
            Directory.Delete(_tempDirectory, recursive: true);
        }
    }
}
