using System.CommandLine;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Stratus.Sift.Cli;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Validation;

namespace Stratus.Sift.Cli.Tests;

public sealed class CliLlmThinkingTests
{
    [Fact]
    public async Task Validator_DefaultSendsThinkingOff()
    {
        using var handler = new OllamaHandler();
        using var client = new HttpClient(handler);
        var validator = new OllamaLlmClassifierValidator(client, new OllamaLlmValidatorOptions { Model = "qwen3.8" });

        var result = await validator.ValidateAsync(new LlmValidationRequest { ClassifierName = "Secret", Candidate = "secret-value" });

        Assert.Equal(LlmValidationStatus.Accepted, result.Status);
        Assert.Equal("false", handler.ThinkJson);
    }

    [Theory]
    [InlineData(LlmThinkingLevel.Off, "false")]
    [InlineData(LlmThinkingLevel.On, "true")]
    [InlineData(LlmThinkingLevel.Low, "\"low\"")]
    [InlineData(LlmThinkingLevel.Medium, "\"medium\"")]
    [InlineData(LlmThinkingLevel.High, "\"high\"")]
    [InlineData(LlmThinkingLevel.Xhigh, "\"xhigh\"")]
    public async Task CreateValidatorAsync_ForwardsThinkingAsOllamaBooleanOrLevel(LlmThinkingLevel level, string expectedJson)
    {
        using var handler = new OllamaHandler();
        using var client = new HttpClient(handler);
        using var services = new ServiceCollection()
            .AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(client))
            .BuildServiceProvider();
        var options = new CliLlmOptions(true, "http://localhost:11434", "qwen3.8", 20, false, level);
        var validator = await CliLlmValidationSupport.CreateValidatorAsync(services, options);

        Assert.NotNull(validator);
        var result = await validator.ValidateAsync(new LlmValidationRequest { ClassifierName = "Secret", Candidate = "secret-value" });

        Assert.Equal(LlmValidationStatus.Accepted, result.Status);
        Assert.Equal(expectedJson, handler.ThinkJson);
    }

    [Theory]
    [InlineData("local", "--path", ".")]
    [InlineData("domain", null, null)]
    [InlineData("network", "--device", "server.example.test")]
    [InlineData("m365", null, null)]
    [InlineData("slack", "--token", "xoxb-test")]
    [InlineData("atlassian", "--url", "https://example.atlassian.net")]
    [InlineData("analyze", "--input", "findings.json")]
    public void AllCommands_DefaultThinkingOffAndAcceptExplicitLevels(string commandName, string? requiredOption, string? requiredValue)
    {
        var root = Program.BuildRootCommand();
        var command = root.Subcommands.Single(item => item.Name == commandName);
        var option = Assert.IsType<Option<LlmThinkingLevel>>(command.Options.Single(item => item.Name == "--llm-think"));
        List<string> arguments = [commandName, "--llm-validate", "--ollama-model", "qwen3.8"];
        if (requiredOption != null)
        {
            arguments.Add(requiredOption);
            arguments.Add(requiredValue!);
        }

        var defaults = root.Parse(arguments.ToArray());
        Assert.Empty(defaults.Errors);
        Assert.Equal(LlmThinkingLevel.Off, defaults.GetValue(option));

        foreach (var level in Enum.GetValues<LlmThinkingLevel>())
        {
            var parsed = root.Parse([.. arguments, "--llm-think", level.ToString().ToLowerInvariant()]);
            Assert.Empty(parsed.Errors);
            Assert.Equal(level, parsed.GetValue(option));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("1")]
    [InlineData("off,on")]
    [InlineData("999")]
    public void ThinkingOption_RejectsMissingOrInvalidLevels(string? level)
    {
        List<string> arguments = ["local", "--path", ".", "--llm-think"];
        if (level != null) arguments.Add(level);

        var parsed = Program.BuildRootCommand().Parse(arguments.ToArray());

        Assert.NotEmpty(parsed.Errors);
    }

    [Fact]
    public void ResumeScopes_ChangeWhenThinkingChanges()
    {
        var off = new CliLlmOptions(true, "http://localhost:11434", "qwen3.8", 20, false);
        var high = off with { ThinkingLevel = LlmThinkingLevel.High };
        var target = new FileSystemScanTarget(FileSystemScanMode.Folder, ".");

        Assert.NotEqual(
            CliResumeIdentity.CreateFilesystemScope(target, ".", "rules", false, off, null, false, null),
            CliResumeIdentity.CreateFilesystemScope(target, ".", "rules", false, high, null, false, null));
        Assert.NotEqual(
            CliResumeIdentity.CreateConnectorScope("Test", new Dictionary<string, string>(), "account", "rules", false, off),
            CliResumeIdentity.CreateConnectorScope("Test", new Dictionary<string, string>(), "account", "rules", false, high));
    }

    private sealed class TestHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class OllamaHandler : HttpMessageHandler
    {
        public string? ThinkJson { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("/api/generate", request.RequestUri?.AbsolutePath);
            using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            ThinkJson = document.RootElement.GetProperty("think").GetRawText();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    response = """{"isMatch":true,"isSensitive":true,"evidenceSummary":"Real secret.","sensitivityReason":"Exposes a credential."}"""
                }))
            };
        }
    }
}
