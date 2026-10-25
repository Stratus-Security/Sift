using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Cli;

internal sealed record CliLlmOptions(bool Enabled, string OllamaUrl, string OllamaModel, int TimeoutSeconds, bool SensitiveOnly,
    LlmThinkingLevel ThinkingLevel = LlmThinkingLevel.Off);
