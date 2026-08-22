using System.Text.Json;
using System.Text.Json.Serialization;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli;

[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    AllowTrailingCommas = true,
    ReadCommentHandling = JsonCommentHandling.Skip)]
[JsonSerializable(typeof(Classifier))]
[JsonSerializable(typeof(Policy))]
[JsonSerializable(typeof(IgnoreRule))]
[JsonSerializable(typeof(CliJsonOutputDocument))]
[JsonSerializable(typeof(CliOutputEventRecord))]
[JsonSerializable(typeof(CliOutputFindingRecord))]
[JsonSerializable(typeof(CliCheckpointState))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(DateTimeOffset))]
[JsonSerializable(typeof(TimeSpan))]
internal sealed partial class CliJsonContext : JsonSerializerContext;
