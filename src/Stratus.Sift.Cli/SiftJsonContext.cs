using System.Text.Json.Serialization;
using Stratus.Sift.Contracts;
using Stratus.Sift.Core;

namespace Stratus.Sift.Cli;

internal sealed record JsonOutputDocument(
    string SchemaVersion,
    string Tool,
    string Version,
    string Target,
    ContentScanSummary Summary,
    ContentObservation[] Observations,
    SiftScanError[] Errors);

internal sealed record NdjsonObservationDocument(
    string Type,
    string SchemaVersion,
    ContentObservation Observation);

internal sealed record NdjsonErrorDocument(
    string Type,
    string SchemaVersion,
    SiftScanError Error);

internal sealed record NdjsonSummaryDocument(
    string Type,
    string SchemaVersion,
    ContentScanSummary Summary);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = true)]
[JsonSerializable(typeof(JsonOutputDocument))]
internal sealed partial class SiftJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(NdjsonObservationDocument))]
[JsonSerializable(typeof(NdjsonErrorDocument))]
[JsonSerializable(typeof(NdjsonSummaryDocument))]
internal sealed partial class SiftNdjsonContext : JsonSerializerContext;
