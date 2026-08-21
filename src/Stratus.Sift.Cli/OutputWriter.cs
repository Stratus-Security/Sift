using System.Reflection;
using System.Text;
using System.Text.Json;
using Stratus.Sift.Contracts;

namespace Stratus.Sift.Cli;

internal static class OutputWriter
{
    internal static async Task WriteAsync(
        ScanRunResult result,
        CliOptions options,
        TextWriter console,
        CancellationToken cancellationToken)
    {
        var content = options.Format switch
        {
            OutputFormat.Json => BuildJson(result),
            OutputFormat.Ndjson => BuildNdjson(result),
            OutputFormat.Snaffler => BuildSnaffler(result),
            _ => BuildText(result),
        };

        if (string.IsNullOrWhiteSpace(options.OutputPath))
        {
            await console.WriteAsync(content.AsMemory(), cancellationToken);
            return;
        }

        PlatformGuard.EnsurePathSupported(options.OutputPath);
        var outputPath = Path.GetFullPath(options.OutputPath);
        var parent = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrWhiteSpace(parent))
        {
            Directory.CreateDirectory(parent);
        }

        await File.WriteAllTextAsync(outputPath, content, new UTF8Encoding(false), cancellationToken);
        await console.WriteLineAsync($"Wrote {result.Observations.Count} observations to {outputPath}");
    }

    private static string BuildJson(ScanRunResult result)
        => JsonSerializer.Serialize(
            new JsonOutputDocument(
                SiftContractVersions.V1,
                "stratus-sift",
                Version,
                result.Target,
                result.ToSummary(),
                [.. result.Observations],
                [.. result.Errors]),
            SiftJsonContext.Default.JsonOutputDocument) + Environment.NewLine;

    private static string BuildNdjson(ScanRunResult result)
    {
        var builder = new StringBuilder();
        foreach (var observation in result.Observations)
        {
            builder.AppendLine(JsonSerializer.Serialize(
                new NdjsonObservationDocument("observation", SiftContractVersions.V1, observation),
                SiftNdjsonContext.Default.NdjsonObservationDocument));
        }

        foreach (var error in result.Errors)
        {
            builder.AppendLine(JsonSerializer.Serialize(
                new NdjsonErrorDocument("error", SiftContractVersions.V1, error),
                SiftNdjsonContext.Default.NdjsonErrorDocument));
        }

        builder.AppendLine(JsonSerializer.Serialize(
            new NdjsonSummaryDocument("summary", SiftContractVersions.V1, result.ToSummary()),
            SiftNdjsonContext.Default.NdjsonSummaryDocument));
        return builder.ToString();
    }

    private static string BuildText(ScanRunResult result)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"Stratus Sift {Version}");
        builder.AppendLine($"Target: {result.Target}");
        builder.AppendLine();
        foreach (var observation in result.Observations)
        {
            builder.Append('[').Append(observation.Severity.ToUpperInvariant()).Append("] ")
                .Append(observation.RuleName).AppendLine();
            builder.Append("  ").Append(observation.ResourcePath);
            if (observation.LineNumber is not null)
            {
                builder.Append(':').Append(observation.LineNumber.Value);
            }

            builder.AppendLine();
            builder.Append("  ").AppendLine(observation.Snippet);
        }

        if (result.Observations.Count == 0)
        {
            builder.AppendLine("No observations detected.");
        }

        AppendErrors(builder, result.Errors);
        AppendSummary(builder, result);
        return builder.ToString();
    }

    private static string BuildSnaffler(ScanRunResult result)
    {
        var builder = new StringBuilder();
        foreach (var observation in result.Observations)
        {
            var colour = observation.Severity switch
            {
                "critical" => "Black",
                "high" => "Red",
                "medium" => "Yellow",
                _ => "Green",
            };
            builder.Append('[').Append(observation.DetectedAtUtc.ToString("O")).Append(" INF] {")
                .Append(colour).Append("}<")
                .Append(observation.RuleId).Append("> ")
                .Append(observation.ResourcePath);
            if (observation.LineNumber is not null)
            {
                builder.Append(':').Append(observation.LineNumber.Value);
            }

            builder.Append(" | ").AppendLine(observation.RedactedValue);
        }

        AppendErrors(builder, result.Errors);
        AppendSummary(builder, result);
        return builder.ToString();
    }

    private static void AppendErrors(StringBuilder builder, IReadOnlyList<ScanError> errors)
    {
        foreach (var error in errors)
        {
            builder.Append("[WARN] ").Append(error.Path).Append(" | ").AppendLine(error.Message);
        }
    }

    private static void AppendSummary(StringBuilder builder, ScanRunResult result)
    {
        builder.AppendLine();
        builder.Append("Discovered ").Append(result.ObjectsDiscovered)
            .Append(", scanned ").Append(result.ObjectsScanned)
            .Append(", observations ").Append(result.Observations.Count)
            .Append(", errors ").Append(result.Errors.Count)
            .AppendLine(".");
    }

    internal static string Version
        => Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";
}
