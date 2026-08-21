using System.Globalization;

namespace Stratus.Sift.Cli;

internal enum OutputFormat
{
    Text,
    Json,
    Ndjson,
    Snaffler,
}

internal sealed record CliOptions(
    string Path,
    OutputFormat Format,
    string? OutputPath,
    bool ShowSecrets,
    bool EnumerateOnly,
    bool IncludeBinary,
    bool Recurse,
    int Parallelism,
    long MaximumFileSizeBytes,
    IReadOnlySet<string> Extensions,
    IReadOnlySet<string> ExcludedDirectoryNames);

internal sealed record CliParseResult(
    CliOptions? Options = null,
    string? Error = null,
    bool ShowHelp = false,
    bool ShowVersion = false);

internal static class CliArguments
{
    private static readonly string[] DefaultExtensions =
    [
        ".cfg", ".conf", ".config", ".csv", ".env", ".ini", ".json", ".log",
        ".md", ".properties", ".ps1", ".sh", ".sql", ".text", ".toml", ".txt",
        ".xml", ".yaml", ".yml",
    ];

    private static readonly string[] DefaultExcludedDirectories =
    [
        ".git", ".idea", ".svn", ".vs", ".vscode", "bin", "node_modules", "obj",
    ];

    internal const string HelpText = """
        Stratus Sift - focused filesystem content discovery

        Usage:
          stratus-sift scan <path> [options]

        Options:
          --format <text|json|ndjson|snaffler>  Output format (default: text)
          --output <path>                      Write output to a file
          --show-secrets                       Include matched values; redacted by default
          --enumerate-only                     List scope without reading content
          --include-binary                     Attempt to scan files containing binary bytes
          --no-recurse                         Scan only the target directory
          --parallelism <1-64>                 Concurrent file reads (default: processor-aware)
          --max-file-size-mb <1-1024>          Maximum file size (default: 10)
          --extensions <csv>                   Extensions to scan, for example .txt,.json,.env
          --exclude-dirs <csv>                 Directory names to skip
          --version                            Show the version
          -h, --help                           Show this help

        Paths may be local folders, files, mapped drives, or reachable UNC shares.
        """;

    internal static CliParseResult Parse(IReadOnlyList<string> args)
    {
        if (args.Count == 0 || args.Any(IsHelp))
        {
            return new CliParseResult(ShowHelp: true);
        }

        if (args.Count == 1 && args[0].Equals("--version", StringComparison.OrdinalIgnoreCase))
        {
            return new CliParseResult(ShowVersion: true);
        }

        if (!args[0].Equals("scan", StringComparison.OrdinalIgnoreCase))
        {
            return new CliParseResult(Error: "The first argument must be 'scan'.");
        }

        if (args.Count < 2 || args[1].StartsWith('-'))
        {
            return new CliParseResult(Error: "A file or directory path is required.");
        }

        var path = args[1];
        var format = OutputFormat.Text;
        string? outputPath = null;
        var showSecrets = false;
        var enumerateOnly = false;
        var includeBinary = false;
        var recurse = true;
        var parallelism = Math.Clamp(Environment.ProcessorCount, 1, 16);
        long maximumFileSizeBytes = 10 * 1024 * 1024;
        IReadOnlySet<string> extensions = NormalizeExtensions(DefaultExtensions);
        IReadOnlySet<string> excludedDirectories = NormalizeNames(DefaultExcludedDirectories);

        for (var index = 2; index < args.Count; index++)
        {
            var argument = args[index];
            switch (argument.ToLowerInvariant())
            {
                case "--format":
                    if (!TryReadValue(args, ref index, out var formatValue))
                    {
                        return new CliParseResult(Error: "--format requires a value.");
                    }

                    if (!Enum.TryParse<OutputFormat>(formatValue, ignoreCase: true, out format))
                    {
                        return new CliParseResult(Error: "--format must be text, json, ndjson, or snaffler.");
                    }
                    break;

                case "--output":
                    if (!TryReadValue(args, ref index, out outputPath))
                    {
                        return new CliParseResult(Error: "--output requires a path.");
                    }
                    break;

                case "--show-secrets":
                    showSecrets = true;
                    break;

                case "--enumerate-only":
                    enumerateOnly = true;
                    break;

                case "--include-binary":
                    includeBinary = true;
                    break;

                case "--no-recurse":
                    recurse = false;
                    break;

                case "--parallelism":
                    if (!TryReadValue(args, ref index, out var parallelismValue)
                        || !int.TryParse(parallelismValue, NumberStyles.None, CultureInfo.InvariantCulture, out parallelism)
                        || parallelism is < 1 or > 64)
                    {
                        return new CliParseResult(Error: "--parallelism must be an integer from 1 to 64.");
                    }
                    break;

                case "--max-file-size-mb":
                    if (!TryReadValue(args, ref index, out var maximumSizeValue)
                        || !long.TryParse(maximumSizeValue, NumberStyles.None, CultureInfo.InvariantCulture, out var maximumSizeMb)
                        || maximumSizeMb is < 1 or > 1024)
                    {
                        return new CliParseResult(Error: "--max-file-size-mb must be an integer from 1 to 1024.");
                    }

                    maximumFileSizeBytes = maximumSizeMb * 1024 * 1024;
                    break;

                case "--extensions":
                    if (!TryReadValue(args, ref index, out var extensionValue))
                    {
                        return new CliParseResult(Error: "--extensions requires a comma-separated value.");
                    }

                    extensions = NormalizeExtensions(SplitValues(extensionValue!));
                    if (extensions.Count == 0)
                    {
                        return new CliParseResult(Error: "--extensions must contain at least one extension.");
                    }
                    break;

                case "--exclude-dirs":
                    if (!TryReadValue(args, ref index, out var excludedValue))
                    {
                        return new CliParseResult(Error: "--exclude-dirs requires a comma-separated value.");
                    }

                    excludedDirectories = NormalizeNames(
                        DefaultExcludedDirectories.Concat(SplitValues(excludedValue!)));
                    break;

                default:
                    return new CliParseResult(Error: $"Unknown option: {argument}");
            }
        }

        return new CliParseResult(new CliOptions(
            path,
            format,
            outputPath,
            showSecrets,
            enumerateOnly,
            includeBinary,
            recurse,
            parallelism,
            maximumFileSizeBytes,
            extensions,
            excludedDirectories));
    }

    private static bool IsHelp(string value)
        => value is "-h" or "--help" or "/?";

    private static bool TryReadValue(IReadOnlyList<string> args, ref int index, out string? value)
    {
        value = null;
        if (index + 1 >= args.Count || args[index + 1].StartsWith('-'))
        {
            return false;
        }

        value = args[++index];
        return !string.IsNullOrWhiteSpace(value);
    }

    private static IEnumerable<string> SplitValues(string value)
        => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static IReadOnlySet<string> NormalizeExtensions(IEnumerable<string> values)
        => values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.StartsWith('.') ? value : $".{value}")
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static IReadOnlySet<string> NormalizeNames(IEnumerable<string> values)
        => values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
}
