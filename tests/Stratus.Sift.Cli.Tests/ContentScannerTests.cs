using System.Text.Json;
using Stratus.Sift.Cli;
using Stratus.Sift.Core;

namespace Stratus.Sift.Cli.Tests;

public sealed class ContentScannerTests
{
    [Fact]
    public async Task ScanAsync_DetectsAndIncludesMatchedValue()
    {
        using var directory = new TemporaryDirectory();
        var secret = string.Concat("sk", "-proj-", "abcdefghijklmnopqrstuvwx");
        await File.WriteAllTextAsync(Path.Combine(directory.Path, ".env"), $"OPENAI_API_KEY={secret}");

        var result = await ScanAsync(directory.Path);

        var observation = Assert.Single(result.Observations, item => item.RuleId == "openai-key");
        Assert.Equal(secret, observation.Value);
        Assert.Contains(secret, observation.Snippet, StringComparison.Ordinal);
        Assert.Equal(1, observation.LineNumber);
    }

    [Fact]
    public async Task ScanAsync_IncludesTokenInObservationAndSnippet()
    {
        using var directory = new TemporaryDirectory();
        var secret = string.Concat("gh", "p_", "abcdefghijklmnopqrstuvwxyz1234567890");
        await File.WriteAllTextAsync(Path.Combine(directory.Path, "settings.json"), secret);

        var result = await ScanAsync(directory.Path);

        var observation = Assert.Single(result.Observations, item => item.RuleId == "github-token");
        Assert.Equal(secret, observation.Value);
        Assert.Contains(secret, observation.Snippet, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanAsync_SkipsExcludedDirectoriesAndUnsupportedExtensions()
    {
        using var directory = new TemporaryDirectory();
        Directory.CreateDirectory(Path.Combine(directory.Path, ".git"));
        await File.WriteAllTextAsync(Path.Combine(directory.Path, ".git", "config"), "password=should-not-appear");
        await File.WriteAllTextAsync(Path.Combine(directory.Path, "image.png"), "password=should-not-appear");

        var result = await ScanAsync(directory.Path);

        Assert.Empty(result.Observations);
        Assert.Equal(0, result.ObjectsDiscovered);
    }

    [Fact]
    public async Task OutputWriter_JsonIncludesMatchedValue()
    {
        using var directory = new TemporaryDirectory();
        await File.WriteAllTextAsync(
            Path.Combine(directory.Path, "appsettings.json"),
            "password=long-password-value");
        var options = Options(directory.Path) with { Format = OutputFormat.Json };
        var result = await ScanAsync(directory.Path);
        using var writer = new StringWriter();

        await OutputWriter.WriteAsync(result, options, writer, CancellationToken.None);

        var output = writer.ToString();
        using var document = JsonDocument.Parse(output);
        Assert.Equal("2.0", document.RootElement.GetProperty("schemaVersion").GetString());
        Assert.Equal(
            "long-password-value",
            document.RootElement.GetProperty("observations")[0].GetProperty("value").GetString());
        Assert.Contains("long-password-value", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OutputWriter_TextIncludesFullValueWhenContextIsTruncated()
    {
        using var directory = new TemporaryDirectory();
        var secret = string.Concat("sk", "-proj-", new string('a', 80));
        await File.WriteAllTextAsync(
            Path.Combine(directory.Path, "long-line.txt"),
            string.Concat(new string('x', 300), " ", secret));
        var options = Options(directory.Path);
        var result = await ScanAsync(directory.Path);
        using var writer = new StringWriter();

        await OutputWriter.WriteAsync(result, options, writer, CancellationToken.None);

        Assert.Contains($"Value: {secret}", writer.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanAsync_EnumerationModeDoesNotReadContent()
    {
        using var directory = new TemporaryDirectory();
        await File.WriteAllTextAsync(Path.Combine(directory.Path, "secrets.txt"), "password=long-password-value");

        var result = await ScanAsync(directory.Path, enumerateOnly: true);

        Assert.Equal(1, result.ObjectsDiscovered);
        Assert.Equal(0, result.ObjectsScanned);
        Assert.Empty(result.Observations);
    }

    private static CliOptions Options(string path) => new(
        Path: path,
        Format: OutputFormat.Text,
        OutputPath: null,
        EnumerateOnly: false,
        IncludeBinary: false,
        Recurse: true,
        Parallelism: 2,
        MaximumFileSizeBytes: 10 * 1024 * 1024,
        Extensions: new HashSet<string>([".json", ".txt"], StringComparer.OrdinalIgnoreCase),
        ExcludedDirectoryNames: new HashSet<string>([".git"], StringComparer.OrdinalIgnoreCase));

    private static Task<SiftFileScanResult> ScanAsync(string path, bool enumerateOnly = false)
        => new SiftFileScanner().ScanAsync(
            path,
            new SiftFileScanOptions(
                EnumerateOnly: enumerateOnly,
                IncludeBinary: false,
                Recurse: true,
                Parallelism: 2,
                MaximumFileSizeBytes: 10 * 1024 * 1024,
                Extensions: new HashSet<string>([".json", ".txt"], StringComparer.OrdinalIgnoreCase),
                ExcludedDirectoryNames: new HashSet<string>([".git"], StringComparer.OrdinalIgnoreCase)),
            CancellationToken.None);

    private sealed class TemporaryDirectory : IDisposable
    {
        internal TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"stratus-sift-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        internal string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
