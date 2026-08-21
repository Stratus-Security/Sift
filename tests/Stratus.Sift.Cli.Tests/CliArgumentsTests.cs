using Stratus.Sift.Cli;

namespace Stratus.Sift.Cli.Tests;

public sealed class CliArgumentsTests
{
    [Fact]
    public void Parse_AcceptsSafeDefaults()
    {
        var result = CliArguments.Parse(["scan", "."]);

        Assert.Null(result.Error);
        Assert.NotNull(result.Options);
        Assert.Equal(OutputFormat.Text, result.Options.Format);
        Assert.True(result.Options.Recurse);
        Assert.Equal(10 * 1024 * 1024, result.Options.MaximumFileSizeBytes);
        Assert.Contains(".json", result.Options.Extensions);
        Assert.Contains(".git", result.Options.ExcludedDirectoryNames);
    }

    [Fact]
    public void Parse_RejectsUnknownOptions()
    {
        var result = CliArguments.Parse(["scan", ".", "--colour", "purple"]);

        Assert.Equal("Unknown option: --colour", result.Error);
    }

    [Fact]
    public void Parse_DoesNotExposeAMaskingMode()
    {
        var result = CliArguments.Parse(["scan", ".", "--show-secrets"]);

        Assert.Equal("Unknown option: --show-secrets", result.Error);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65")]
    [InlineData("many")]
    public void Parse_RejectsInvalidParallelism(string value)
    {
        var result = CliArguments.Parse(["scan", ".", "--parallelism", value]);

        Assert.Contains("1 to 64", result.Error);
    }

    [Fact]
    public void Parse_NormalizesExtensions()
    {
        var result = CliArguments.Parse(["scan", ".", "--extensions", "txt,.ENV"]);

        Assert.Equal(2, result.Options!.Extensions.Count);
        Assert.Contains(".txt", result.Options.Extensions);
        Assert.Contains(".env", result.Options.Extensions);
    }
}
