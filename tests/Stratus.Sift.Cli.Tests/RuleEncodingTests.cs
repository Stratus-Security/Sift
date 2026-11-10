using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli.Tests;

public sealed class RuleEncodingTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "sift-rules-" + Guid.NewGuid().ToString("N"));
    private const string Json = """
        [
          { "Pattern": "*資料*", "MatchTarget": "DirectoryPath", "IsEnabled": true },
          { "Name": "日本語の検出", "Severity": "High",
            "Matches": [{ "Target": "Content", "IsLiteral": true, "Patterns": ["機密情報"], "IncludedExtensions": [".txt"] }] }
        ]
        """;

    public RuleEncodingTests() => Directory.CreateDirectory(_directory);

    [Theory]
    [InlineData("utf8")]
    [InlineData("utf8-bom")]
    [InlineData("utf16-le")]
    [InlineData("utf16-be")]
    [InlineData("utf32-le")]
    [InlineData("utf32-be")]
    public async Task UnicodeEncodings_PreserveJapaneseRules(string name)
    {
        Encoding encoding = name switch
        {
            "utf8" => new UTF8Encoding(false),
            "utf8-bom" => new UTF8Encoding(true),
            "utf16-le" => new UnicodeEncoding(false, true),
            "utf16-be" => new UnicodeEncoding(true, true),
            "utf32-le" => new UTF32Encoding(false, true),
            _ => new UTF32Encoding(true, true)
        };
        await File.WriteAllTextAsync(Path.Combine(_directory, "rules.json"), Json, encoding);
        var catalog = await CliRuleCatalogLoader.LoadAsync(_directory, NullLogger.Instance);
        Assert.Equal("*資料*", Assert.Single(catalog.IgnoreRules).Pattern);
        Assert.Equal("日本語の検出", Assert.Single(catalog.Classifiers).Name);
        Assert.True(IgnoreRuleEvaluator.ShouldPruneDirectory(@"\\server\Data\資料", catalog.IgnoreRules));
    }

    public static TheoryData<byte[]> InvalidEncodings => new()
    {
        // Shift-JIS "資料" within otherwise valid ASCII JSON.
        { [.. Encoding.ASCII.GetBytes("{\"Pattern\":\"*"), 0x8e, 0x91, 0x97, 0xbf,
            .. Encoding.ASCII.GetBytes("*\",\"MatchTarget\":\"DirectoryPath\"}")] },
        { [0xff, 0xfe, 0x00, 0xd8] }, // UTF-16 LE: unpaired high surrogate.
        { [0xfe, 0xff, 0xd8, 0x00] }, // UTF-16 BE: unpaired high surrogate.
        { [0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00] }, // Invalid UTF-32 LE scalar.
        { [0x00, 0x00, 0xfe, 0xff, 0x00, 0x11, 0x00, 0x00] }, // Invalid UTF-32 BE scalar.
        { [0xef, 0xbb, 0xbf, 0xe3, 0x81] } // Truncated UTF-8 sequence.
    };

    [Theory]
    [MemberData(nameof(InvalidEncodings))]
    public async Task InvalidEncoding_StopsLoadingInsteadOfReplacingCharactersOrFallingBack(byte[] bytes)
    {
        var path = Path.Combine(_directory, "broken.json");
        await File.WriteAllBytesAsync(path, bytes);
        var error = await Assert.ThrowsAsync<CliRuleLoadException>(
            () => CliRuleCatalogLoader.LoadAsync(_directory, NullLogger.Instance));
        Assert.Contains(path, error.Message);
        Assert.Contains("Save it as UTF-8", error.Message);
    }

    [Fact]
    public async Task InvalidJson_StopsLoadingInsteadOfOmittingCustomRules()
    {
        await File.WriteAllTextAsync(Path.Combine(_directory, "good.json"), Json);
        var broken = Path.Combine(_directory, "broken.json");
        await File.WriteAllTextAsync(broken, """{"Pattern":""");
        var error = await Assert.ThrowsAsync<CliRuleLoadException>(
            () => CliRuleCatalogLoader.LoadAsync(_directory, NullLogger.Instance));
        Assert.Contains(broken, error.Message);
    }

    [Fact]
    public async Task Utf16WithoutBom_IsRejectedWithConversionInstructions()
    {
        await File.WriteAllBytesAsync(Path.Combine(_directory, "rules.json"), Encoding.Unicode.GetBytes(Json));
        var error = await Assert.ThrowsAsync<CliRuleLoadException>(
            () => CliRuleCatalogLoader.LoadAsync(_directory, NullLogger.Instance));
        Assert.Contains("Save it as UTF-8", error.Message);
        Assert.Contains("BOM", error.Message);
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
