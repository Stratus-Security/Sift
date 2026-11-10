using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli.Tests;

public sealed class IgnoreRuleReliabilityTests
{
    [Theory]
    [InlineData(@"\\server\Data\資料*", @"\\server.example.test\Data\資料", true)]
    [InlineData(@"\\server.example.test\Data\資料*", @"\\server\Data\資料", true)]
    [InlineData(@"\\SERVER.EXAMPLE.TEST\Data\資料", @"\\server\Data\資料", true)]
    [InlineData(@"\\server\Data\資料", @"\\server.example.test\Data\資料", true)]
    [InlineData(@"\\server.example.test.\Data\資料*", @"\\server.example.test\Data\資料", true)]
    [InlineData(@"//server/Data/資料*", @"\\server.example.test\Data\資料", true)]
    [InlineData(@"\\server\Data\資料*", @"\\?\UNC\server.example.test\Data\資料", true)]
    [InlineData(@"\\?\UNC\server.example.test\Data\資料*", @"\\server\Data\資料", true)]
    [InlineData(@"\\server.*\Data\資料*", @"\\server.example.test\Data\資料", true)]
    [InlineData(@"\\server.one.test\Data\資料*", @"\\server.two.test\Data\資料", false)]
    [InlineData(@"\\server\Data\資料*", @"\\server2.example.test\Data\資料", false)]
    [InlineData(@"\\server\Data\資料*", @"\\server.example.test\Other\資料", false)]
    [InlineData(@"\\server\Data\資料*", @"\\server.example.test\Data\Other", false)]
    [InlineData(@"\\192\Data\資料*", @"\\192.0.2.1\Data\資料", false)]
    [InlineData(@"\\2001-db8--1\Data\資料*", @"\\2001-db8--1.ipv6-literal.net\Data\資料", false)]
    public void UncDirectoryIgnores_TolerateOptionalDomainWithoutChangingShareOrHost(
        string pattern, string directory, bool expected)
    {
        var rules = new[] { new IgnoreRule { Pattern = pattern, MatchTarget = RuleTarget.DirectoryPath } };
        Assert.Equal(expected, IgnoreRuleEvaluator.ShouldPruneDirectory(directory, rules));
        Assert.Equal(expected, IgnoreRuleEvaluator.ShouldIgnore(directory + @"\child\file.txt", rules));
    }

    [Theory]
    [InlineData(RuleTarget.DirectoryPath, "*ガイド*", @"\\server\Data\カ\u3099イド")]
    [InlineData(RuleTarget.DirectoryName, "ガイド", @"\\server\Data\カ\u3099イド")]
    [InlineData(RuleTarget.DirectoryPath, "*カ\u3099イド*", @"\\server\Data\ガイド")]
    [InlineData(RuleTarget.FileName, "カ\u3099イド.txt", @"\\server\Data\ガイド.txt")]
    [InlineData(RuleTarget.FileExtension, ".カ\u3099", @"\\server\Data\file.ガ")]
    public void IgnoreRules_MatchCanonicallyEquivalentJapaneseText(RuleTarget target, string pattern, string path)
    {
        // Verbatim UNC literals keep "\u3099" as text; expand it to a combining dakuten.
        path = path.Replace(@"\u3099", "\u3099");
        var rules = new[] { new IgnoreRule { Pattern = pattern, MatchTarget = target } };
        Assert.True(IgnoreRuleEvaluator.ShouldIgnore(path, rules));
        if (target is RuleTarget.DirectoryPath or RuleTarget.DirectoryName)
            Assert.True(IgnoreRuleEvaluator.ShouldPruneDirectory(path, rules));
    }

    [Fact]
    public void UnicodeNormalization_DoesNotConflateHalfWidthFolderNames()
    {
        var rules = new[] { new IgnoreRule { Pattern = "*ガイド*", MatchTarget = RuleTarget.DirectoryPath } };
        Assert.False(IgnoreRuleEvaluator.ShouldPruneDirectory(@"\\server\Data\ｶﾞｲﾄﾞ", rules));
    }

    [Fact]
    public async Task ShortHostIgnore_PrunesMatchingFolderOnFqdnSmbDrive()
    {
        var rules = new[] { new IgnoreRule { Pattern = @"\\server\Data\資料*", MatchTarget = RuleTarget.DirectoryPath } };
        using var drive = new SmbKerberosDrive(
            new SmbKerberosConnection(System.Net.IPAddress.Loopback, "server.example.test", null, null,
                SmbAuthenticationProtocol.Ntlm, false),
            "Data", path => IgnoreRuleEvaluator.ShouldPruneDirectory(path, rules), null);
        var listed = new List<string>();
        await drive.ProcessDirectoriesAsync(path =>
        {
            listed.Add(path);
            return path.Length == 0
                ? [new SMBLibrary.FileDirectoryInformation { FileName = "資料", FileAttributes = SMBLibrary.FileAttributes.Directory }]
                : throw new InvalidOperationException("An ignored folder was entered.");
        }, null, _ => Task.CompletedTask);
        Assert.Equal([""], listed);
    }
}
