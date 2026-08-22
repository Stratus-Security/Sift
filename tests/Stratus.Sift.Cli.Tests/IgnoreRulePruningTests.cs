using Microsoft.Extensions.Logging.Abstractions;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.FileSystem;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Cli.Tests;

public class IgnoreRulePruningTests
{
    [Fact]
    public void ShouldPruneDirectory_ReturnsTrue_ForIgnoredDirectoryPath()
    {
        var ignoreRules = new List<IgnoreRule>
        {
            new()
            {
                Pattern = "*\\winsxs*",
                MatchTarget = RuleTarget.DirectoryPath,
                IsEnabled = true
            }
        };

        var shouldPrune = IgnoreRuleEvaluator.ShouldPruneDirectory(@"C:\Windows\WinSxS", ignoreRules);

        Assert.True(shouldPrune);
    }

    [Fact]
    public void EnumeratePath_SkipsIgnoredDirectorySubtree()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("n"));
        var includedDirectory = Path.Combine(root, "keep");
        var ignoredDirectory = Path.Combine(root, "skipme");

        Directory.CreateDirectory(includedDirectory);
        Directory.CreateDirectory(ignoredDirectory);
        File.WriteAllText(Path.Combine(includedDirectory, "included.txt"), "keep");
        File.WriteAllText(Path.Combine(ignoredDirectory, "ignored.txt"), "skip");

        var ignoreRules = new List<IgnoreRule>
        {
            new()
            {
                Pattern = "skipme",
                MatchTarget = RuleTarget.DirectoryName,
                IsEnabled = true
            }
        };

        try
        {
            var enumerator = new StandardFileSystemEnumerator(NullLogger<StandardFileSystemEnumerator>.Instance);
            PathFilter directoryFilter = path => IgnoreRuleEvaluator.ShouldPruneDirectory(path.ToString(), ignoreRules);

            var entries = enumerator
                .EnumeratePath(root, directoryFilter, includeAcls: false)
                .Select(entry => entry.Path)
                .ToList();

            Assert.Contains(entries, path => path.EndsWith(Path.Combine("keep", "included.txt"), StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(entries, path => path.Contains(Path.Combine("skipme"), StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
