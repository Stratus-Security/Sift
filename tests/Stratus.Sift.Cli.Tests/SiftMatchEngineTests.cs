using System.Text;
using System.Text.RegularExpressions;
using Stratus.Sift.Core;

namespace Stratus.Sift.Cli.Tests;

public sealed class SiftMatchEngineTests
{
    [Fact]
    public void FindMatches_PreservesExactValueAndSkipsCompletedOverlap()
    {
        var pattern = new Regex("token-[a-z]+", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

        var result = SiftMatchEngine.FindMatches("token-first token-second", pattern, overlapLength: 11);

        var match = Assert.Single(result.Matches);
        Assert.Equal("token-second", match.Value);
        Assert.False(result.TimedOut);
    }

    [Fact]
    public void FindMatches_AppliesEntropyAndValidation()
    {
        var pattern = new Regex("secret=(?<value>[a-z0-9]+)", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

        var result = SiftMatchEngine.FindMatches(
            "secret=aaaaaaaa secret=a1b2c3d4",
            pattern,
            "value",
            minimumEntropy: 2,
            validator: candidate => candidate.Context.Contains("a1b2", StringComparison.Ordinal)
                ? SiftValidationResult.Valid(0.9)
                : SiftValidationResult.Invalid);

        var match = Assert.Single(result.Matches);
        Assert.Equal("a1b2c3d4", match.Value);
        Assert.Equal(0.9, match.Confidence);
    }

    [Fact]
    public void LooksBinary_AllowsUtf16TextAndRejectsBinaryData()
    {
        var text = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("password=review-me")).ToArray();

        Assert.False(SiftEvidence.LooksBinary(text));
        Assert.True(SiftEvidence.LooksBinary([0x00, 0x01, 0x02, 0x03, 0xff]));
    }
}
