using Stratus.Sift.Cli;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli.Tests;

public sealed class CliFindingFormatterTests
{
    [Theory]
    [InlineData("Alpha*Beta42", "Alpha is a heading. password=Alpha*Beta42 done", "Alpha is a heading. password=[[Alpha*Beta42]] done")]
    [InlineData("ab****", "ab is a heading. password=ab**** done", "ab is a heading. password=[[ab****]] done")]
    [InlineData("Secret42", "secret42 is an example. password=Secret42", "secret42 is an example. password=[[Secret42]]")]
    [InlineData("sk********", "task backlog TOKEN=sk-prod-abcdefghijklmnopqrstuvwxyz123456 END", "task backlog TOKEN=[[sk-prod-abcdefghijklmnopqrstuvwxyz123456]] END")]
    [InlineData("sk********", "first=sk-test second=sk-real", "first=sk-test second=sk-real")]
    [InlineData("ab*cd", "ab is a heading. password=different", "ab is a heading. password=different")]
    [InlineData("missing", "password=different with surrounding context", "password=different with surrounding context")]
    [InlineData("", "password=different with surrounding context", "password=different with surrounding context")]
    public void FormatFindingEvidence_HighlightsOnlyALocatedMatch(string value, string snippet, string expected)
    {
        var finding = new ScanFinding { RedactedValue = value, Snippet = snippet };

        Assert.Equal(expected, CliFindingFormatter.FormatFindingEvidence(finding, "/synthetic/settings.txt"));
    }

    [Fact]
    public void ExtractDisplayMatchValue_PreservesLiteralAsterisksForLlmValidation()
    {
        var finding = new ScanFinding
        {
            RedactedValue = "Alpha*Beta42",
            Snippet = "Alpha is a heading. password=Alpha*Beta42 done"
        };

        Assert.Equal("Alpha*Beta42", CliFindingFormatter.ExtractDisplayMatchValue(finding, "/synthetic/settings.txt"));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(500)]
    [InlineData(0)]
    public void FormatFindingEvidence_InvalidSavedOffsetFallsBackToTheExactMatch(int offset)
    {
        var finding = new ScanFinding { RedactedValue = "secret", Snippet = "password=secret", SnippetMatchStart = offset };

        Assert.Equal("password=[[secret]]", CliFindingFormatter.FormatFindingEvidence(finding, "/synthetic/settings.txt"));
    }
}
