using Stratus.Sift.Cli;

namespace Stratus.Sift.Cli.Tests;

public sealed class ProgramTests
{
    [Fact]
    public async Task RunAsync_HelpSucceeds()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await Program.RunAsync(["--help"], output, error, CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Contains("sift scan", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task RunAsync_MissingTargetFailsWithoutStackTrace()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var missingPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

        var exitCode = await Program.RunAsync(["scan", missingPath], output, error, CancellationToken.None);

        Assert.Equal(ExitCodes.Failed, exitCode);
        Assert.Contains("does not exist", error.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(" at ", error.ToString(), StringComparison.Ordinal);
    }
}
