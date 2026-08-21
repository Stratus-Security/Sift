using System.Runtime.InteropServices;
using Stratus.Sift.Cli;

namespace Stratus.Sift.Cli.Tests;

public sealed class PlatformGuardTests
{
    [Theory]
    [InlineData((int)SiftPlatform.Windows, Architecture.X64, @"C:\Data")]
    [InlineData((int)SiftPlatform.Windows, Architecture.Arm64, @"\\server\share")]
    [InlineData((int)SiftPlatform.Linux, Architecture.X64, "/srv/data")]
    [InlineData((int)SiftPlatform.Linux, Architecture.Arm64, "/mnt/share")]
    [InlineData((int)SiftPlatform.MacOS, Architecture.X64, "/Volumes/Data")]
    [InlineData((int)SiftPlatform.MacOS, Architecture.Arm64, "/Volumes/Share")]
    public void EnsureSupported_AcceptsReleasePlatforms(
        int platform,
        Architecture architecture,
        string path)
        => PlatformGuard.EnsureSupported((SiftPlatform)platform, architecture, path);

    [Theory]
    [InlineData((int)SiftPlatform.Linux)]
    [InlineData((int)SiftPlatform.MacOS)]
    public void EnsureSupported_RejectsUncPathsOutsideWindows(int platform)
    {
        var exception = Assert.Throws<PlatformNotSupportedException>(
            () => PlatformGuard.EnsureSupported((SiftPlatform)platform, Architecture.X64, @"\\server\share"));

        Assert.Contains("Mount the share", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData((int)SiftPlatform.Linux)]
    [InlineData((int)SiftPlatform.MacOS)]
    public void EnsureSupported_RejectsWindowsDrivePathsOutsideWindows(int platform)
        => Assert.Throws<PlatformNotSupportedException>(
            () => PlatformGuard.EnsureSupported((SiftPlatform)platform, Architecture.X64, @"C:\Data"));

    [Theory]
    [InlineData(Architecture.X86)]
    [InlineData(Architecture.Arm)]
    [InlineData(Architecture.Wasm)]
    public void EnsureSupported_RejectsUnsupportedArchitectures(Architecture architecture)
        => Assert.Throws<PlatformNotSupportedException>(
            () => PlatformGuard.EnsureSupported(SiftPlatform.Windows, architecture, @"C:\Data"));

    [Fact]
    public void EnsureSupported_RejectsUnsupportedOperatingSystems()
        => Assert.Throws<PlatformNotSupportedException>(
            () => PlatformGuard.EnsureSupported(SiftPlatform.Unsupported, Architecture.X64, "/data"));
}
