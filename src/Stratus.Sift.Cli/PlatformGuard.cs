using System.Runtime.InteropServices;

namespace Stratus.Sift.Cli;

internal enum SiftPlatform
{
    Windows,
    Linux,
    MacOS,
    Unsupported,
}

internal static class PlatformGuard
{
    internal static void EnsureSupported(string targetPath)
        => EnsureSupported(CurrentPlatform, RuntimeInformation.ProcessArchitecture, targetPath);

    internal static void EnsureSupported(
        SiftPlatform platform,
        Architecture architecture,
        string targetPath)
    {
        if (platform == SiftPlatform.Unsupported)
        {
            throw new PlatformNotSupportedException(
                "Sift supports Windows, Linux and macOS only.");
        }

        if (architecture is not Architecture.X64 and not Architecture.Arm64)
        {
            throw new PlatformNotSupportedException(
                "Sift supports x64 and Arm64 processors only.");
        }

        EnsurePathSupported(platform, targetPath);
    }

    internal static void EnsurePathSupported(string path)
        => EnsurePathSupported(CurrentPlatform, path);

    internal static void EnsurePathSupported(SiftPlatform platform, string path)
    {
        if (platform != SiftPlatform.Windows && LooksLikeUncPath(path))
        {
            throw new PlatformNotSupportedException(
                "UNC paths are supported on Windows only. Mount the share, then scan its local path.");
        }

        if (platform != SiftPlatform.Windows && LooksLikeWindowsDrivePath(path))
        {
            throw new PlatformNotSupportedException(
                "Windows drive paths are supported on Windows only. Use a local or mounted path.");
        }
    }

    private static SiftPlatform CurrentPlatform
        => OperatingSystem.IsWindows() ? SiftPlatform.Windows
            : OperatingSystem.IsLinux() ? SiftPlatform.Linux
            : OperatingSystem.IsMacOS() ? SiftPlatform.MacOS
            : SiftPlatform.Unsupported;

    private static bool LooksLikeUncPath(string path)
        => path.StartsWith("\\\\", StringComparison.Ordinal)
            || path.StartsWith("//", StringComparison.Ordinal);

    private static bool LooksLikeWindowsDrivePath(string path)
        => path.Length >= 3
            && char.IsAsciiLetter(path[0])
            && path[1] == ':'
            && path[2] is '\\' or '/';
}
