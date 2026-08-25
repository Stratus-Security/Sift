namespace Stratus.Sift.Cli;

internal static class CliSiftBanner
{
    private static readonly BannerLine[] BannerLines =
    [
        new(@"  ____  _  __ _   ", ConsoleColor.Cyan),
        new(@" / ___|(_)/ _| |_ ", ConsoleColor.Cyan),
        new(@" \___ \| | |_| __|", ConsoleColor.Cyan),
        new(@"  ___) | |  _| |_ ", ConsoleColor.Cyan),
        new(@" |____/|_|_|  \__|", ConsoleColor.Cyan),
        new(@" www.stratussecurity.com", ConsoleColor.DarkGray),
    ];

    internal static IReadOnlyList<BannerLine> Lines => BannerLines;

    internal sealed record BannerLine(string Text, ConsoleColor Color);
}
