using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Stratus.Sift.Core.Enums;

namespace Stratus.Sift.Cli;

internal static partial class CliConsoleFormat
{
    private const int StdInputHandle = -10;
    private const int StdOutputHandle = -11;
    private const uint EnableVirtualTerminalProcessing = 0x0004;
    [GeneratedRegex(@"\u001B\[[0-9;]*[A-Za-z]", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex AnsiRegex();

    internal static bool SupportsAnsi { get; } = DetectAnsiSupport();

    internal static string? GetAnsiColorCode(ConsoleColor color)
    {
        return GetAnsiSequence(color, null);
    }

    internal static void WriteStyledLine(IReadOnlyList<CliStyledSegment> segments)
    {
        if (segments.Count == 0)
        {
            Console.WriteLine();
            return;
        }

        if (SupportsAnsi)
        {
            foreach (var segment in segments)
            {
                var sequence = GetAnsiSequence(segment.Foreground, segment.Background);
                if (!string.IsNullOrEmpty(sequence))
                {
                    Console.Write(sequence);
                }

                Console.Write(segment.Text);
                if (!string.IsNullOrEmpty(sequence))
                {
                    Console.Write("\u001b[0m");
                }
            }

            Console.WriteLine();
            return;
        }

        var originalForeground = Console.ForegroundColor;
        var originalBackground = Console.BackgroundColor;
        foreach (var segment in segments)
        {
            if (segment.Foreground.HasValue)
            {
                Console.ForegroundColor = segment.Foreground.Value;
            }

            if (segment.Background.HasValue)
            {
                Console.BackgroundColor = segment.Background.Value;
            }

            Console.Write(segment.Text);
            Console.ForegroundColor = originalForeground;
            Console.BackgroundColor = originalBackground;
        }

        Console.WriteLine();
    }

    internal static string ConcatenateSegments(IReadOnlyList<CliStyledSegment> segments)
    {
        var builder = new StringBuilder();
        foreach (var segment in segments)
        {
            builder.Append(segment.Text);
        }

        return builder.ToString();
    }

    internal static ConsoleColor GetRiskColor(Severity severity)
    {
        return severity switch
        {
            Severity.Critical => ConsoleColor.Red,
            Severity.High => ConsoleColor.Magenta,
            Severity.Medium => ConsoleColor.Yellow,
            Severity.Low => ConsoleColor.Cyan,
            Severity.Info => ConsoleColor.DarkGray,
            Severity.Informational => ConsoleColor.DarkGray,
            _ => ConsoleColor.Green
        };
    }

    internal static string NormalizeEvidenceText(string? value)
    {
        return (value ?? string.Empty)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Trim();
    }

    internal static string ApplyHighlight(string value, int start, int length)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        var safeStart = Math.Max(0, Math.Min(start, value.Length));
        var safeLength = Math.Max(0, Math.Min(length, value.Length - safeStart));
        if (safeLength == 0)
        {
            return value;
        }

        var before = value[..safeStart];
        var match = value.Substring(safeStart, safeLength);
        var after = value[(safeStart + safeLength)..];

        if (SupportsAnsi)
        {
            return $"{before}\u001b[93m{match}\u001b[0m{after}";
        }

        return $"{before}[[{match}]]{after}";
    }

    internal static string StripAnsi(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return AnsiRegex().Replace(value, string.Empty)
            .Replace("\r", string.Empty, StringComparison.Ordinal);
    }

    internal static void DrainBufferedInput()
    {
        if (Console.IsInputRedirected)
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            TryFlushWindowsConsoleInput();
            return;
        }

        try
        {
            while (Console.KeyAvailable)
            {
                Console.ReadKey(intercept: true);
            }
        }
        catch
        {
        }
    }

    private static bool DetectAnsiSupport()
    {
        if (Console.IsOutputRedirected ||
            !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("NO_COLOR")))
        {
            return false;
        }

        if (!OperatingSystem.IsWindows())
        {
            var term = Environment.GetEnvironmentVariable("TERM");
            if (string.IsNullOrWhiteSpace(term) ||
                string.Equals(term, "dumb", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }

        if (!TryEnableWindowsVirtualTerminal())
        {
            return false;
        }

        return true;
    }

    private static bool TryEnableWindowsVirtualTerminal()
    {
        try
        {
            var handle = GetStdHandle(StdOutputHandle);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                return false;
            }

            if (!GetConsoleMode(handle, out var mode))
            {
                return false;
            }

            if ((mode & EnableVirtualTerminalProcessing) != 0)
            {
                return true;
            }

            return SetConsoleMode(handle, mode | EnableVirtualTerminalProcessing);
        }
        catch
        {
            return false;
        }
    }

    private static void TryFlushWindowsConsoleInput()
    {
        try
        {
            var handle = GetStdHandle(StdInputHandle);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                return;
            }

            FlushConsoleInputBuffer(handle);
        }
        catch
        {
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushConsoleInputBuffer(IntPtr hConsoleInput);

    private static string? GetAnsiSequence(ConsoleColor? foreground, ConsoleColor? background)
    {
        if (!SupportsAnsi)
        {
            return null;
        }

        var codes = new List<string>(2);
        var foregroundCode = foreground.HasValue ? GetAnsiColorNumber(foreground.Value, background: false) : null;
        var backgroundCode = background.HasValue ? GetAnsiColorNumber(background.Value, background: true) : null;
        if (foregroundCode != null)
        {
            codes.Add(foregroundCode);
        }

        if (backgroundCode != null)
        {
            codes.Add(backgroundCode);
        }

        return codes.Count == 0 ? null : $"\u001b[{string.Join(';', codes)}m";
    }

    private static string? GetAnsiColorNumber(ConsoleColor color, bool background)
    {
        return (color, background) switch
        {
            (ConsoleColor.Black, false) => "30",
            (ConsoleColor.DarkRed, false) => "31",
            (ConsoleColor.Red, false) => "91",
            (ConsoleColor.DarkGreen, false) => "32",
            (ConsoleColor.Green, false) => "92",
            (ConsoleColor.DarkYellow, false) => "33",
            (ConsoleColor.Yellow, false) => "93",
            (ConsoleColor.DarkBlue, false) => "34",
            (ConsoleColor.Blue, false) => "94",
            (ConsoleColor.DarkMagenta, false) => "35",
            (ConsoleColor.Magenta, false) => "95",
            (ConsoleColor.DarkCyan, false) => "36",
            (ConsoleColor.Cyan, false) => "96",
            (ConsoleColor.Gray, false) => "37",
            (ConsoleColor.White, false) => "97",
            (ConsoleColor.DarkGray, false) => "90",
            (ConsoleColor.Black, true) => "40",
            (ConsoleColor.DarkRed, true) => "41",
            (ConsoleColor.Red, true) => "101",
            (ConsoleColor.DarkGreen, true) => "42",
            (ConsoleColor.Green, true) => "102",
            (ConsoleColor.DarkYellow, true) => "43",
            (ConsoleColor.Yellow, true) => "103",
            (ConsoleColor.DarkBlue, true) => "44",
            (ConsoleColor.Blue, true) => "104",
            (ConsoleColor.DarkMagenta, true) => "45",
            (ConsoleColor.Magenta, true) => "105",
            (ConsoleColor.DarkCyan, true) => "46",
            (ConsoleColor.Cyan, true) => "106",
            (ConsoleColor.Gray, true) => "47",
            (ConsoleColor.White, true) => "107",
            (ConsoleColor.DarkGray, true) => "100",
            _ => null
        };
    }
}

internal readonly record struct CliStyledSegment(string Text, ConsoleColor? Foreground = null, ConsoleColor? Background = null);
