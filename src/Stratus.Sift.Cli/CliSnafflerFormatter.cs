using System.Security.Principal;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli;

internal sealed class CliSnafflerFormatter
{
    private readonly string _hostString;

    internal CliSnafflerFormatter(string? hostString = null)
    {
        _hostString = string.IsNullOrWhiteSpace(hostString) ? BuildHostString() : hostString;
    }

    internal IReadOnlyList<CliBannerLine> GetBanner()
    {
        return
        [
            new CliBannerLine(@" .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..   ", ConsoleColor.Red),
            new CliBannerLine(@";;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;  ", ConsoleColor.DarkYellow),
            new CliBannerLine(@"'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['  ", ConsoleColor.Yellow),
            new CliBannerLine(@"  '''    $ $$$ 'Y$c$$c$$$cc$$$c`$$$'`` `$$$'`` $$'     $$""""   $$$$$$c    ", ConsoleColor.Green),
            new CliBannerLine(@" 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,", ConsoleColor.Blue),
            new CliBannerLine(@"  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W' ", ConsoleColor.DarkMagenta),
            new CliBannerLine(@"                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler  ", ConsoleColor.White),
        ];
    }

    internal CliRenderedLine FormatInfo(string message, DateTimeOffset? timestampUtc = null)
    {
        return FormatMessage(CliSnafflerLogKind.Info, message, timestampUtc);
    }

    internal CliRenderedLine FormatError(string message, DateTimeOffset? timestampUtc = null)
    {
        return FormatMessage(CliSnafflerLogKind.Error, message, timestampUtc);
    }

    internal CliRenderedLine FormatShareDiscovery(string path, string? access, string? comment, DateTimeOffset? timestampUtc = null)
    {
        var normalizedPath = NormalizePath(path);
        return FormatShareLikeResult(
            CliSnafflerLogKind.Share,
            "Green",
            normalizedPath,
            string.IsNullOrWhiteSpace(access) ? "R" : access,
            string.IsNullOrWhiteSpace(comment) ? string.Empty : comment!,
            timestampUtc);
    }

    internal CliRenderedLine FormatDirectoryDiscovery(string path, DateTimeOffset? timestampUtc = null)
    {
        return FormatDirectoryResult("Green", NormalizePath(path), timestampUtc ?? DateTimeOffset.UtcNow);
    }

    internal CliRenderedLine FormatDriveDiscovery(string name, string id, string driveType, string? webUrl, DateTimeOffset? timestampUtc = null)
    {
        var summary = string.IsNullOrWhiteSpace(webUrl)
            ? $"Discovered drive: {name} ({id}) [{driveType}]"
            : $"Discovered drive: {name} ({id}) [{driveType}] - {webUrl}";
        return FormatInfo(summary, timestampUtc);
    }

    internal CliRenderedLine FormatFinding(ScanFinding finding, string resourcePath, CliFindingDisplayContext? context = null, DateTimeOffset? timestampUtc = null)
    {
        var kind = InferResultKind(resourcePath, context);
        var triage = GetTriage(finding);
        var timestamp = timestampUtc ?? DateTimeOffset.UtcNow;

        return kind switch
        {
            CliSnafflerResultKind.Share => FormatShareLikeResult(
                CliSnafflerLogKind.Share,
                triage.Label,
                NormalizePath(resourcePath),
                string.IsNullOrWhiteSpace(context?.Access) ? "R" : context.Access!,
                GetShareComment(finding, context),
                timestamp),
            CliSnafflerResultKind.Directory => FormatDirectoryResult(
                triage.Label,
                NormalizePath(resourcePath),
                timestamp),
            _ => FormatFileResult(finding, resourcePath, context, triage, timestamp),
        };
    }

    private CliRenderedLine FormatMessage(CliSnafflerLogKind kind, string message, DateTimeOffset? timestampUtc)
    {
        var segments = CreatePrefix(kind, timestampUtc ?? DateTimeOffset.UtcNow);
        segments.Add(new CliStyledSegment(NormalizeInline(message)));
        return new CliRenderedLine(CliConsoleFormat.ConcatenateSegments(segments), segments);
    }

    private CliRenderedLine FormatShareLikeResult(
        CliSnafflerLogKind kind,
        string triageLabel,
        string sharePath,
        string access,
        string comment,
        DateTimeOffset? timestampUtc)
    {
        var segments = CreatePrefix(kind, timestampUtc ?? DateTimeOffset.UtcNow);
        segments.Add(CreateTriageSegment(triageLabel));
        segments.Add(new CliStyledSegment($"<{sharePath}>", ConsoleColor.Cyan));
        segments.Add(new CliStyledSegment($"({NormalizeInline(access)})", ConsoleColor.DarkMagenta));
        if (!string.IsNullOrWhiteSpace(comment))
        {
            segments.Add(new CliStyledSegment(" "));
            segments.Add(new CliStyledSegment(NormalizeInline(comment)));
        }

        return new CliRenderedLine(CliConsoleFormat.ConcatenateSegments(segments), segments);
    }

    private CliRenderedLine FormatDirectoryResult(string triageLabel, string directoryPath, DateTimeOffset timestampUtc)
    {
        var segments = CreatePrefix(CliSnafflerLogKind.Directory, timestampUtc);
        segments.Add(CreateTriageSegment(triageLabel));
        segments.Add(new CliStyledSegment($"({directoryPath})", ConsoleColor.DarkMagenta));
        return new CliRenderedLine(CliConsoleFormat.ConcatenateSegments(segments), segments);
    }

    private CliRenderedLine FormatFileResult(
        ScanFinding finding,
        string resourcePath,
        CliFindingDisplayContext? context,
        CliTriage triage,
        DateTimeOffset timestampUtc)
    {
        var normalizedPath = NormalizePath(resourcePath);
        var matchedRule = NormalizeInline(string.IsNullOrWhiteSpace(finding.ClassifierName) ? finding.RuleName : finding.ClassifierName);
        var access = string.IsNullOrWhiteSpace(context?.Access) ? "R" : context.Access!;
        var matchedValue = GetMatchedValue(finding, normalizedPath);
        var matchContext = GetMatchContext(finding);
        var fileStat = ResolveFileStat(normalizedPath, context);

        var detail = $"<{matchedRule}|{access}|{matchedValue}|{FormatFileSize(fileStat.Size)}|{FormatTimestamp(fileStat.ModifiedUtc)}>";
        var segments = CreatePrefix(CliSnafflerLogKind.File, timestampUtc);
        segments.Add(CreateTriageSegment(triage.Label));
        segments.Add(new CliStyledSegment(detail, ConsoleColor.Cyan));
        segments.Add(new CliStyledSegment($"({normalizedPath})", ConsoleColor.DarkMagenta));
        if (!string.IsNullOrWhiteSpace(matchContext))
        {
            segments.Add(new CliStyledSegment(" "));
            segments.Add(new CliStyledSegment(matchContext));
        }

        return new CliRenderedLine(CliConsoleFormat.ConcatenateSegments(segments), segments);
    }

    private List<CliStyledSegment> CreatePrefix(CliSnafflerLogKind kind, DateTimeOffset timestampUtc)
    {
        var segments = new List<CliStyledSegment>
        {
            new($"{_hostString} "),
            new($"{FormatTimestamp(timestampUtc.UtcDateTime)} ", ConsoleColor.DarkGray),
        };

        var tag = kind switch
        {
            CliSnafflerLogKind.File => ("[File]", ConsoleColor.Green, true),
            CliSnafflerLogKind.Share => ("[Share]", ConsoleColor.Yellow, true),
            CliSnafflerLogKind.Error => ("[Error]", ConsoleColor.Magenta, true),
            CliSnafflerLogKind.Fatal => ("[Fatal]", ConsoleColor.Red, true),
            CliSnafflerLogKind.Trace => ("[Trace]", ConsoleColor.DarkGray, true),
            CliSnafflerLogKind.Debug => ("[Degub]", ConsoleColor.Gray, true),
            CliSnafflerLogKind.Info => ("[Info]", ConsoleColor.White, true),
            CliSnafflerLogKind.Directory => ("[Dir]", (ConsoleColor?)null, false),
            _ => ("[Info]", ConsoleColor.White, true),
        };

        segments.Add(tag.Item3
            ? new CliStyledSegment($"{tag.Item1} ", tag.Item2)
            : new CliStyledSegment($"{tag.Item1} "));
        return segments;
    }

    private static CliStyledSegment CreateTriageSegment(string triageLabel)
    {
        var foreground = triageLabel switch
        {
            "Red" => ConsoleColor.DarkRed,
            "Yellow" => ConsoleColor.DarkYellow,
            "Green" => ConsoleColor.DarkGreen,
            _ => ConsoleColor.Black,
        };

        return new CliStyledSegment($"{{{triageLabel}}}", foreground, ConsoleColor.White);
    }

    private static CliTriage GetTriage(ScanFinding finding)
    {
        if (finding.IsReportOnly)
        {
            return new CliTriage("Black");
        }

        return finding.Severity switch
        {
            Severity.Critical => new CliTriage("Red"),
            Severity.High => new CliTriage("Red"),
            Severity.Medium => new CliTriage("Yellow"),
            _ => new CliTriage("Green"),
        };
    }

    private static CliSnafflerResultKind InferResultKind(string resourcePath, CliFindingDisplayContext? context)
    {
        if (context != null)
        {
            return context.Kind;
        }

        var normalizedPath = NormalizePath(resourcePath);
        if (IsUncShareRoot(normalizedPath))
        {
            return CliSnafflerResultKind.Share;
        }

        if (resourcePath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal) ||
            resourcePath.EndsWith(Path.AltDirectorySeparatorChar.ToString(), StringComparison.Ordinal))
        {
            return CliSnafflerResultKind.Directory;
        }

        if (Directory.Exists(normalizedPath))
        {
            return CliSnafflerResultKind.Directory;
        }

        return CliSnafflerResultKind.File;
    }

    private static bool IsUncShareRoot(string path)
    {
        if (!path.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return false;
        }

        var trimmed = path.TrimEnd('\\', '/');
        var segments = trimmed.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return segments.Length == 2;
    }

    private static string GetShareComment(ScanFinding finding, CliFindingDisplayContext? context)
    {
        if (!string.IsNullOrWhiteSpace(context?.Comment))
        {
            return NormalizeInline(context.Comment);
        }

        return string.Empty;
    }

    private static string GetMatchedValue(ScanFinding finding, string normalizedPath)
    {
        var displayValue = CliFindingFormatter.ExtractDisplayMatchValue(finding, normalizedPath);
        if (!string.IsNullOrWhiteSpace(displayValue))
        {
            return NormalizeInline(displayValue);
        }

        var pathSegment = Path.GetFileName(normalizedPath.TrimEnd('\\', '/'));
        if (!string.IsNullOrWhiteSpace(pathSegment))
        {
            return NormalizeInline(pathSegment);
        }

        return NormalizeInline(string.IsNullOrWhiteSpace(finding.ClassifierName) ? finding.RuleName : finding.ClassifierName);
    }

    private static string GetMatchContext(ScanFinding finding)
    {
        if (CliFindingFormatter.IsMetadataFinding(finding))
        {
            return string.Empty;
        }

        return (finding.Snippet ?? string.Empty)
            .Replace("\r\n", "\\n", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal)
            .Replace("\r", "\\n", StringComparison.Ordinal)
            .Trim();
    }

    private static CliFileStat ResolveFileStat(string path, CliFindingDisplayContext? context)
    {
        if (context?.Size.HasValue == true || context?.ModifiedUtc.HasValue == true)
        {
            return new CliFileStat(context?.Size, context?.ModifiedUtc);
        }

        try
        {
            if (File.Exists(path))
            {
                var info = new FileInfo(path);
                return new CliFileStat(info.Length, info.LastWriteTimeUtc);
            }
        }
        catch
        {
        }

        return new CliFileStat(null, null);
    }

    private static string FormatFileSize(long? size)
    {
        if (!size.HasValue)
        {
            return "?";
        }

        if (size.Value == 0)
        {
            return "0B";
        }

        string[] suffixes = ["B", "kB", "MB", "GB", "TB", "PB", "EB"];
        var bytes = Math.Abs(size.Value);
        var place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
        var num = Math.Round(bytes / Math.Pow(1024, place), 1);
        return (Math.Sign(size.Value) * num) + suffixes[place];
    }

    private static string FormatTimestamp(DateTime? timestampUtc)
    {
        return timestampUtc.HasValue ? timestampUtc.Value.ToUniversalTime().ToString("u") : "?";
    }

    private static string NormalizeInline(string? value)
    {
        return (value ?? string.Empty)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Trim();
    }

    private static string NormalizePath(string path)
    {
        var normalized = NormalizeInline(path);
        while ((normalized.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal) ||
                normalized.EndsWith(Path.AltDirectorySeparatorChar.ToString(), StringComparison.Ordinal)) &&
               !IsDriveRoot(normalized))
        {
            normalized = normalized[..^1];
        }

        return normalized;
    }

    private static bool IsDriveRoot(string path)
    {
        return path.Length == 3 &&
               char.IsLetter(path[0]) &&
               path[1] == ':' &&
               (path[2] == Path.DirectorySeparatorChar || path[2] == Path.AltDirectorySeparatorChar);
    }

    private static string BuildHostString()
    {
        var currentUser = Environment.UserName;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                currentUser = WindowsIdentity.GetCurrent().Name;
            }
        }
        catch
        {
        }

        return $"[{currentUser}@{Environment.MachineName}]";
    }

    internal sealed record CliBannerLine(string Text, ConsoleColor Color);
    internal sealed record CliRenderedLine(string PlainText, IReadOnlyList<CliStyledSegment> Segments);
    internal sealed record CliFindingDisplayContext(CliSnafflerResultKind Kind, long? Size = null, DateTime? ModifiedUtc = null, string? Access = null, string? Comment = null);

    internal enum CliSnafflerResultKind
    {
        File,
        Directory,
        Share
    }

    private enum CliSnafflerLogKind
    {
        Trace,
        Debug,
        Info,
        File,
        Directory,
        Share,
        Error,
        Fatal
    }

    private sealed record CliTriage(string Label);
    private sealed record CliFileStat(long? Size, DateTime? ModifiedUtc);
}
