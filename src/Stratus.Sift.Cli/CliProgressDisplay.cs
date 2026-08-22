using System.Diagnostics;
using System.Text;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli;

internal sealed class CliProgressDisplay : IAsyncDisposable
{
    private static readonly object ConsoleLock = new();

    private readonly Stopwatch _stopwatch = Stopwatch.StartNew();
    private readonly PeriodicTimer? _timer;
    private readonly CancellationTokenSource? _renderCts;
    private readonly Task? _renderTask;
    private readonly string _title;
    private readonly CliOutputStyle _style;
    private readonly CliOutputCapture? _outputCapture;
    private readonly CliSnafflerFormatter _snafflerFormatter = new();
    private readonly TimeSpan _statusRefreshInterval = TimeSpan.FromSeconds(1);
    private readonly TimeSpan _clockRefreshInterval = TimeSpan.FromSeconds(5);

    private string _phase = "Preparing";
    private string _currentDrive = string.Empty;
    private string _currentPath = string.Empty;
    private ThrottleNotice? _throttleNotice;
    private ThrottleNotificationHub? _throttleNotifications;
    private Action<ThrottleNotice>? _throttleUpdatedHandler;
    private string _lastRenderedStatusLine = string.Empty;
    private string _summaryTitle = "Scan complete";
    private long _filesDiscovered;
    private long _filesScanned;
    private long _findings;
    private long _errors;
    private int _totalDrives;
    private int _completedDrives;
    private bool _completed;
    private bool _statusDirty = true;
    private bool _interactivePromptActive;
    private DateTimeOffset _lastStatusRenderUtc = DateTimeOffset.MinValue;

    public CliProgressDisplay(string title, CliOutputOptions? outputOptions = null)
    {
        _title = title;
        _style = outputOptions?.Style ?? CliOutputStyle.Default;
        if (!string.IsNullOrWhiteSpace(outputOptions?.Path))
        {
            _outputCapture = new CliOutputCapture(
                outputOptions.Path!,
                outputOptions.Format,
                _style,
                title,
                outputOptions.Append);
        }

        if (!Console.IsInputRedirected)
        {
            _renderCts = new CancellationTokenSource();
            _timer = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
            _renderTask = Task.Run(() => RenderLoopAsync(_renderCts.Token));
        }

        WriteHeader();
        if (_style == CliOutputStyle.Default)
        {
            RenderStatusLine();
        }
    }

    public void SetPhase(string phase)
    {
        lock (ConsoleLock)
        {
            _phase = phase;
            MarkStatusDirtyUnsafe();
        }
    }

    public void AttachThrottleMonitor(ThrottleNotificationHub throttleNotifications)
    {
        lock (ConsoleLock)
        {
            _throttleNotifications = throttleNotifications;
            _throttleNotice = throttleNotifications.Latest;
            _throttleUpdatedHandler = notice =>
            {
                lock (ConsoleLock)
                {
                    _throttleNotice = notice;
                    MarkStatusDirtyUnsafe();
                }
            };

            throttleNotifications.Updated += _throttleUpdatedHandler;
            MarkStatusDirtyUnsafe();
        }
    }

    public void SetTotalDrives(int totalDrives)
    {
        lock (ConsoleLock)
        {
            _totalDrives = totalDrives;
            MarkStatusDirtyUnsafe();
        }
    }

    public void SetCurrentDrive(string driveName)
    {
        lock (ConsoleLock)
        {
            _currentDrive = driveName;
            _currentPath = string.Empty;
            MarkStatusDirtyUnsafe();
        }
    }

    public void SetCurrentPath(string path)
    {
        lock (ConsoleLock)
        {
            _currentPath = path;
            MarkStatusDirtyUnsafe();
        }
    }

    public void ClearCurrentPath()
    {
        lock (ConsoleLock)
        {
            _currentPath = string.Empty;
            MarkStatusDirtyUnsafe();
        }
    }

    public void MarkDriveCompleted()
    {
        Interlocked.Increment(ref _completedDrives);
    }

    public void IncrementFiles()
    {
        Interlocked.Increment(ref _filesScanned);
    }

    public void AddFilesDiscovered(int count)
    {
        Interlocked.Add(ref _filesDiscovered, count);
        lock (ConsoleLock)
        {
            MarkStatusDirtyUnsafe();
        }
    }

    public void AddFilesScanned(int count)
    {
        Interlocked.Add(ref _filesScanned, count);
        lock (ConsoleLock)
        {
            MarkStatusDirtyUnsafe();
        }
    }

    public void AddFindings(int count)
    {
        Interlocked.Add(ref _findings, count);
    }

    public void IncrementErrors()
    {
        Interlocked.Increment(ref _errors);
    }

    public long ErrorCount => Interlocked.Read(ref _errors);

    public void WriteDiscoveryRoot(string noun, string path, string? exposure, string access = "R")
    {
        if (_style == CliOutputStyle.Snaffler)
        {
            var renderedLine = string.Equals(noun, "share", StringComparison.OrdinalIgnoreCase)
                ? _snafflerFormatter.FormatShareDiscovery(path, access, null)
                : _snafflerFormatter.FormatDirectoryDiscovery(path);
            WriteRenderedLine(renderedLine, string.Equals(noun, "share", StringComparison.OrdinalIgnoreCase) ? "share" : "directory");
            return;
        }

        var message = string.IsNullOrWhiteSpace(exposure)
            ? $"Discovered {noun}: {path}"
            : $"Discovered {noun}: {path} [{exposure}]";
        WriteEvent(message, ConsoleColor.Cyan);
    }

    public void WriteDiscoveryDrive(string name, string id, string driveType, string? webUrl)
    {
        if (_style == CliOutputStyle.Snaffler)
        {
            WriteRenderedLine(_snafflerFormatter.FormatDriveDiscovery(name, id, driveType, webUrl), "share");
            return;
        }

        var summary = $"Discovered drive: {name} ({id}) [{driveType}]";
        WriteEvent(string.IsNullOrWhiteSpace(webUrl) ? summary : $"{summary} - {webUrl}", ConsoleColor.Cyan);
    }

    public void WriteFinding(ScanFinding finding, string resourcePath, CliSnafflerFormatter.CliFindingDisplayContext? context = null)
    {
        if (_style == CliOutputStyle.Snaffler)
        {
            var evidence = CliFindingFormatter.IsMetadataFinding(finding)
                ? null
                : CliFindingFormatter.FormatFindingEvidence(finding, resourcePath);
            _outputCapture?.RecordFinding(finding, resourcePath, evidence);
            WriteRenderedLine(_snafflerFormatter.FormatFinding(finding, resourcePath, context), "finding");
            return;
        }

        var findingColor = CliConsoleFormat.GetRiskColor(finding.Severity);
        string[] lines;
        string? evidenceText = null;
        if (CliFindingFormatter.IsMetadataFinding(finding))
        {
            var formattedPath = CliFindingFormatter.FormatMetadataPath(resourcePath);
            lines =
            [
                $"Finding: {finding.RuleName}",
                $"  Risk: {finding.Severity}",
                $"  Path: {formattedPath}",
            ];
        }
        else
        {
            evidenceText = CliFindingFormatter.FormatFindingEvidence(finding, resourcePath);
            var findingLines = new List<string>
            {
                $"Finding: {finding.RuleName}",
                $"  Risk: {finding.Severity}",
                $"  Path: {resourcePath}",
                $"  Evidence: {evidenceText}",
            };
            var sensitivityReasonLine = BuildSensitivityReasonLine(finding);
            if (!string.IsNullOrWhiteSpace(sensitivityReasonLine))
            {
                findingLines.Add(sensitivityReasonLine);
            }

            lines = [.. findingLines];
        }

        _outputCapture?.RecordFinding(finding, resourcePath, evidenceText);
        lock (ConsoleLock)
        {
            ClearStatusLineUnsafe();
            for (var i = 0; i < lines.Length; i++)
            {
                if (i == 0 || i == 1)
                {
                    WriteStyledLineUnsafe(lines[i], findingColor);
                }
                else
                {
                    WritePlainLineUnsafe(lines[i]);
                }
            }

            _outputCapture?.RecordCliLines(lines);
            _outputCapture?.RecordEvent("finding", lines[0]);
            RenderStatusLineUnsafe();
        }
    }

    public void WriteEvent(string message, ConsoleColor color)
    {
        WriteEvent([message], color);
    }

    public void Complete(string summaryTitle)
    {
        lock (ConsoleLock)
        {
            _completed = true;
            _summaryTitle = summaryTitle;

            if (_style == CliOutputStyle.Snaffler)
            {
                var line = _snafflerFormatter.FormatInfo("Snaffler out.");
                ClearStatusLineUnsafe();
                CliConsoleFormat.WriteStyledLine(line.Segments);
                _outputCapture?.RecordCliLines(line.PlainText);
                _outputCapture?.RecordEvent("info", line.PlainText);
                return;
            }

            ClearStatusLineUnsafe();
            var summaryLines = new List<string>
            {
                summaryTitle,
                $"Elapsed: {_stopwatch.Elapsed:hh\\:mm\\:ss}"
            };

            WriteStyledLineUnsafe(summaryLines[0], ConsoleColor.Cyan);
            WritePlainLineUnsafe(summaryLines[1]);
            if (Interlocked.Read(ref _filesDiscovered) > 0)
            {
                summaryLines.Add($"Files discovered: {Interlocked.Read(ref _filesDiscovered):N0}");
                WritePlainLineUnsafe(summaryLines[^1]);
            }

            summaryLines.Add($"Files scanned: {Interlocked.Read(ref _filesScanned):N0}");
            summaryLines.Add($"Findings: {Interlocked.Read(ref _findings):N0}");
            WritePlainLineUnsafe(summaryLines[^2]);
            WritePlainLineUnsafe(summaryLines[^1]);
            if (Interlocked.Read(ref _errors) > 0)
            {
                summaryLines.Add($"Errors: {Interlocked.Read(ref _errors):N0}");
                WriteStyledLineUnsafe(summaryLines[^1], ConsoleColor.Yellow);
            }

            _outputCapture?.RecordCliLines(string.Empty);
            _outputCapture?.RecordCliLines(summaryLines.ToArray());
        }
    }

    public async Task<T> RunInteractivePromptAsync<T>(Func<Task<T>> promptAction)
    {
        lock (ConsoleLock)
        {
            _interactivePromptActive = true;
            ClearStatusLineUnsafe();
        }

        try
        {
            return await promptAction();
        }
        finally
        {
            lock (ConsoleLock)
            {
                _interactivePromptActive = false;
                MarkStatusDirtyUnsafe();
                RenderStatusLineUnsafe();
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_completed)
        {
            _summaryTitle = ErrorCount > 0 ? "Scan failed" : "Scan interrupted";
        }

        if (_throttleNotifications != null && _throttleUpdatedHandler != null)
        {
            _throttleNotifications.Updated -= _throttleUpdatedHandler;
        }

        if (_renderCts != null)
        {
            _renderCts.Cancel();
        }

        if (_renderTask != null)
        {
            try
            {
                await _renderTask;
            }
            catch (OperationCanceledException)
            {
            }
        }

        _timer?.Dispose();
        _renderCts?.Dispose();

        if (_outputCapture != null)
        {
            await _outputCapture.WriteAsync(new CliOutputCapture.CliOutputSummary(
                _summaryTitle,
                _stopwatch.Elapsed,
                Interlocked.Read(ref _filesDiscovered),
                Interlocked.Read(ref _filesScanned),
                Interlocked.Read(ref _findings),
                Interlocked.Read(ref _errors)));
        }
    }

    private void WriteHeader()
    {
        lock (ConsoleLock)
        {
            if (_style == CliOutputStyle.Snaffler)
            {
                foreach (var bannerLine in _snafflerFormatter.GetBanner())
                {
                    WriteStyledLineUnsafe(bannerLine.Text, bannerLine.Color);
                    _outputCapture?.RecordCliLines(bannerLine.Text);
                }

                WritePlainLineUnsafe(string.Empty);
                _outputCapture?.RecordCliLines(string.Empty);
                var titleLine = _snafflerFormatter.FormatInfo(_title);
                CliConsoleFormat.WriteStyledLine(titleLine.Segments);
                _outputCapture?.RecordCliLines(titleLine.PlainText);
                _outputCapture?.RecordEvent("header", titleLine.PlainText);
                return;
            }

            WriteStyledLineUnsafe(_title, ConsoleColor.Cyan);
            _outputCapture?.RecordCliLines(_title);
            _outputCapture?.RecordEvent("header", _title);
        }
    }

    private async Task RenderLoopAsync(CancellationToken cancellationToken)
    {
        if (_timer == null)
        {
            return;
        }

        try
        {
            while (await _timer.WaitForNextTickAsync(cancellationToken))
            {
                lock (ConsoleLock)
                {
                    if (!_interactivePromptActive)
                    {
                        CliConsoleFormat.DrainBufferedInput();
                    }

                    if (_completed)
                    {
                        return;
                    }

                    if (_style == CliOutputStyle.Default && !_interactivePromptActive && ShouldRenderStatusUnsafe())
                    {
                        RenderStatusLineUnsafe();
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void WriteEvent(string[] lines, ConsoleColor color)
    {
        if (_style == CliOutputStyle.Snaffler)
        {
            foreach (var line in lines)
            {
                WriteRenderedLine(CreateSnafflerEventLine(line, color), ColorToEventKind(color));
            }

            return;
        }

        lock (ConsoleLock)
        {
            ClearStatusLineUnsafe();
            for (var i = 0; i < lines.Length; i++)
            {
                if (i == 0)
                {
                    WriteStyledLineUnsafe(lines[i], color);
                }
                else
                {
                    WritePlainLineUnsafe(lines[i]);
                }
            }

            _outputCapture?.RecordCliLines(lines);
            _outputCapture?.RecordEvent(ColorToEventKind(color), lines[0]);
            RenderStatusLineUnsafe();
        }
    }

    private CliSnafflerFormatter.CliRenderedLine CreateSnafflerEventLine(string message, ConsoleColor color)
    {
        return color == ConsoleColor.Red
            ? _snafflerFormatter.FormatError(message)
            : _snafflerFormatter.FormatInfo(message);
    }

    private void WriteRenderedLine(CliSnafflerFormatter.CliRenderedLine line, string eventKind)
    {
        lock (ConsoleLock)
        {
            ClearStatusLineUnsafe();
            CliConsoleFormat.WriteStyledLine(line.Segments);
            _outputCapture?.RecordCliLines(line.PlainText);
            _outputCapture?.RecordEvent(eventKind, line.PlainText);
            if (_style == CliOutputStyle.Default)
            {
                RenderStatusLineUnsafe();
            }
        }
    }

    private static string ColorToEventKind(ConsoleColor color)
    {
        return color switch
        {
            ConsoleColor.Red => "error",
            ConsoleColor.Yellow => "warning",
            ConsoleColor.Green => "finding",
            ConsoleColor.Magenta => "finding",
            ConsoleColor.Cyan => "info",
            _ => "message"
        };
    }

    private void RenderStatusLine()
    {
        lock (ConsoleLock)
        {
            RenderStatusLineUnsafe();
        }
    }

    private void RenderStatusLineUnsafe()
    {
        if (_style != CliOutputStyle.Default)
        {
            return;
        }

        var elapsed = _stopwatch.Elapsed;
        var discovered = Interlocked.Read(ref _filesDiscovered);
        var scanned = Interlocked.Read(ref _filesScanned);
        var findings = Interlocked.Read(ref _findings);
        var rate = elapsed.TotalSeconds > 0 ? discovered / elapsed.TotalSeconds : 0;
        var status = new StringBuilder();
        status.Append(_phase);
        if (_totalDrives > 0)
        {
            status.Append($" | Drives {_completedDrives}/{_totalDrives}");
        }

        status.Append($" | Discovered {discovered:N0}");
        status.Append($" | Scanned {scanned:N0}");
        status.Append($" | Findings {findings:N0}");
        status.Append($" | Rate {rate:0.0}/s");
        status.Append($" | Elapsed {elapsed:hh\\:mm\\:ss}");
        if (!string.IsNullOrWhiteSpace(_currentPath))
        {
            status.Append($" | Current {Truncate(_currentPath, 60)}");
        }
        else if (!string.IsNullOrWhiteSpace(_currentDrive))
        {
            status.Append($" | Current {Truncate(_currentDrive, 40)}");
        }

        if (_throttleNotice != null)
        {
            var remainingThrottle = _throttleNotice.RemainingGlobalPause;
            if (remainingThrottle > TimeSpan.Zero)
            {
                status.Append($" | Throttled {_throttleNotice.Service} {(int)_throttleNotice.StatusCode} {remainingThrottle:mm\\:ss} left");
            }
        }

        if (CliConsoleFormat.SupportsAnsi)
        {
            var renderedStatus = FitToConsoleWidth(status.ToString());
            if (string.Equals(renderedStatus, _lastRenderedStatusLine, StringComparison.Ordinal))
            {
                _lastStatusRenderUtc = DateTimeOffset.UtcNow;
                _statusDirty = false;
                return;
            }

            Console.Write("\r\u001b[2K");
            var ansiCode = CliConsoleFormat.GetAnsiColorCode(ConsoleColor.DarkGray);
            if (ansiCode != null)
            {
                Console.Write($"{ansiCode}{renderedStatus}\u001b[0m");
            }
            else
            {
                Console.Write(renderedStatus);
            }

            _lastRenderedStatusLine = renderedStatus;
            _lastStatusRenderUtc = DateTimeOffset.UtcNow;
            _statusDirty = false;
        }
    }

    private bool ShouldRenderStatusUnsafe()
    {
        var now = DateTimeOffset.UtcNow;
        if (_statusDirty)
        {
            return now - _lastStatusRenderUtc >= _statusRefreshInterval;
        }

        return now - _lastStatusRenderUtc >= _clockRefreshInterval;
    }

    private void MarkStatusDirtyUnsafe()
    {
        _statusDirty = true;
    }

    private static string? BuildSensitivityReasonLine(ScanFinding finding)
    {
        if (finding.LlmValidationStatus != Stratus.Sift.Core.Enums.LlmValidationStatus.Accepted ||
            finding.LlmIsSensitive != true)
        {
            return null;
        }

        var reason = !string.IsNullOrWhiteSpace(finding.LlmSensitivityReason)
            ? finding.LlmSensitivityReason
            : !string.IsNullOrWhiteSpace(finding.LlmValidationEvidenceSummary)
                ? finding.LlmValidationEvidenceSummary
                : finding.LlmValidationReason;

        if (string.IsNullOrWhiteSpace(reason))
        {
            return null;
        }

        return $"  Sensitive reason: {reason}";
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..(maxLength - 3)] + "...";
    }

    private void ClearStatusLineUnsafe()
    {
        if (_style == CliOutputStyle.Default && CliConsoleFormat.SupportsAnsi)
        {
            Console.Write("\r\u001b[2K");
            _lastRenderedStatusLine = string.Empty;
        }
    }

    private static string FitToConsoleWidth(string value)
    {
        var width = GetConsoleWidth();
        if (width <= 0)
        {
            return value;
        }

        var maxVisibleLength = Math.Max(20, width - 1);
        return value.Length <= maxVisibleLength
            ? value
            : value[..(maxVisibleLength - 3)] + "...";
    }

    private static int GetConsoleWidth()
    {
        try
        {
            return Console.WindowWidth > 0 ? Console.WindowWidth : Console.BufferWidth;
        }
        catch
        {
            return 120;
        }
    }

    private static void WriteStyledLineUnsafe(string message, ConsoleColor color)
    {
        var ansiCode = CliConsoleFormat.GetAnsiColorCode(color);
        if (ansiCode != null)
        {
            Console.WriteLine($"{ansiCode}{message}\u001b[0m");
            return;
        }

        var originalColor = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(message);
        Console.ForegroundColor = originalColor;
    }

    private static void WritePlainLineUnsafe(string message)
    {
        Console.WriteLine(message);
    }
}
