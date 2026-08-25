using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli;

internal sealed class CliOutputCapture
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
    private static readonly JsonSerializerOptions SpoolJsonOptions = new();

    private const int CliBatchLineThreshold = 64;
    private const int OutputQueueCapacity = 256;

    private readonly string _path;
    private readonly CliOutputFormat _format;
    private readonly string _title;
    private readonly string _temporaryPath;
    private readonly string _eventSpoolPath;
    private readonly string _findingSpoolPath;
    private readonly bool _append;
    private readonly DateTimeOffset _startedAtUtc = DateTimeOffset.UtcNow;
    private readonly Channel<OutputCaptureMessage> _channel = Channel.CreateBounded<OutputCaptureMessage>(
        new BoundedChannelOptions(OutputQueueCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait
        });
    private readonly Task _writerTask;

    internal CliOutputCapture(string path, CliOutputFormat format, CliOutputStyle style, string title, bool append = false)
    {
        _path = path;
        _format = format;
        _title = title;
        var suffix = $".{Environment.ProcessId}.{Guid.NewGuid():N}";
        _temporaryPath = path + suffix + ".partial";
        _eventSpoolPath = path + suffix + ".events";
        _findingSpoolPath = path + suffix + ".findings";
        _append = append;
        _writerTask = Task.Run(async () =>
        {
            try
            {
                await ProcessMessagesAsync();
            }
            catch (Exception ex)
            {
                _channel.Writer.TryComplete(ex);
                throw;
            }
        });
    }

    internal void RecordCliLines(params string[] lines)
    {
        if (_format != CliOutputFormat.Cli || lines.Length == 0)
        {
            return;
        }

        WriteMessage(new CliLinesMessage([.. lines.Select(CliConsoleFormat.StripAnsi)]));
    }

    internal void RecordEvent(string kind, string message)
    {
        WriteMessage(new EventMessage(
            new CliOutputEventRecord
            {
                Kind = kind,
                Message = CliConsoleFormat.StripAnsi(message),
                TimestampUtc = DateTimeOffset.UtcNow
            }));
    }

    internal void RecordFinding(ScanFinding finding, string resourcePath, string? evidence)
    {
        WriteMessage(new FindingMessage(
            new CliOutputFindingRecord
            {
                RuleName = finding.RuleName,
                ClassifierName = finding.ClassifierName,
                ResourcePath = resourcePath,
                Severity = finding.Severity.ToString(),
                ConfidenceLevel = finding.ConfidenceLevel.ToString(),
                Exposure = finding.Exposure,
                Owner = finding.Owner,
                IsMetadata = CliFindingFormatter.IsMetadataFinding(finding),
                Evidence = evidence,
                RedactedValue = finding.RedactedValue,
                Snippet = finding.Snippet,
                DetectedAtUtc = finding.DetectedAt,
                EvidenceJson = finding.EvidenceJson,
                LlmValidationStatus = finding.LlmValidationStatus,
                ValidationStatus = finding.LlmValidationStatus?.ToString(),
                LlmValidationModel = string.IsNullOrWhiteSpace(finding.LlmValidationModel) ? null : finding.LlmValidationModel,
                LlmValidationReason = string.IsNullOrWhiteSpace(finding.LlmValidationReason) ? null : finding.LlmValidationReason,
                LlmValidationEvidenceSummary = string.IsNullOrWhiteSpace(finding.LlmValidationEvidenceSummary) ? null : finding.LlmValidationEvidenceSummary,
                LlmIsSensitive = finding.LlmIsSensitive,
                LlmSensitivityReason = string.IsNullOrWhiteSpace(finding.LlmSensitivityReason) ? null : finding.LlmSensitivityReason,
                LlmValidatedAtUtc = finding.LlmValidatedAt
            }));
    }

    internal async Task WriteAsync(CliOutputSummary summary, CancellationToken cancellationToken = default)
    {
        await _channel.Writer.WriteAsync(new CompleteMessage(summary), cancellationToken);
        _channel.Writer.TryComplete();
        await _writerTask.WaitAsync(cancellationToken);
    }

    internal async Task FlushCheckpointAsync(CliOutputSummary summary, CancellationToken cancellationToken = default)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await _channel.Writer.WriteAsync(new FlushMessage(summary, completion), cancellationToken);
        var finished = await Task.WhenAny(completion.Task, _writerTask).WaitAsync(cancellationToken);
        if (finished == _writerTask)
        {
            await _writerTask.WaitAsync(cancellationToken);
        }

        await completion.Task.WaitAsync(cancellationToken);
    }

    private void WriteMessage(OutputCaptureMessage message)
    {
        while (!_channel.Writer.TryWrite(message))
        {
            if (_writerTask.IsCompleted)
            {
                _writerTask.GetAwaiter().GetResult();
            }

            if (!_channel.Writer.WaitToWriteAsync().AsTask().GetAwaiter().GetResult())
            {
                _writerTask.GetAwaiter().GetResult();
                throw new InvalidOperationException("The output writer stopped before the scan completed.");
            }
        }
    }

    private async Task ProcessMessagesAsync()
    {
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var existingJsonDocument = await ReadExistingJsonDocumentAsync();
        var appendCli = _append
            && _format == CliOutputFormat.Cli
            && File.Exists(_path)
            && new FileInfo(_path).Length > 0;

        using var cliStream = _format == CliOutputFormat.Cli
            ? new StreamWriter(
                new FileStream(
                    _path,
                    appendCli ? FileMode.Append : FileMode.Create,
                    FileAccess.Write,
                    System.IO.FileShare.Read),
                Encoding.UTF8)
            {
                AutoFlush = false
            }
            : null;

        if (appendCli && cliStream != null)
        {
            await cliStream.WriteLineAsync();
        }

        try
        {
            using var eventSpool = _format == CliOutputFormat.Json ? CreateSpoolWriter(_eventSpoolPath) : null;
            using var findingSpool = _format == CliOutputFormat.Json ? CreateSpoolWriter(_findingSpoolPath) : null;
            if (existingJsonDocument is not null && eventSpool is not null && findingSpool is not null)
            {
                await SpoolExistingRecordsAsync(existingJsonDocument, eventSpool, findingSpool);
            }

            var cliLineBuffer = new List<string>();
            CliOutputSummary? summary = null;
            var newFindingCount = 0L;

            await foreach (var message in _channel.Reader.ReadAllAsync())
            {
                switch (message)
                {
                    case CliLinesMessage cliLines when cliStream != null:
                        cliLineBuffer.AddRange(cliLines.Lines);
                        if (cliLineBuffer.Count >= CliBatchLineThreshold)
                        {
                            await FlushCliLinesAsync(cliStream, cliLineBuffer);
                        }
                        break;

                    case EventMessage eventMessage when eventSpool != null:
                        await eventSpool.WriteLineAsync(JsonSerializer.Serialize(eventMessage.Event, CliJsonContext.Default.CliOutputEventRecord));
                        break;

                    case FindingMessage findingMessage when findingSpool != null:
                        await findingSpool.WriteLineAsync(JsonSerializer.Serialize(findingMessage.Finding, CliJsonContext.Default.CliOutputFindingRecord));
                        newFindingCount++;
                        break;

                    case FlushMessage flushMessage:
                        try
                        {
                            if (cliStream != null)
                            {
                                await FlushCliLinesAsync(cliStream, cliLineBuffer);
                                await cliStream.FlushAsync();
                            }
                            else if (eventSpool != null && findingSpool != null)
                            {
                                await eventSpool.FlushAsync();
                                await findingSpool.FlushAsync();
                                await WriteJsonDocumentAsync(
                                    flushMessage.Summary,
                                    existingJsonDocument,
                                    newFindingCount);
                            }

                            flushMessage.Completion.SetResult();
                        }
                        catch (Exception exception)
                        {
                            flushMessage.Completion.SetException(exception);
                            throw;
                        }
                        break;

                    case CompleteMessage completeMessage:
                        summary = completeMessage.Summary;
                        break;
                }
            }

            if (cliStream != null)
            {
                await FlushCliLinesAsync(cliStream, cliLineBuffer);
                return;
            }

            if (summary is null || eventSpool is null || findingSpool is null)
            {
                throw new InvalidOperationException("The scan output ended without a completion summary.");
            }

            await eventSpool.FlushAsync();
            await findingSpool.FlushAsync();
            await WriteJsonDocumentAsync(
                summary,
                existingJsonDocument,
                newFindingCount);
        }
        finally
        {
            TryDelete(_eventSpoolPath);
            TryDelete(_findingSpoolPath);
            TryDelete(_temporaryPath);
        }
    }

    private async Task<CliJsonOutputDocument?> ReadExistingJsonDocumentAsync()
    {
        if (!_append
            || _format != CliOutputFormat.Json
            || !File.Exists(_path)
            || new FileInfo(_path).Length == 0)
        {
            return null;
        }

        try
        {
            await using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, System.IO.FileShare.Read);
            return await JsonSerializer.DeserializeAsync(stream, CliJsonContext.Default.CliJsonOutputDocument)
                ?? throw new JsonException("The existing JSON output was empty.");
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            throw new InvalidOperationException(
                $"Cannot resume into JSON output '{_path}' because the existing file is not a valid Stratus Sift JSON result. The file was left unchanged.",
                ex);
        }
    }

    private static StreamWriter CreateSpoolWriter(string path)
        => new(
            new FileStream(path, FileMode.CreateNew, FileAccess.Write, System.IO.FileShare.Read),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

    private static async Task SpoolExistingRecordsAsync(
        CliJsonOutputDocument existing,
        StreamWriter eventSpool,
        StreamWriter findingSpool)
    {
        foreach (var item in existing.Events)
        {
            await eventSpool.WriteLineAsync(JsonSerializer.Serialize(item, CliJsonContext.Default.CliOutputEventRecord));
        }

        foreach (var item in existing.FindingsList)
        {
            await findingSpool.WriteLineAsync(JsonSerializer.Serialize(item, CliJsonContext.Default.CliOutputFindingRecord));
        }

        existing.Events.Clear();
        existing.FindingsList.Clear();
    }

    private static async Task FlushCliLinesAsync(StreamWriter writer, List<string> lines)
    {
        if (lines.Count == 0)
        {
            return;
        }

        foreach (var line in lines)
        {
            await writer.WriteLineAsync(line);
        }

        lines.Clear();
        await writer.FlushAsync();
    }

    private async Task WriteJsonDocumentAsync(
        CliOutputSummary summary,
        CliJsonOutputDocument? previous,
        long newFindingRecords)
    {
        await using (var stream = new FileStream(
                         _temporaryPath,
                         FileMode.CreateNew,
                         FileAccess.Write,
                         System.IO.FileShare.None,
                         bufferSize: 64 * 1024,
                         FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
            writer.WriteStartObject();
            WriteValue(writer, nameof(CliJsonOutputDocument.SchemaVersion), previous?.SchemaVersion ?? CliStoredOutputVersions.Current);
            WriteValue(writer, nameof(CliJsonOutputDocument.Title), string.IsNullOrWhiteSpace(previous?.Title) ? _title : previous.Title);
            WriteValue(writer, nameof(CliJsonOutputDocument.SummaryTitle), summary.SummaryTitle);
            WriteValue(writer, nameof(CliJsonOutputDocument.StartedAtUtc), previous?.StartedAtUtc ?? _startedAtUtc);
            WriteValue(writer, nameof(CliJsonOutputDocument.GeneratedAtUtc), DateTimeOffset.UtcNow);
            WriteValue(writer, nameof(CliJsonOutputDocument.Elapsed), (previous?.Elapsed ?? TimeSpan.Zero) + summary.Elapsed);
            WriteValue(writer, nameof(CliJsonOutputDocument.FilesDiscovered), (previous?.FilesDiscovered ?? 0) + summary.FilesDiscovered);
            WriteValue(writer, nameof(CliJsonOutputDocument.FilesScanned), (previous?.FilesScanned ?? 0) + summary.FilesScanned);
            WriteValue(writer, nameof(CliJsonOutputDocument.Findings), (previous?.Findings ?? 0) + (summary.Findings > 0 ? summary.Findings : newFindingRecords));
            WriteValue(writer, nameof(CliJsonOutputDocument.Errors), (previous?.Errors ?? 0) + summary.Errors);
            await WriteSpoolArrayAsync(writer, nameof(CliJsonOutputDocument.Events), _eventSpoolPath);
            await WriteSpoolArrayAsync(writer, nameof(CliJsonOutputDocument.FindingsList), _findingSpoolPath);
            writer.WriteEndObject();
            await writer.FlushAsync();
            await stream.FlushAsync();
        }

        File.Move(_temporaryPath, _path, overwrite: true);
    }

    private static void WriteValue<T>(Utf8JsonWriter writer, string propertyName, T value)
    {
        writer.WritePropertyName(propertyName);
        JsonSerializer.Serialize(writer, value, typeof(T), CliJsonContext.Default);
    }

    private static async Task WriteSpoolArrayAsync(Utf8JsonWriter writer, string propertyName, string spoolPath)
    {
        writer.WritePropertyName(propertyName);
        writer.WriteStartArray();
        using var reader = new StreamReader(
            new FileStream(spoolPath, FileMode.Open, FileAccess.Read, System.IO.FileShare.ReadWrite),
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: true);
        while (await reader.ReadLineAsync() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            using var document = JsonDocument.Parse(line);
            document.RootElement.WriteTo(writer);
        }
        writer.WriteEndArray();
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best effort cleanup for scan-local temporary files.
        }
    }

    internal sealed record CliOutputSummary(
        string SummaryTitle,
        TimeSpan Elapsed,
        long FilesDiscovered,
        long FilesScanned,
        long Findings,
        long Errors);

    private abstract record OutputCaptureMessage;

    private sealed record CliLinesMessage(IReadOnlyList<string> Lines) : OutputCaptureMessage;
    private sealed record EventMessage(CliOutputEventRecord Event) : OutputCaptureMessage;
    private sealed record FindingMessage(CliOutputFindingRecord Finding) : OutputCaptureMessage;
    private sealed record FlushMessage(CliOutputSummary Summary, TaskCompletionSource Completion) : OutputCaptureMessage;
    private sealed record CompleteMessage(CliOutputSummary Summary) : OutputCaptureMessage;
}

internal enum CliOutputFormat
{
    Cli,
    Json
}

internal enum CliOutputStyle
{
    Default,
    Snaffler
}

internal sealed record CliOutputOptions(string? Path, CliOutputFormat Format, CliOutputStyle Style, bool Append = false);
