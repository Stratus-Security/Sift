using System.Diagnostics;
using System.Text;
using Stratus.Sift.Scanner.Models;
using UglyToad.PdfPig;

namespace Stratus.Sift.Scanner.Services;

public partial class ContentExtractor
{
    private static readonly SemaphoreSlim OcrSlots = new(2, 2);

    private static ContentExtractionResult AppendPdfOcr(PdfDocument document, StringBuilder text)
    {
        var state = CurrentExtraction.Value;
        if (state?.Options.EnableOcr != true)
            return new(text.ToString(), text.Length > 0, text.Length > 0 ? null : "PDF has no stored text; enable OCR to inspect images.");
        var complete = true; var images = 0; var ocrPages = 0;
        foreach (var page in document.GetPages())
        {
            state.Cancellation.ThrowIfCancellationRequested();
            if (page.NumberOfImages == 0 && !string.IsNullOrWhiteSpace(page.Text)) continue;
            if (++ocrPages > Math.Clamp(state.Options.MaxOcrPages, 1, 10_000)) { complete = false; break; }
            if (string.IsNullOrWhiteSpace(page.Text) && page.NumberOfImages == 0) complete = false;
            foreach (var image in page.GetImages())
            {
                if (++images > 1000 || (long)image.WidthInSamples * image.HeightInSamples > 25_000_000)
                { complete = false; continue; }
                try
                {
                    if (!image.TryGetPng(out var png) || png.Length > MaxFileSize) { complete = false; continue; }
                    using var stream = new MemoryStream(png, false);
                    var result = ExtractImageOcr(stream, ".png");
                    complete &= result.IsComplete;
                    if (!AppendBounded(text, result.Text, true)) return Truncated(text);
                }
                catch (Exception ex) when (!(ex is OperationCanceledException && state.Cancellation.IsCancellationRequested))
                { RecordExtractionException(ex); complete = false; }
            }
        }
        return new(text.ToString(), complete, complete ? null : "Some PDF images or pages could not be inspected with OCR.");
    }

    private static ContentExtractionResult ExtractImageOcr(Stream input, string extension)
    {
        var state = CurrentExtraction.Value;
        if (state?.Options.EnableOcr != true) return Failure("Image inspection requires OCR.");
        if (state.Elapsed.Elapsed > TimeSpan.FromMinutes(2)) return Failure("OCR exceeded the document time limit.");
        OcrSlots.Wait(state.Cancellation);
        var directory = Path.Combine(Path.GetTempPath(), "sift-ocr-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(directory);
            var file = Path.Combine(directory, "image" + extension);
            using (var target = File.Create(file))
                if (!CopyToBounded(input, target, MaxFileSize)) return Failure("OCR image exceeds the input limit.");
            var start = new ProcessStartInfo(state.Options.TesseractPath)
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            start.ArgumentList.Add(file);
            start.ArgumentList.Add("stdout");
            start.ArgumentList.Add("-l");
            start.ArgumentList.Add(state.Options.OcrLanguage);
            using var process = Process.Start(start) ?? throw new IOException("OCR process could not be started.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(state.Cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(state.Options.OcrTimeoutSeconds, 1, 120)));
            var output = ReadOcrOutputAsync(process.StandardOutput, MaxExtractedCharacters, timeout.Token);
            var errors = ReadOcrOutputAsync(process.StandardError, 64 * 1024, timeout.Token);
            try
            {
                Task.WhenAll(process.WaitForExitAsync(timeout.Token), output, errors).GetAwaiter().GetResult();
                return process.ExitCode == 0 ? new(output.Result, true) : Failure("OCR runtime could not inspect the image.");
            }
            catch (Exception ex)
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                state.Cancellation.ThrowIfCancellationRequested();
                if (ex is not OperationCanceledException) RecordExtractionException(ex);
                return Failure("OCR timed out or exceeded its output limit.");
            }
        }
        catch (Exception ex) when (!(ex is OperationCanceledException && state.Cancellation.IsCancellationRequested))
        {
            // A missing/unusable executable is an expected OCR availability problem.
            if (ex is System.ComponentModel.Win32Exception)
            {
                RecordExtractionException(ex, expected: true);
                return Failure("OCR is unavailable or failed: " + ex.Message);
            }
            return Failure(ex, "OCR is unavailable or failed: " + ex.Message);
        }
        finally
        {
            // This generated directory contains only the input written above. No archive names enter it.
            var full = Path.GetFullPath(directory);
            var root = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase) && Path.GetFileName(full).StartsWith("sift-ocr-", StringComparison.Ordinal))
                try { Directory.Delete(full, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            OcrSlots.Release();
        }
    }

    private static async Task<string> ReadOcrOutputAsync(StreamReader reader, int limit, CancellationToken ct)
    {
        var text = new StringBuilder(); var buffer = new char[8192]; int read;
        while ((read = await reader.ReadAsync(buffer, ct)) > 0)
        {
            if (text.Length + read > limit) throw new InvalidDataException("OCR output exceeded its limit.");
            text.Append(buffer, 0, read);
        }
        return text.ToString();
    }
}
