using System.Globalization;
using Microsoft.Extensions.Configuration;
using Stratus.Sift.Scanner.Models;

namespace Stratus.Sift.Cli;

internal static class CliContentOptions
{
    internal static void Apply(ScanOptions options, IConfiguration settings, IReadOnlyDictionary<string, string>? connector = null)
    {
        string? Read(string key) => connector != null && connector.TryGetValue(key, out var value) ? value : settings["ContentScanner:" + key];
        int Number(string key, int fallback, int maximum)
        {
            var raw = Read(key);
            return raw == null ? fallback : int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value > 0 && value <= maximum
                ? value : throw new ArgumentException($"{key} must be between 1 and {maximum}.");
        }
        bool Boolean(string key, bool fallback) => Read(key) is not { } raw ? fallback : bool.TryParse(raw, out var value) ? value
            : throw new ArgumentException($"{key} must be true or false.");
        options.MaxBinaryDocumentBytes = Number("MaxDocumentMiB", 10, 512) * 1024L * 1024;
        options.MaxExtractedCharacters = Number("MaxExtractedCharacters", 10 * 1024 * 1024, 64 * 1024 * 1024);
        options.EnableOcr = options.EnableBinaryDocuments && Boolean("EnableOcr", true);
        options.ScanExternalFiles = Boolean("ScanExternalFiles", false);
        options.TesseractPath = Read("TesseractPath") ?? "tesseract";
        options.OcrLanguage = Read("OcrLanguage") ?? "eng";
        options.OcrTimeoutSeconds = Number("OcrTimeoutSeconds", 30, 120);
        options.MaxOcrPages = Number("MaxOcrPages", 200, 10_000);
        options.MaxEmbeddedDocumentDepth = Number("MaxEmbeddedDocumentDepth", 3, 8);
        options.IncludeDocumentHistory = Boolean("IncludeDocumentHistory", true);
    }

    internal static string Fingerprint(ScanOptions? options) => options == null ? "default-content-limits" : string.Join('|',
        options.MaxBinaryDocumentBytes.ToString(CultureInfo.InvariantCulture), options.MaxExtractedCharacters.ToString(CultureInfo.InvariantCulture),
        options.EnableOcr, options.TesseractPath, options.OcrLanguage, options.OcrTimeoutSeconds, options.MaxOcrPages,
        options.MaxEmbeddedDocumentDepth, options.IncludeDocumentHistory);
}
