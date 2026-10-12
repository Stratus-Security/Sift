using System.Collections.Concurrent;
using System.IO.Compression;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Connectors.SharePoint;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Scanner.Models;
using Stratus.Sift.Scanner.Services;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Fonts.Standard14Fonts;
using UglyToad.PdfPig.Writer;
using static Stratus.Sift.Cli.Tests.Microsoft365ReliabilityTests;

namespace Stratus.Sift.Cli.Tests;

public sealed class BinaryDiagnosticsRegressionTests
{
    [Theory]
    [InlineData(".docx", false)]
    [InlineData(".docx", true)]
    [InlineData(".xlsx", false)]
    [InlineData(".xlsx", true)]
    [InlineData(".pdf", false)]
    [InlineData(".pdf", true)]
    public async Task CorruptDocuments_StayIncompleteWithDebugDetails(string extension, bool local)
    {
        var logger = new RecordingLogger<FileScanner>();
        var scanner = new FileScanner(logger, new ContentExtractor(), new ValidatorFactory([]));
        var options = new ScanOptions { EnableBinaryDocuments = true };
        var plan = Plan(extension);
        ScanResult result;
        if (local)
        {
            var path = Path.Combine(Path.GetTempPath(), "sift-binary-test-" + Guid.NewGuid().ToString("N") + extension);
            try
            {
                await File.WriteAllBytesAsync(path, [1, 2, 3]);
                result = await scanner.ScanFileWithResultAsync(path, plan, options);
            }
            finally { File.Delete(path); }
        }
        else
        {
            using var stream = new MemoryStream([1, 2, 3]);
            result = await scanner.ScanStreamAsync(stream, "test" + extension, plan, options);
        }
        Assert.False(result.IsComplete);
        Assert.False(result.HasUnexpectedInspectionFailure, logger.Entries.FirstOrDefault(e => e.Exception != null).Exception?.ToString());
        Assert.NotEmpty(result.IncompleteReason!);
        Assert.DoesNotContain(logger.Entries, e => e.Level >= LogLevel.Warning);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains(result.IncompleteReason!));
        if (extension != ".pdf") Assert.Contains(logger.Entries, e => e.Exception != null);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PdfOcrFailure_RetainsTextFindingsIncludingInsideZip(bool archive)
    {
        var logger = new RecordingLogger<FileScanner>();
        var scanner = new FileScanner(logger, new ContentExtractor(), new ValidatorFactory([]));
        var bytes = PdfWithTextAndImage();
        if (archive)
        {
            using var zip = new MemoryStream();
            using (var writer = new ZipArchive(zip, ZipArchiveMode.Create, true))
            using (var entry = writer.CreateEntry("test.pdf").Open()) entry.Write(bytes);
            bytes = zip.ToArray();
        }
        using var stream = new MemoryStream(bytes);
        var result = await scanner.ScanStreamAsync(stream, archive ? "test.zip" : "test.pdf", Plan(".pdf"), OcrOptions());
        Assert.False(result.IsComplete);
        Assert.False(result.HasUnexpectedInspectionFailure);
        Assert.Contains("OCR", result.IncompleteReason);
        Assert.Single(result.Issues);
        Assert.DoesNotContain(logger.Entries, e => e.Level >= LogLevel.Warning);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains("OCR"));
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Exception is System.ComponentModel.Win32Exception);
    }

    [Theory]
    [InlineData(".docx")]
    [InlineData(".pdf")]
    [InlineData(".zip")]
    [InlineData(".tar")]
    public async Task ExpectedRemoteDocumentFailures_DoNotWarnOrCheckpoint(string extension)
    {
        var bytes = extension == ".pdf" ? PdfWithTextAndImage() : new byte[] { 1, 2, 3 };
        var logger = new RecordingLogger<RemoteDriveScanner>();
        var file = RemoteFile(bytes, extension);
        var outcome = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(file), options: OcrOptions(),
            extension: extension, logger: logger);
        Assert.True(outcome.Incomplete);
        Assert.Null(outcome.FinalToken);
        Assert.Empty(outcome.Checkpoints);
        Assert.Equal(0, outcome.Processed);
        if (extension == ".pdf") Assert.Single(outcome.Findings);
        Assert.DoesNotContain(logger.Entries, e => e.Level >= LogLevel.Warning);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Information && e.Message.Contains("remain pending"));
    }

    [Fact]
    public async Task UnexpectedEmbeddedOcrFault_RetainsFindingsAndWarns()
    {
        var options = OcrOptions();
        options.TesseractPath = null!; // Invalid configuration must remain visible through the PDF aggregation.
        var logger = new RecordingLogger<FileScanner>();
        var scanner = new FileScanner(logger, new ContentExtractor(), new ValidatorFactory([]));
        using var stream = new MemoryStream(PdfWithTextAndImage());
        var result = await scanner.ScanStreamAsync(stream, "test.pdf", Plan(".pdf"), options);
        Assert.False(result.IsComplete);
        Assert.True(result.HasUnexpectedInspectionFailure);
        Assert.Single(result.Issues);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Exception is InvalidOperationException);

        var remoteLogger = new RecordingLogger<RemoteDriveScanner>();
        var outcome = await ScanAsync(new Microsoft365CoverageTests.SingleFileDrive(RemoteFile(PdfWithTextAndImage(), ".pdf")),
            options: options, extension: ".pdf", logger: remoteLogger);
        Assert.True(outcome.Incomplete);
        Assert.Null(outcome.FinalToken);
        Assert.Single(outcome.Findings);
        Assert.Contains(remoteLogger.Entries, e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public void UnexpectedStreamFault_IsNotClassifiedAsCorruption()
    {
        using var stream = new FaultingStream();
        var result = new ContentExtractor().ExtractWithResult(stream, ".docx");
        Assert.False(result.IsComplete);
        Assert.True(result.HasUnexpectedFailure);
        Assert.IsType<NullReferenceException>(result.FailureException);
    }

    [Fact]
    public void RequestedCancellation_IsNotAnExpectedDocumentFailure()
    {
        using var stream = new MemoryStream(PdfWithTextAndImage());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => new ContentExtractor()
            .ExtractWithResult(stream, ".pdf", OcrOptions(), cancellation.Token));
    }

    private static ScannerExecutionPlan Plan(string extension)
    {
        var classifier = new Classifier
        {
            Id = Guid.NewGuid(), Name = "Content rule", EnableLlmValidation = false,
            Matches = [new ClassifierMatch { Target = RuleTarget.Content, Patterns = ["secret"], IncludedExtensions = [extension] }]
        };
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([classifier]);
        return ScannerExecutionPlan.Create(optimizer,
            new Dictionary<Guid, List<Policy>> { [classifier.Id] = [new Policy { Name = "Test" }] });
    }

    private static ScanOptions OcrOptions() => new()
    {
        EnableBinaryDocuments = true, EnableZipArchives = true, EnableOcr = true,
        TesseractPath = Path.Combine(Path.GetTempPath(), "missing-sift-ocr-" + Guid.NewGuid().ToString("N") + ".exe")
    };

    private static Microsoft365ContentFile RemoteFile(byte[] bytes, string extension)
        => new("test", "test" + extension, "https://contoso.sharepoint.com/test" + extension, "v1", bytes.Length,
            (_, _) => Task.FromResult<Stream?>(new MemoryStream(bytes)));

    private static byte[] PdfWithTextAndImage()
    {
        var builder = new PdfDocumentBuilder();
        var page = builder.AddPage(200, 200);
        page.AddText("secret", 12, new PdfPoint(10, 100), builder.AddStandard14Font(Standard14Font.Helvetica));
        page.AddPng(Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII="),
            new PdfRectangle(10, 10, 30, 30));
        return builder.Build();
    }

    private sealed class FaultingStream : MemoryStream
    {
        public override long Length => throw new NullReferenceException("Unexpected stream implementation fault.");
    }

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        internal ConcurrentQueue<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = new();
        public bool IsEnabled(LogLevel level) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Enqueue((level, formatter(state, exception), exception));
    }
}
