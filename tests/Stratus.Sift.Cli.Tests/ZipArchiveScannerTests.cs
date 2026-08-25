using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Cli;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Models;
using Stratus.Sift.Scanner.Services;
using Stratus.Sift.Scanner.Validators;

namespace Stratus.Sift.Cli.Tests;

public sealed class ZipArchiveScannerTests : IDisposable
{
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly List<(LogLevel Level, string Message)> _entries = [];

        public IReadOnlyList<(LogLevel Level, string Message)> Entries => _entries;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => _entries.Add((logLevel, formatter(state, exception)));
    }

    private sealed class NonSeekableStream(Stream inner) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => inner.Read(buffer);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => inner.ReadAsync(buffer, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private readonly string _temporaryDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

    public ZipArchiveScannerTests()
    {
        Directory.CreateDirectory(_temporaryDirectory);
    }

    public void Dispose()
    {
        if (Directory.Exists(_temporaryDirectory))
        {
            Directory.Delete(_temporaryDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task ScanFile_StreamsZipEntriesAndUsesVirtualPaths()
    {
        var zipPath = CreateZip(("configs/production.txt", "token=SIFT-ZIP-SECRET"));
        var (plan, scanner, _) = CreateScanner();

        var result = await scanner.ScanFileWithResultAsync(
            zipPath,
            plan,
            new ScanOptions { EnableZipArchives = true });

        var finding = Assert.Single(result.Issues);
        Assert.Equal("SIFT-ZIP-SECRET", finding.RedactedValue);
        Assert.Equal($"{zipPath}!/configs/production.txt", finding.ResourcePath);
    }

    [Fact]
    public async Task LocalCommand_EnablesZipInspectionByDefault()
    {
        var zipPath = CreateZip(("configs/production.txt", "token=SIFT-ZIP-SECRET"));
        var rulesDirectory = Path.Combine(_temporaryDirectory, "rules");
        Directory.CreateDirectory(rulesDirectory);
        await File.WriteAllTextAsync(
            Path.Combine(rulesDirectory, "zip-secret.json"),
            """
            {
              "Name": "ZIP secret",
              "Matches": [
                {
                  "Target": "Content",
                  "Patterns": [ "SIFT-ZIP-SECRET" ],
                  "Keywords": [ "token" ],
                  "IncludedExtensions": [ ".txt" ],
                  "IsLiteral": true
                }
              ]
            }
            """);
        var outputPath = Path.Combine(_temporaryDirectory, "result.log");

        var exitCode = await Program.RunAsync(
        [
            "local",
            "--path", _temporaryDirectory,
            "--rules", rulesDirectory,
            "--output", outputPath,
            "--threads", "1"
        ]);

        Assert.Equal(CliExitCodes.Success, exitCode);
        var output = await File.ReadAllTextAsync(outputPath);
        Assert.Contains($"{zipPath}!/configs/production.txt", output, StringComparison.Ordinal);
        Assert.Contains("SIFT-ZIP-SECRET", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanStream_StreamsZipEntriesFromSeekableSources()
    {
        await using var zip = CreateZipStream(("nested/settings.txt", "token=SIFT-ZIP-SECRET"));
        var (plan, scanner, _) = CreateScanner();

        var result = await scanner.ScanStreamAsync(
            zip,
            "remote.zip",
            plan,
            new ScanOptions { EnableZipArchives = true });

        var finding = Assert.Single(result.Issues);
        Assert.Equal("remote.zip!/nested/settings.txt", finding.ResourcePath);
    }

    [Fact]
    public async Task ScanFile_AppliesPolicyPathScopesToEntriesInsteadOfTheOuterArchive()
    {
        var zipPath = CreateZip(("configs/production.txt", "token=SIFT-ZIP-SECRET"));
        var virtualPath = $"{zipPath}!/configs/production.txt";
        var (plan, scanner, _) = CreateScanner(["*production.txt"]);

        var result = await scanner.ScanFileWithResultAsync(
            zipPath,
            plan,
            new ScanOptions { EnableZipArchives = true });

        var finding = Assert.Single(result.Issues);
        Assert.Equal(virtualPath, finding.ResourcePath);
    }

    [Fact]
    public async Task ScanFile_CanDisableZipInspection()
    {
        var zipPath = CreateZip(("secret.txt", "token=SIFT-ZIP-SECRET"));
        var (plan, scanner, _) = CreateScanner();

        var result = await scanner.ScanFileWithResultAsync(
            zipPath,
            plan,
            new ScanOptions { EnableZipArchives = false });

        Assert.Empty(result.Issues);
    }

    [Fact]
    public async Task ScanFile_SkipsEntriesBeyondExpansionLimits()
    {
        var zipPath = CreateZip(("secret.txt", "token=SIFT-ZIP-SECRET"));
        var (plan, scanner, logger) = CreateScanner();

        var result = await scanner.ScanFileWithResultAsync(
            zipPath,
            plan,
            new ScanOptions { EnableZipArchives = true, MaxZipEntryBytes = 4 });

        Assert.Empty(result.Issues);
        Assert.Contains(
            logger.Entries,
            entry => entry.Level == LogLevel.Warning
                && entry.Message.Contains("Skipped 1 unsafe", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanFile_RejectsOversizedCentralDirectoriesBeforeLoadingEntries()
    {
        var zipPath = CreateZip(
            ("first.txt", "nothing to report"),
            ("secret.txt", "token=SIFT-ZIP-SECRET"));
        var (plan, scanner, logger) = CreateScanner();

        var result = await scanner.ScanFileWithResultAsync(
            zipPath,
            plan,
            new ScanOptions
            {
                EnableZipArchives = true,
                MaxZipEntries = 1
            });

        Assert.Empty(result.Issues);
        Assert.Contains(
            logger.Entries,
            entry => entry.Level == LogLevel.Warning
                && entry.Message.Contains("central directory", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanFile_RejectsMalformedZipFilesWithoutAFileFailure()
    {
        var path = Path.Combine(_temporaryDirectory, $"{Guid.NewGuid():N}.zip");
        await File.WriteAllTextAsync(path, "token=SIFT-ZIP-SECRET");
        var (plan, scanner, logger) = CreateScanner();

        var result = await scanner.ScanFileWithResultAsync(
            path,
            plan,
            new ScanOptions { EnableZipArchives = true });

        Assert.Empty(result.Issues);
        Assert.DoesNotContain(logger.Entries, entry => entry.Level == LogLevel.Error);
    }

    [Fact]
    public async Task ScanFile_SkipsSuspiciousCompressionRatios()
    {
        var content = $"token=SIFT-ZIP-SECRET{new string('A', 32 * 1024)}";
        var zipPath = CreateZip(("secret.txt", content));
        var (plan, scanner, _) = CreateScanner();

        var result = await scanner.ScanFileWithResultAsync(
            zipPath,
            plan,
            new ScanOptions { EnableZipArchives = true, MaxZipCompressionRatio = 2 });

        Assert.Empty(result.Issues);
    }

    [Fact]
    public async Task ScanFile_RejectsTraversalEntryNames()
    {
        var zipPath = CreateZip(("../secret.txt", "token=SIFT-ZIP-SECRET"));
        var (plan, scanner, _) = CreateScanner();

        var result = await scanner.ScanFileWithResultAsync(
            zipPath,
            plan,
            new ScanOptions { EnableZipArchives = true });

        Assert.Empty(result.Issues);
    }

    [Fact]
    public async Task ScanFile_DoesNotExpandNestedZipArchives()
    {
        await using var innerZip = CreateZipStream(("secret.txt", "token=SIFT-ZIP-SECRET"));
        var outerPath = Path.Combine(_temporaryDirectory, $"{Guid.NewGuid():N}.zip");
        await using (var outerFile = File.Create(outerPath))
        using (var outerZip = new ZipArchive(outerFile, ZipArchiveMode.Create, leaveOpen: false))
        await using (var entry = outerZip.CreateEntry("inner.zip").Open())
        {
            await innerZip.CopyToAsync(entry);
        }

        var (plan, scanner, _) = CreateScanner();
        var result = await scanner.ScanFileWithResultAsync(
            outerPath,
            plan,
            new ScanOptions { EnableZipArchives = true });

        Assert.Empty(result.Issues);
    }

    [Fact]
    public async Task ScanStream_UsesABoundedBufferForNonSeekableZipSources()
    {
        var zip = CreateZipStream(("secret.txt", "token=SIFT-ZIP-SECRET"));
        await using var nonSeekable = new NonSeekableStream(zip);
        var (plan, scanner, logger) = CreateScanner();

        var result = await scanner.ScanStreamAsync(
            nonSeekable,
            "remote.zip",
            plan,
            new ScanOptions { EnableZipArchives = true });

        var finding = Assert.Single(result.Issues);
        Assert.Equal("remote.zip!/secret.txt", finding.ResourcePath);
        Assert.DoesNotContain(logger.Entries, entry => entry.Level == LogLevel.Error);
    }

    [Fact]
    public async Task ScanStream_RejectsNonSeekableArchivesBeyondTheBufferLimit()
    {
        var zip = CreateZipStream(("secret.txt", "token=SIFT-ZIP-SECRET"));
        await using var nonSeekable = new NonSeekableStream(zip);
        var (plan, scanner, logger) = CreateScanner();

        var result = await scanner.ScanStreamAsync(
            nonSeekable,
            "remote.zip",
            plan,
            new ScanOptions
            {
                EnableZipArchives = true,
                MaxZipBufferedContainerBytes = 4
            });

        Assert.Empty(result.Issues);
        Assert.Contains(
            logger.Entries,
            entry => entry.Level == LogLevel.Warning
                && entry.Message.Contains("buffering limit", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanFile_PropagatesCancellationDuringZipInspection()
    {
        var zipPath = CreateZip(("secret.txt", "token=SIFT-ZIP-SECRET"));
        var (plan, scanner, _) = CreateScanner();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scanner.ScanFileWithResultAsync(
            zipPath,
            plan,
            new ScanOptions { EnableZipArchives = true },
            cancellationToken: cancellation.Token));
    }

    private string CreateZip(params (string Name, string Content)[] entries)
    {
        var path = Path.Combine(_temporaryDirectory, $"{Guid.NewGuid():N}.zip");
        using var file = File.Create(path);
        using var archive = new ZipArchive(file, ZipArchiveMode.Create, leaveOpen: false);
        WriteEntries(archive, entries);
        return path;
    }

    private static MemoryStream CreateZipStream(params (string Name, string Content)[] entries)
    {
        var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntries(archive, entries);
        }

        stream.Position = 0;
        return stream;
    }

    private static void WriteEntries(
        ZipArchive archive,
        IEnumerable<(string Name, string Content)> entries)
    {
        foreach (var (name, content) in entries)
        {
            using var writer = new StreamWriter(
                archive.CreateEntry(name, CompressionLevel.Optimal).Open(),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            writer.Write(content);
        }
    }

    private static (ScannerExecutionPlan Plan, FileScanner Scanner, RecordingLogger<FileScanner> Logger) CreateScanner(
        List<string>? includePaths = null)
    {
        var classifier = new Classifier
        {
            Id = Guid.NewGuid(),
            Name = "ZIP secret",
            Matches =
            [
                new ClassifierMatch
                {
                    Target = RuleTarget.Content,
                    Patterns = ["SIFT-ZIP-SECRET"],
                    Keywords = ["token"],
                    IncludedExtensions = [".txt"],
                    IsLiteral = true
                }
            ]
        };
        var policy = new Policy
        {
            Id = Guid.NewGuid(),
            Name = "ZIP secret",
            Severity = Severity.High,
            Configuration = new PolicyConfiguration
            {
                IncludePaths = includePaths ?? []
            }
        };
        var link = new PolicyClassifier
        {
            Policy = policy,
            PolicyId = policy.Id,
            Classifier = classifier,
            ClassifierId = classifier.Id
        };
        policy.PolicyClassifiers.Add(link);
        classifier.PolicyClassifiers.Add(link);

        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers([classifier]);
        var plan = ScannerExecutionPlan.Create(
            optimizer,
            new Dictionary<Guid, List<Policy>> { [classifier.Id] = [policy] });
        var logger = new RecordingLogger<FileScanner>();
        var scanner = new FileScanner(
            logger,
            new ContentExtractor(),
            new ValidatorFactory(Array.Empty<IValidator>()));
        return (plan, scanner, logger);
    }
}
