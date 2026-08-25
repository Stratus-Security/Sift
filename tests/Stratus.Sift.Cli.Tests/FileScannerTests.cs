using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;
using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Validators;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using System.Text;
using Stratus.Sift.Scanner.Models;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace Stratus.Sift.Cli.Tests;

public class FileScannerTests : IDisposable
{
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly ConcurrentQueue<(LogLevel Level, string Message)> _entries = new();

        public IReadOnlyCollection<(LogLevel Level, string Message)> Entries => _entries.ToArray();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => _entries.Enqueue((logLevel, formatter(state, exception)));
    }

    private sealed class NonSeekableStream : Stream
    {
        private readonly Stream _inner;

        public NonSeekableStream(Stream inner)
        {
            _inner = inner;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => _inner.Read(buffer);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => _inner.ReadAsync(buffer, cancellationToken);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => _inner.ReadAsync(buffer, offset, count, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private sealed class NonSeekableFileScanner : FileScanner
    {
        private readonly Func<Stream> _streamFactory;

        public NonSeekableFileScanner(Func<Stream> streamFactory)
            : base(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()))
        {
            _streamFactory = streamFactory;
        }

        protected override Stream? OpenStream(string filePath)
        {
            return _streamFactory();
        }
    }

    private readonly string _tempDirectory;

    public FileScannerTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory))
        {
            Directory.Delete(_tempDirectory, true);
        }
    }

    private (List<Classifier>, List<Policy>) CreateConfig(
        string name,
        List<string> patterns,
        Severity severity,
        List<string>? keywords = null,
        List<string>? extensions = null,
        RuleTarget target = RuleTarget.Content,
        Classifier? subClassifier = null,
        bool isLiteral = false,
        bool caseSensitive = false)
    {
        var c = new Classifier
        {
            Id = Guid.NewGuid(),
            Name = name,
            Matches = new List<ClassifierMatch>
            {
                new ClassifierMatch
                {
                    Patterns = patterns,
                    Keywords = keywords ?? new(),
                    IncludedExtensions = extensions ?? new(),
                    Target = target,
                    IsLiteral = isLiteral,
                    CaseSensitive = caseSensitive
                }
            }
        };

        if (subClassifier != null)
        {
            c.SubClassifiers.Add(subClassifier);
        }

        var p = new Policy
        {
            Id = Guid.NewGuid(),
            Name = name,
            Severity = severity
        };

        var pc = new PolicyClassifier { Policy = p, Classifier = c, PolicyId = p.Id, ClassifierId = c.Id };
        p.PolicyClassifiers.Add(pc);
        c.PolicyClassifiers.Add(pc);

        return (new List<Classifier>{c}, new List<Policy>{p});
    }

    [Fact]
    public async Task ScanFileWithResultAsync_PropagatesCancellationWithoutLoggingAFileFailure()
    {
        var filePath = Path.Combine(_tempDirectory, "cancelled.txt");
        await File.WriteAllTextAsync(filePath, new string('a', 128 * 1024));
        var (classifiers, policies) = CreateConfig(
            "Cancellation test",
            ["secret"],
            Severity.High,
            extensions: [".txt"]);
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);
        var policyMap = policies
            .SelectMany(policy => policy.PolicyClassifiers.Select(link => (link.ClassifierId, policy)))
            .GroupBy(item => item.ClassifierId)
            .ToDictionary(group => group.Key, group => group.Select(item => item.policy).ToList());
        var logger = new RecordingLogger<FileScanner>();
        var scanner = new FileScanner(
            logger,
            new ContentExtractor(),
            new ValidatorFactory(Enumerable.Empty<IValidator>()));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scanner.ScanFileWithResultAsync(
            filePath,
            optimizer,
            policyMap,
            cancellationToken: cancellation.Token));

        Assert.DoesNotContain(logger.Entries, entry => entry.Level == LogLevel.Error);
    }

    [Fact]
    public void ScanFile_ShouldDetectAwsKey_WhenFileContainsSecret()
    {
        // Arrange
        var fileName = "config.json";
        var filePath = Path.Combine(_tempDirectory, fileName);
        var secret = "AKIA1234567890ABCDEF";
        var content = $@"
{{
    ""app_name"": ""test-app"",
    ""aws_access_key"": ""{secret}"",
    ""region"": ""us-east-1""
}}";
        File.WriteAllText(filePath, content);

        var (classifiers, policies) = CreateConfig(
            "AWS Access Key",
            new List<string> { "(AWS|AKIA)[0-9A-Z]{16}" },
            Severity.Critical,
            keywords: new List<string> { "aws_access_key" },
            extensions: new List<string> { ".json" }
        );

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        // Act
        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        // Assert
        Assert.Single(findings);
        var finding = findings.First();
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(secret, finding.RedactedValue);
        Assert.Contains("aws_access_key", finding.Snippet);
        Assert.Contains(secret, finding.Snippet);
    }

    [Fact]
    public void ScanFile_ShouldIgnoreBinaryFiles()
    {
        // Arrange
        var fileName = "binary.dat";
        var filePath = Path.Combine(_tempDirectory, fileName);

        using (var fs = new FileStream(filePath, FileMode.Create))
        {
            fs.WriteByte(0x41); // 'A'
            fs.WriteByte(0x00); // Null byte
            fs.WriteByte(0x42); // 'B'
        }

        var (classifiers, policies) = CreateConfig(
            "Any Text",
            new List<string> { ".*" },
            Severity.Low,
            keywords: new List<string> { "A" },
            extensions: new List<string> { ".dat" }
        );

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        // Act
        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void ScanFile_ShouldSkipRule_WhenKeywordMissing()
    {
        // Arrange
        var fileName = "notes.txt";
        var filePath = Path.Combine(_tempDirectory, fileName);
        var content = "Here is a key: AKIA1234567890ABCDEF";
        File.WriteAllText(filePath, content);

        var (classifiers, policies) = CreateConfig(
            "AWS Access Key",
            new List<string> { "AKIA[0-9A-Z]{16}" },
            Severity.Critical,
            keywords: new List<string> { "AWS" }, // REQUIRED keyword missing in content
            extensions: new List<string> { ".txt" }
        );

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        // Act
        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void ScanFile_ShouldIgnoreInactivePolicies()
    {
        var filePath = Path.Combine(_tempDirectory, "settings.txt");
        File.WriteAllText(filePath, "token=AKIA1234567890ABCDEF");

        var (classifiers, policies) = CreateConfig(
            "AWS Access Key",
            new List<string> { "AKIA[0-9A-Z]{16}" },
            Severity.Critical,
            keywords: new List<string> { "token" },
            extensions: new List<string> { ".txt" });

        policies[0].Active = false;

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void ScanFile_ShouldSkipFinding_WhenConfiguredValidatorIsUnknown()
    {
        var filePath = Path.Combine(_tempDirectory, "validator.txt");
        File.WriteAllText(filePath, "token=AKIA1234567890ABCDEF");

        var (classifiers, policies) = CreateConfig(
            "Token detector",
            new List<string> { "AKIA[0-9A-Z]{16}" },
            Severity.Critical,
            keywords: new List<string> { "token" },
            extensions: new List<string> { ".txt" });

        classifiers[0].Validator = "MadeUpValidator";

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void ScanFile_ShouldNotPopulateLlmPayload_WhenClassifierDisablesLlmValidation()
    {
        var filePath = Path.Combine(_tempDirectory, "jwt.txt");
        File.WriteAllText(filePath, "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature");

        var (classifiers, policies) = CreateConfig(
            "JSON Web Token (JWT)",
            new List<string> { "eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+" },
            Severity.High,
            keywords: new List<string> { "Bearer" },
            extensions: new List<string> { ".txt" });

        classifiers[0].EnableLlmValidation = false;

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        var finding = Assert.Single(findings);
        Assert.True(string.IsNullOrEmpty(finding.LlmValidationCandidate));
        Assert.True(string.IsNullOrEmpty(finding.LlmValidationContext));
        Assert.True(string.IsNullOrEmpty(finding.LlmPromptVersion));
    }

    [Fact]
    public void ScanFile_DefaultContentMatchesRemainCaseInsensitive()
    {
        var filePath = Path.Combine(_tempDirectory, "case-default.txt");
        File.WriteAllText(filePath, "secretvalue");

        var (classifiers, policies) = CreateConfig(
            "Case default",
            new List<string> { "SecretValue" },
            Severity.Medium,
            extensions: new List<string> { ".txt" },
            isLiteral: true);

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(findings);
    }

    [Fact]
    public void ScanFile_CaseSensitiveContentMatchesRequireExactCase()
    {
        var filePath = Path.Combine(_tempDirectory, "case-sensitive.txt");
        File.WriteAllText(filePath, "secretvalue");

        var (classifiers, policies) = CreateConfig(
            "Case sensitive content",
            new List<string> { "SecretValue" },
            Severity.Medium,
            extensions: new List<string> { ".txt" },
            isLiteral: true,
            caseSensitive: true);

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Empty(findings);

        File.WriteAllText(filePath, "SecretValue");
        findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(findings);
    }

    [Fact]
    public void ScanFile_CaseSensitiveFileNameMatchesRequireExactCase()
    {
        var lowercasePath = Path.Combine(_tempDirectory, "sam");
        File.WriteAllText(lowercasePath, "placeholder");
        var exactPath = Path.Combine(_tempDirectory, "SAM");
        File.WriteAllText(exactPath, "placeholder");

        var (classifiers, policies) = CreateConfig(
            "Case sensitive filename",
            new List<string> { "SAM" },
            Severity.Critical,
            target: RuleTarget.FileName,
            isLiteral: true,
            caseSensitive: true);

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        var lowercaseFindings = scanner.ScanFile(lowercasePath, classifiers, policies).ToList();
        var exactFindings = scanner.ScanFile(exactPath, classifiers, policies).ToList();

        Assert.Empty(lowercaseFindings);
        Assert.Single(exactFindings);
    }

    [Fact]
    public void ScanFile_ShouldDetectSecretInDocx()
    {
        // Arrange
        var fileName = "secret.docx";
        var filePath = Path.Combine(_tempDirectory, fileName);
        var secret = "AKIA1234567890ABCDEF";

        using (var doc = WordprocessingDocument.Create(filePath, WordprocessingDocumentType.Document))
        {
            var mainPart = doc.AddMainDocumentPart();
            mainPart.Document = new Document();
            var body = mainPart.Document.AppendChild(new Body());
            var para = body.AppendChild(new Paragraph());
            var run = para.AppendChild(new Run());
            run.AppendChild(new Text($"This is a confidential document containing AWS Key: {secret}"));
        }

        var (classifiers, policies) = CreateConfig(
            "AWS Access Key",
            new List<string> { "(AWS|AKIA)[0-9A-Z]{16}" },
            Severity.Critical,
            keywords: new List<string> { "AWS" },
            extensions: new List<string> { ".docx" }
        );

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        // Act
        var findings = scanner.ScanFile(filePath, classifiers, policies, new Stratus.Sift.Scanner.Models.ScanOptions { EnableBinaryDocuments = true }).ToList();

        // Assert
        Assert.Single(findings);
        Assert.StartsWith("AK", findings.First().RedactedValue);
        Assert.Contains(secret, findings.First().Snippet);
    }

    [Fact]
    public void ScanFile_ShouldRunSubClassifier_WhenParentMatchesFilename()
    {
        // Arrange
        var fileName = "unattend.xml";
        var filePath = Path.Combine(_tempDirectory, fileName);
        var secret = "<AdministratorPassword>MySecretPassword123</AdministratorPassword>";
        var content = $@"
<Unattend>
    {secret}
</Unattend>";
        File.WriteAllText(filePath, content);

        var subClassifier = new Classifier
        {
            Id = Guid.NewGuid(),
            Name = "Cleartext Admin Password",
            Matches = new List<ClassifierMatch>
            {
                new ClassifierMatch
                {
                    Target = RuleTarget.Content,
                    Patterns = new List<string> { "<AdministratorPassword>.*<\\/AdministratorPassword>" },
                    Keywords = new List<string> { "<AdministratorPassword>" },
                    IncludedExtensions = new List<string>() // Empty!
                }
            }
        };

        // Note: For SubClassifiers to trigger Policies, the Policy must target the SubClassifier OR the parent Policy handles it?
        // In the new model, ClassifierOptimizer handles sub-classifiers.
        // We need a Policy for the SubClassifier to report an issue.

        var subPolicy = new Policy
        {
            Id = Guid.NewGuid(),
            Name = "Cleartext Admin Password",
            Severity = Severity.High
        };
        var pcSub = new PolicyClassifier { Policy = subPolicy, Classifier = subClassifier, PolicyId = subPolicy.Id, ClassifierId = subClassifier.Id };
        subPolicy.PolicyClassifiers.Add(pcSub);
        subClassifier.PolicyClassifiers.Add(pcSub);

        var (classifiers, policies) = CreateConfig(
            "Unattended Install File",
            new List<string> { "unattend.xml" },
            Severity.Low,
            target: RuleTarget.FileName,
            subClassifier: subClassifier
        );

        // Add subPolicy to policies list
        policies.Add(subPolicy);

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));

        // Act
        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.RuleName == "Unattended Install File");
        Assert.Contains(findings, f => f.RuleName == "Cleartext Admin Password");
    }

    [Fact]
    public void ScanFile_ShouldPopulateRuleStats_WhenRuleMatches()
    {
        // Arrange
        var fileName = "stats_test.txt";
        var filePath = Path.Combine(_tempDirectory, fileName);
        var secret = "AKIA1234567890ABCDEF";
        var content = $"{secret}\n{secret}\n{secret}";
        File.WriteAllText(filePath, content);

        var (classifiers, policies) = CreateConfig(
            "AWS Access Key",
            new List<string> { "(AWS|AKIA)[0-9A-Z]{16}" },
            Severity.Critical,
            keywords: new List<string> { "AKIA" },
            extensions: new List<string> { ".txt" }
        );

        var scanner = new FileScanner(NullLogger<FileScanner>.Instance, new ContentExtractor(), new ValidatorFactory(Enumerable.Empty<IValidator>()));
        var stats = new System.Collections.Concurrent.ConcurrentDictionary<string, int>();

        // Act
        scanner.ScanFile(filePath, classifiers, policies, ruleStats: stats);

        // Assert
        Assert.True(stats.ContainsKey("AWS Access Key"));
        Assert.Equal(3, stats["AWS Access Key"]);
    }

    [Fact]
    public void ScanFile_ShouldHandleNonSeekableStreams()
    {
        // Arrange
        var fileName = "config.txt";
        var filePath = Path.Combine(_tempDirectory, fileName);
        var secret = "AKIA1234567890ABCDEF";
        var content = $"aws_access_key={secret}";

        var (classifiers, policies) = CreateConfig(
            "AWS Access Key",
            new List<string> { "(AWS|AKIA)[0-9A-Z]{16}" },
            Severity.Critical,
            keywords: new List<string> { "aws_access_key" },
            extensions: new List<string> { ".txt" }
        );

        var scanner = new NonSeekableFileScanner(() =>
            new NonSeekableStream(new MemoryStream(Encoding.UTF8.GetBytes(content), writable: false)));

        // Act
        var findings = scanner.ScanFile(filePath, classifiers, policies).ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("AWS Access Key", findings[0].RuleName);
        Assert.Contains(secret, findings[0].Snippet);
    }

    [Fact]
    public void ScanOptions_DefaultsToUnlimitedReadThroughput()
    {
        Assert.Equal(0, new ScanOptions().MaxDiskReadBytesPerSecond);
    }

    [Fact]
    public async Task CompiledExecutionPlan_MatchesLegacyScannerResults()
    {
        var filePath = Path.Combine(_tempDirectory, "compiled-plan.txt");
        File.WriteAllText(filePath, "api_secret=SIFT-COMPILED-PLAN-SECRET");
        var (classifiers, policies) = CreateConfig(
            "Compiled plan secret",
            ["SIFT-COMPILED-PLAN-SECRET"],
            Severity.High,
            keywords: ["api_secret"],
            extensions: [".txt"],
            isLiteral: true);
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);
        var policyMap = new Dictionary<Guid, List<Policy>>
        {
            [classifiers[0].Id] = policies
        };
        var plan = ScannerExecutionPlan.Create(optimizer, policyMap);
        var scanner = new FileScanner(
            NullLogger<FileScanner>.Instance,
            new ContentExtractor(),
            new ValidatorFactory([]));

        var legacy = scanner.ScanFile(filePath, optimizer, policyMap).ToList();
        var compiled = await scanner.ScanFileWithResultAsync(filePath, plan);

        var legacyFinding = Assert.Single(legacy);
        var compiledFinding = Assert.Single(compiled.Issues);
        Assert.Equal(legacyFinding.RuleName, compiledFinding.RuleName);
        Assert.Equal(legacyFinding.RedactedValue, compiledFinding.RedactedValue);
        Assert.Equal(legacyFinding.Severity, compiledFinding.Severity);
    }

    [Fact]
    public async Task ScanDiagnostics_ReportsOpenedFilesAndPhysicalReads()
    {
        var filePath = Path.Combine(_tempDirectory, "diagnostics.txt");
        File.WriteAllText(filePath, "token=SIFT-DIAGNOSTICS-SECRET");
        var (classifiers, policies) = CreateConfig(
            "Diagnostics secret",
            ["SIFT-DIAGNOSTICS-SECRET"],
            Severity.High,
            keywords: ["token"],
            extensions: [".txt"],
            isLiteral: true);
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);
        var plan = ScannerExecutionPlan.Create(
            optimizer,
            new Dictionary<Guid, List<Policy>> { [classifiers[0].Id] = policies });
        var diagnostics = new ScanDiagnostics();
        var scanner = new FileScanner(
            NullLogger<FileScanner>.Instance,
            new ContentExtractor(),
            new ValidatorFactory([]));

        var result = await scanner.ScanFileWithResultAsync(
            filePath,
            plan,
            new ScanOptions { Diagnostics = diagnostics });

        Assert.Single(result.Issues);
        var snapshot = diagnostics.Snapshot();
        Assert.Equal(1, snapshot.FilesOpened);
        Assert.Equal(new FileInfo(filePath).Length, snapshot.PhysicalBytesRead);
        Assert.True(snapshot.AggregateRuleEvaluationTime >= TimeSpan.Zero);
    }
}
