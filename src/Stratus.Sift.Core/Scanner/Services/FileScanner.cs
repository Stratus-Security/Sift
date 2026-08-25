using System.Text.RegularExpressions;
using System.Text;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Validation;
using Stratus.Sift.Scanner.Models;
using Stratus.Sift.Scanner.Interfaces;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Buffers;
using System.IO.Enumeration;
using System.Diagnostics;
using Stratus.Sift.Core;

namespace Stratus.Sift.Scanner.Services;

public class FileScanner : IScanner
{
    private readonly ILogger<FileScanner> _logger;
    private readonly ContentExtractor _contentExtractor;
    private readonly ValidatorFactory _validatorFactory;
    private readonly SharedReadRateLimiter _readRateLimiter = new();
    private const int BufferSize = 64 * 1024; // 64KB
    private const int OverlapSize = 4 * 1024; // 4KB - Sufficient for most lines/secrets
    private const int ValidationContextRadius = 512;
    private static readonly List<AclEntry> _emptyAclEntries = new();

    public FileScanner(ILogger<FileScanner> logger, ContentExtractor contentExtractor, ValidatorFactory validatorFactory)
    {
        _logger = logger;
        _contentExtractor = contentExtractor;
        _validatorFactory = validatorFactory;
    }

    public IEnumerable<ScanFinding> ScanFile(string filePath, IEnumerable<Classifier> classifiers, IEnumerable<Policy> policies, ScanOptions? options = null, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null)
    {
        return ScanFileWithResult(filePath, classifiers, policies, options, ruleStats).Issues;
    }

    public ScanResult ScanFileWithResult(string filePath, IEnumerable<Classifier> classifiers, IEnumerable<Policy> policies, ScanOptions? options = null, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null)
    {
        var optimizer = new ClassifierOptimizer(logger: _logger);
        var validClassifiers = ClassifierRuntimeValidator.FilterValidClassifiers(classifiers, _logger);
        optimizer.LoadClassifiers(validClassifiers);

        var policyMap = new Dictionary<Guid, List<Policy>>();
        foreach (var p in policies)
        {
            if (!p.Active || p.PolicyClassifiers == null) continue;
            foreach (var pc in p.PolicyClassifiers)
            {
                if (!policyMap.ContainsKey(pc.ClassifierId)) policyMap[pc.ClassifierId] = new List<Policy>();
                policyMap[pc.ClassifierId].Add(p);
            }
        }

        var plan = ScannerExecutionPlan.Create(optimizer, policyMap);
        return ScanFileInternalAsync(filePath, plan, options, null, "Unknown", null, null, null, null, ruleStats, CancellationToken.None).GetAwaiter().GetResult();
    }

    public IEnumerable<ScanFinding> ScanFile(string filePath, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, ScanOptions? options = null, string? exposure = null, string owner = "Unknown", List<AclEntry>? aclEntries = null, long? fileSize = null, string? ext = null, string? name = null, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null, IEnumerable<IgnoreRule>? ignoreRules = null)
    {
        var plan = ScannerExecutionPlan.Create(optimizer, policyMap, ignoreRules);
        return ScanFileInternalAsync(filePath, plan, options, exposure, owner, aclEntries, ext, name, fileSize, ruleStats, CancellationToken.None).GetAwaiter().GetResult().Issues;
    }

    public ScanResult ScanFileWithResult(string filePath, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, ScanOptions? options = null, string? exposure = null, string owner = "Unknown", List<AclEntry>? aclEntries = null, long? fileSize = null, string? ext = null, string? name = null, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null, IEnumerable<IgnoreRule>? ignoreRules = null)
    {
        var plan = ScannerExecutionPlan.Create(optimizer, policyMap, ignoreRules);
        return ScanFileInternalAsync(filePath, plan, options, exposure, owner, aclEntries, ext, name, fileSize, ruleStats, CancellationToken.None).GetAwaiter().GetResult();
    }

    public Task<ScanResult> ScanFileWithResultAsync(
        string filePath,
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        ScanOptions? options = null,
        string? exposure = null,
        string owner = "Unknown",
        List<AclEntry>? aclEntries = null,
        long? fileSize = null,
        string? ext = null,
        string? name = null,
        System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null,
        IEnumerable<IgnoreRule>? ignoreRules = null,
        CancellationToken cancellationToken = default) =>
        ScanFileInternalAsync(
            filePath,
            ScannerExecutionPlan.Create(optimizer, policyMap, ignoreRules),
            options,
            exposure,
            owner,
            aclEntries,
            ext,
            name,
            fileSize,
            ruleStats,
            cancellationToken);

    public Task<ScanResult> ScanFileWithResultAsync(
        string filePath,
        ScannerExecutionPlan plan,
        ScanOptions? options = null,
        string? exposure = null,
        string owner = "Unknown",
        List<AclEntry>? aclEntries = null,
        long? fileSize = null,
        string? ext = null,
        string? name = null,
        System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null,
        CancellationToken cancellationToken = default) =>
        ScanFileInternalAsync(
            filePath,
            plan,
            options,
            exposure,
            owner,
            aclEntries,
            ext,
            name,
            fileSize,
            ruleStats,
            cancellationToken);

    private static bool IsPathIncluded(string filePath, Policy policy)
    {
        if (policy.Configuration == null) return true;

        // 1. Check Include Paths (Allowlist)
        // If IncludePaths is specified, file MUST match at least one.
        // If empty, assume all paths are included (unless excluded).
        if (policy.Configuration.IncludePaths != null && policy.Configuration.IncludePaths.Any())
        {
            bool included = false;
            foreach (var pattern in policy.Configuration.IncludePaths)
            {
                if (FileSystemName.MatchesSimpleExpression(pattern, filePath))
                {
                    included = true;
                    break;
                }
            }
            if (!included) return false;
        }

        // 2. Check Exclude Paths (Blocklist)
        if (policy.Configuration.ExcludePaths != null && policy.Configuration.ExcludePaths.Any())
        {
            foreach (var pattern in policy.Configuration.ExcludePaths)
            {
                if (FileSystemName.MatchesSimpleExpression(pattern, filePath))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static Dictionary<Guid, List<Policy>> ScopePolicyMap(string filePath, ScannerExecutionPlan plan)
    {
        if (!plan.HasPathScopedPolicies)
        {
            return plan.PolicyMap;
        }

        var scopedPolicyMap = new Dictionary<Guid, List<Policy>>();
        foreach (var kvp in plan.PolicyMap)
        {
            var validPolicies = kvp.Value.Where(p => IsPathIncluded(filePath, p)).ToList();
            if (validPolicies.Any())
            {
                scopedPolicyMap[kvp.Key] = validPolicies;
            }
        }

        return scopedPolicyMap;
    }

    private async Task<ScanResult> ScanFileInternalAsync(string filePath, ScannerExecutionPlan plan, ScanOptions? options, string? exposure, string owner, List<AclEntry>? aclEntries, string? ext, string? name, long? fileSize, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats, CancellationToken cancellationToken)
    {
        options ??= new ScanOptions();
        var optimizer = plan.Optimizer;
        var ignoreRules = plan.IgnoreRules;

        ext ??= Path.GetExtension(filePath);
        name ??= Path.GetFileName(filePath);
        exposure ??= "Unknown";
        owner ??= "Unknown";
        aclEntries ??= _emptyAclEntries;

        var policyNameLookup = plan.PolicyNameLookup;

        // Pre-filter Policies based on Path Scope
        // We only want to evaluate policies that apply to this file path.
        // This optimizes performance by reducing the number of active policies.
        var scopedPolicyMap = ScopePolicyMap(filePath, plan);

        if (IgnoreRuleEvaluator.ShouldIgnore(filePath, ignoreRules))
        {
            return new ScanResult { Issues = Enumerable.Empty<ScanFinding>() };
        }

        List<ClassifierOptimizer.MetadataMatch>? directMetadataMatches = null;
        foreach (var metadataMatch in optimizer.GetMetadataMatches(filePath))
        {
            if (PathsReferToSameScope(metadataMatch.ResourcePath, filePath))
            {
                (directMetadataMatches ??= new List<ClassifierOptimizer.MetadataMatch>()).Add(metadataMatch);
            }
        }

        // If no policies apply to this path, we can skip content scanning entirely 
        // UNLESS we are in discovery mode (not implemented yet, assumed false for optimization).
        if (scopedPolicyMap.Count == 0)
        {
            options.Diagnostics?.RecordFileSkipped();
            return new ScanResult { Issues = Enumerable.Empty<ScanFinding>() };
        }

        var result = new ScanResult();
        List<ScanFinding>? issues = null;
        List<ClassifierOptimizer>? subOptimizers = null;
        bool metadataClassifierMatched = false;

        try
        {
            // 2. Check Metadata Classifiers
            foreach (var metadataMatch in directMetadataMatches ?? [])
            {
                var classifier = metadataMatch.Classifier;
                metadataClassifierMatched = true;
                result.AddMatchedClassifier(classifier.Name);

                if (scopedPolicyMap.TryGetValue(classifier.Id, out var policies))
                {
                    foreach (var policy in policies)
                    {
                        if (ruleStats != null) ruleStats.AddOrUpdate(classifier.Name, 1, (_, c) => c + 1);

                        (issues ??= new List<ScanFinding>()).Add(new ScanFinding
                        {
                            Id = Guid.NewGuid(),
                            RuleName = policy.Name,
                            PolicyName = policy.Name,
                            ClassifierName = classifier.Name,
                            ResourcePath = metadataMatch.ResourcePath,
                            Severity = policy.Severity,
                            ConfidenceLevel = ConfidenceLevel.High,
                            RedactedValue = "[METADATA MATCH]",
                            Exposure = exposure,
                            Owner = owner,
                            DetectedAt = DateTime.UtcNow,
                            AclEntries = aclEntries,
                            IsReportOnly = policy.IsReportOnly
                        });

                        if (policy.StopOnMatch)
                        {
                            result.Issues = AggregateIssues(issues, policyNameLookup);
                            return result;
                        }

                    }
                }

                var subOpt = optimizer.GetSubOptimizer(classifier);
                if (subOpt != null)
                {
                    subOptimizers ??= new List<ClassifierOptimizer>();
                    subOptimizers.Add(subOpt);
                }
            }

            // 3. Rule-Based Extension Allowlist
            if (!metadataClassifierMatched && !optimizer.HasRulesForExtension(ext))
            {
                options.Diagnostics?.RecordFileSkipped();
                result.Issues = Enumerable.Empty<ScanFinding>();
                return result;
            }

            if (!optimizer.HasContentClassifiers && (subOptimizers == null || subOptimizers.Count == 0))
            {
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            if (fileSize.HasValue && fileSize.Value == 0)
            {
                options.Diagnostics?.RecordFileSkipped();
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            // Content Extraction
            if (options.EnableBinaryDocuments && _contentExtractor.Supports(ext))
            {
                try
                {
                    string extractedText = _contentExtractor.Extract(filePath);
                    if (!string.IsNullOrWhiteSpace(extractedText))
                    {
                        var bufferIssues = ScanBuffer(extractedText.AsSpan(), optimizer, scopedPolicyMap, filePath, ext, name, exposure, owner, aclEntries, subOptimizers, ruleStats, policyNameLookup);
                        (issues ??= new List<ScanFinding>()).AddRange(bufferIssues.Issues);
                        foreach (var c in bufferIssues.EnumerateMatchedClassifiers()) result.AddMatchedClassifier(c);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Failed to extract content from file: {Path}", filePath);
                }
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            // Binary Check & Stream Opening
            Stream? streamObj = null;
            try
            {
                streamObj = OpenStream(filePath);
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }

            if (streamObj == null)
            {
                options.Diagnostics?.RecordFileSkipped();
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            options.Diagnostics?.RecordFileOpened();

            using var stream = new RateLimitedReadStream(
                streamObj,
                _readRateLimiter,
                options.MaxDiskReadBytesPerSecond,
                options.Diagnostics);

            var effectiveFileSize = fileSize;
            if (!effectiveFileSize.HasValue && stream.CanSeek)
            {
                effectiveFileSize = stream.Length;
            }

            if (effectiveFileSize.HasValue && effectiveFileSize.Value == 0)
            {
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            if (!stream.CanSeek)
            {
                long? forwardScanLimit = effectiveFileSize.HasValue && effectiveFileSize.Value <= options.MaxFileSize
                    ? null
                    : options.HeadSize;

                var scanRes = await ScanStreamInternalAsync(stream, optimizer, scopedPolicyMap, filePath, ext, name, exposure, owner, aclEntries, cancellationToken, ruleStats, forwardScanLimit, ignoreRules, policyNameLookup, subOptimizers, preflightCompleted: true, rejectBinary: !options.EnableBinaryDocuments, diagnostics: options.Diagnostics);
                (issues ??= new List<ScanFinding>()).AddRange(scanRes.Issues);
                foreach (var c in scanRes.EnumerateMatchedClassifiers()) result.AddMatchedClassifier(c);
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            // Full Scan
            if (effectiveFileSize!.Value <= options.MaxFileSize)
            {
                var scanRes = await ScanStreamInternalAsync(stream, optimizer, scopedPolicyMap, filePath, ext, name, exposure, owner, aclEntries, cancellationToken, ruleStats, null, ignoreRules, policyNameLookup, subOptimizers, preflightCompleted: true, rejectBinary: !options.EnableBinaryDocuments, diagnostics: options.Diagnostics);
                (issues ??= new List<ScanFinding>()).AddRange(scanRes.Issues);
                foreach (var c in scanRes.EnumerateMatchedClassifiers()) result.AddMatchedClassifier(c);
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            // Large File: Head + Tail
            // Head
            var headResults = await ScanStreamInternalAsync(stream, optimizer, scopedPolicyMap, filePath, ext, name, exposure, owner, aclEntries, cancellationToken, ruleStats, options.HeadSize, ignoreRules, policyNameLookup, subOptimizers, preflightCompleted: true, rejectBinary: !options.EnableBinaryDocuments, diagnostics: options.Diagnostics);
            if (headResults != null)
            {
                (issues ??= new List<ScanFinding>()).AddRange(headResults.Issues);
                foreach (var c in headResults.EnumerateMatchedClassifiers()) result.AddMatchedClassifier(c);
            }

            // Tail
            if (effectiveFileSize.Value > options.TailSize)
            {
                stream.Seek(-options.TailSize, SeekOrigin.End);
                var tailResults = await ScanStreamInternalAsync(stream, optimizer, scopedPolicyMap, filePath, ext, name, exposure, owner, aclEntries, cancellationToken, ruleStats, options.TailSize, ignoreRules, policyNameLookup, subOptimizers, preflightCompleted: true, rejectBinary: !options.EnableBinaryDocuments, diagnostics: options.Diagnostics);
                if (tailResults != null)
                {
                    (issues ??= new List<ScanFinding>()).AddRange(tailResults.Issues);
                    foreach (var c in tailResults.EnumerateMatchedClassifiers()) result.AddMatchedClassifier(c);
                }
            }

            result.Issues = AggregateIssues(issues, policyNameLookup);
            return result;
        }
        catch (UnauthorizedAccessException)
        {
            //_logger.LogDebug("Access denied to file: {Path}. Error: {Message}", filePath, ex.Message);
        }
        catch (IOException ex)
        {
            _logger.LogDebug("IO error scanning file: {Path}. Error: {Message}", filePath, ex.Message);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning file: {Path}", filePath);
        }

        result.Issues = AggregateIssues(issues, policyNameLookup);
        return result;
    }

    private sealed class RateLimitedReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly SharedReadRateLimiter _limiter;
        private readonly long _bytesPerSecond;
        private readonly ScanDiagnostics? _diagnostics;
        private const int LeaseSize = 256 * 1024;
        private const int ProbeAllowance = 1024;
        private int _remainingLeaseBytes;

        public RateLimitedReadStream(
            Stream inner,
            SharedReadRateLimiter limiter,
            long bytesPerSecond,
            ScanDiagnostics? diagnostics)
        {
            _inner = inner;
            _limiter = limiter;
            _bytesPerSecond = bytesPerSecond;
            _diagnostics = diagnostics;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            EnsureLeaseAsync(GetExpectedReadSize(count), CancellationToken.None)
                .AsTask()
                .GetAwaiter()
                .GetResult();
            var read = _inner.Read(buffer, offset, count);
            _remainingLeaseBytes -= read;
            _diagnostics?.RecordBytesRead(read);
            return read;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await EnsureLeaseAsync(GetExpectedReadSize(buffer.Length), cancellationToken);
            var read = await _inner.ReadAsync(buffer, cancellationToken);
            _remainingLeaseBytes -= read;
            _diagnostics?.RecordBytesRead(read);
            return read;
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken) =>
            ReadArrayAsync(buffer, offset, count, cancellationToken);

        private async Task<int> ReadArrayAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            await EnsureLeaseAsync(GetExpectedReadSize(count), cancellationToken);
            var read = await _inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
            _remainingLeaseBytes -= read;
            _diagnostics?.RecordBytesRead(read);
            return read;
        }

        private int GetExpectedReadSize(int requestedBytes)
        {
            if (!_inner.CanSeek)
            {
                return requestedBytes;
            }

            return (int)Math.Min(requestedBytes, Math.Max(0, _inner.Length - _inner.Position));
        }

        private async ValueTask EnsureLeaseAsync(int expectedBytes, CancellationToken cancellationToken)
        {
            if (_bytesPerSecond <= 0)
            {
                return;
            }

            if (expectedBytes <= _remainingLeaseBytes)
            {
                return;
            }

            var minimumBytes = expectedBytes - Math.Max(0, _remainingLeaseBytes);
            var remainingLength = _inner.CanSeek
                ? Math.Max(0, _inner.Length - _inner.Position)
                : LeaseSize;
            var repeatedProbeBytes = Math.Min(ProbeAllowance, remainingLength);
            var preferredLease = (int)Math.Min(
                LeaseSize,
                Math.Max(minimumBytes, remainingLength + repeatedProbeBytes));
            var limiterWait = await _limiter.AcquireAsync(preferredLease, _bytesPerSecond, cancellationToken);
            _diagnostics?.RecordLimiterWait(limiterWait);
            _remainingLeaseBytes = Math.Max(0, _remainingLeaseBytes) + preferredLease;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync() => _inner.DisposeAsync();
    }

    public async Task<ScanResult> ScanStreamAsync(Stream stream, string fileName, IEnumerable<Classifier> classifiers, IEnumerable<Policy> policies, IEnumerable<IgnoreRule>? ignoreRules = null, string exposure = "Unknown", string owner = "Unknown", List<AclEntry>? aclEntries = null, CancellationToken cancellationToken = default, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null)
    {
        var optimizer = new ClassifierOptimizer(logger: _logger);
        optimizer.LoadClassifiers(classifiers);

        var policyMap = new Dictionary<Guid, List<Policy>>();
        foreach (var p in policies)
        {
            if (!p.Active || p.PolicyClassifiers == null) continue;
            foreach (var pc in p.PolicyClassifiers)
            {
                if (!policyMap.ContainsKey(pc.ClassifierId)) policyMap[pc.ClassifierId] = new List<Policy>();
                policyMap[pc.ClassifierId].Add(p);
            }
        }

        return await ScanStreamAsync(stream, fileName, optimizer, policyMap, ignoreRules, exposure, owner, aclEntries, cancellationToken, ruleStats);
    }

    public async Task<ScanResult> ScanStreamAsync(Stream stream, string fileName, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, IEnumerable<IgnoreRule>? ignoreRules = null, string exposure = "Unknown", string owner = "Unknown", List<AclEntry>? aclEntries = null, CancellationToken cancellationToken = default, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null)
    {
        var plan = ScannerExecutionPlan.Create(optimizer, policyMap, ignoreRules);
        return await ScanStreamAsync(
            stream,
            fileName,
            plan,
            options: null,
            exposure,
            owner,
            aclEntries,
            cancellationToken,
            ruleStats);
    }

    public async Task<ScanResult> ScanStreamAsync(
        Stream stream,
        string fileName,
        ScannerExecutionPlan plan,
        ScanOptions? options = null,
        string exposure = "Unknown",
        string owner = "Unknown",
        List<AclEntry>? aclEntries = null,
        CancellationToken cancellationToken = default,
        System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null)
    {
        options ??= new ScanOptions();
        var ext = Path.GetExtension(fileName);
        var name = Path.GetFileName(fileName);
        aclEntries ??= new List<AclEntry>();
        var scopedPolicyMap = ScopePolicyMap(fileName, plan);
        if (scopedPolicyMap.Count == 0)
        {
            options.Diagnostics?.RecordFileSkipped();
            return new ScanResult { Issues = Enumerable.Empty<ScanFinding>() };
        }

        options.Diagnostics?.RecordFileOpened();
        var measuredStream = new RateLimitedReadStream(
            stream,
            _readRateLimiter,
            options.MaxDiskReadBytesPerSecond,
            options.Diagnostics);

        return await ScanStreamInternalAsync(
            measuredStream,
            plan.Optimizer,
            scopedPolicyMap,
            fileName,
            ext,
            name,
            exposure,
            owner,
            aclEntries,
            cancellationToken,
            ruleStats,
            limitBytes: null,
            plan.IgnoreRules,
            plan.PolicyNameLookup,
            diagnostics: options.Diagnostics);
    }

    private async Task<ScanResult> ScanStreamInternalAsync(Stream stream, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, string fileName, string ext, string name, string exposure, string owner, List<AclEntry> aclEntries, CancellationToken cancellationToken, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null, long? limitBytes = null, IEnumerable<IgnoreRule>? ignoreRules = null, Dictionary<string, Policy>? policyLookup = null, List<ClassifierOptimizer>? preparedSubOptimizers = null, bool preflightCompleted = false, Encoding? preparedEncoding = null, bool rejectBinary = false, ScanDiagnostics? diagnostics = null)
    {
        var result = new ScanResult();
        List<ScanFinding>? issues = null;
        List<ClassifierOptimizer>? subOptimizers = preparedSubOptimizers;

        if (!preflightCompleted)
        {
        if (IgnoreRuleEvaluator.ShouldIgnore(fileName, ignoreRules))
        {
            return new ScanResult { Issues = Enumerable.Empty<ScanFinding>() };
        }

        // 1. Check Metadata Classifiers
        foreach (var metadataMatch in optimizer.GetMetadataMatches(fileName))
        {
            if (!PathsReferToSameScope(metadataMatch.ResourcePath, fileName)) continue;

            var classifier = metadataMatch.Classifier;
            result.AddMatchedClassifier(classifier.Name);

            // Evaluate Policies
            if (policyMap.TryGetValue(classifier.Id, out var policies))
            {
                foreach (var policy in policies)
                {
                    if (ruleStats != null) ruleStats.AddOrUpdate(classifier.Name, 1, (_, c) => c + 1);

                    (issues ??= new List<ScanFinding>()).Add(new ScanFinding
                    {
                        Id = Guid.NewGuid(),
                        RuleName = policy.Name,
                        PolicyName = policy.Name,
                        ClassifierName = classifier.Name,
                        ResourcePath = metadataMatch.ResourcePath,
                        Severity = policy.Severity,
                        ConfidenceLevel = ConfidenceLevel.High,
                        RedactedValue = "[METADATA MATCH]",
                        Exposure = exposure,
                        Owner = owner,
                        DetectedAt = DateTime.UtcNow,
                        AclEntries = aclEntries,
                        IsReportOnly = policy.IsReportOnly
                    });

                    if (policy.StopOnMatch)
                    {
                        result.Issues = AggregateIssues(issues, policyLookup);
                        return result;
                    }

                }
            }

            var subOpt = optimizer.GetSubOptimizer(classifier);
            if (subOpt != null)
            {
                (subOptimizers ??= new List<ClassifierOptimizer>()).Add(subOpt);
            }
        }
        }

        var encoding = preparedEncoding;
        Decoder? decoder = null;
        var bytePool = ArrayPool<byte>.Shared;
        var charPool = ArrayPool<char>.Shared;
        var usefulBytes = BufferSize - OverlapSize;
        if (stream.CanSeek)
        {
            usefulBytes = (int)Math.Min(usefulBytes, Math.Max(1, stream.Length - stream.Position));
        }
        if (limitBytes.HasValue)
        {
            usefulBytes = (int)Math.Min(usefulBytes, Math.Max(1, limitBytes.Value));
        }

        byte[] byteBuffer = bytePool.Rent(usefulBytes);
        char[]? buffer = null;
        var usefulChars = 0;
        var chunkClassifiers = new HashSet<Classifier>();

        try
        {
            int bufferOffset = 0;
            long totalBytesRead = 0;
            long totalCharsDecoded = 0;
            var firstRead = true;
            var stop = false;

            while (!stop)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requestedBytes = byteBuffer.Length;
                if (limitBytes.HasValue)
                {
                    var remainingBytes = limitBytes.Value - totalBytesRead;
                    if (remainingBytes <= 0) break;
                    requestedBytes = (int)Math.Min(requestedBytes, remainingBytes);
                }

                var bytesRead = await stream.ReadAsync(
                    byteBuffer.AsMemory(0, requestedBytes),
                    cancellationToken);
                var flushDecoder = bytesRead <= 0;
                if (flushDecoder && firstRead) break;
                totalBytesRead += bytesRead;

                var bytes = byteBuffer.AsSpan(0, bytesRead);
                if (firstRead)
                {
                    firstRead = false;
                    if (rejectBinary && SiftEvidence.LooksBinary(bytes))
                    {
                        diagnostics?.RecordFileSkipped();
                        return result;
                    }

                    encoding ??= DetectEncoding(bytes);
                    decoder = encoding.GetDecoder();
                    usefulChars = Math.Min(
                        BufferSize,
                        Math.Max(OverlapSize + 1, encoding.GetMaxCharCount(usefulBytes) + OverlapSize));
                    buffer = charPool.Rent(usefulChars);
                    var preamble = encoding.Preamble;
                    if (!preamble.IsEmpty && bytes.StartsWith(preamble))
                    {
                        bytes = bytes[preamble.Length..];
                    }
                }

                while (!bytes.IsEmpty || flushDecoder)
                {
                    decoder!.Convert(
                        bytes,
                        buffer!.AsSpan(bufferOffset, usefulChars - bufferOffset),
                        flush: flushDecoder,
                        out var bytesUsed,
                        out var charsUsed,
                        out var completed);
                    bytes = bytes[bytesUsed..];

                    if (charsUsed == 0)
                    {
                        if (completed || bytesUsed == 0) break;
                        continue;
                    }

                    var validLength = bufferOffset + charsUsed;
                    var span = buffer.AsSpan(0, validLength);
                    var ruleEvaluationStarted = Stopwatch.GetTimestamp();
                    chunkClassifiers.Clear();
                    optimizer.PopulateClassifiersForContent(span, chunkClassifiers, ext);

                    if (subOptimizers is { Count: > 0 })
                    {
                        foreach (var subOpt in subOptimizers)
                        {
                            subOpt.PopulateClassifiersForContent(span, chunkClassifiers, ext);
                        }
                    }

                    if (chunkClassifiers.Count > 0)
                    {
                        foreach (var c in chunkClassifiers) result.AddMatchedClassifier(c.Name);

                        stop = ScanChunk(span, chunkClassifiers, policyMap, fileName, ext, name, exposure, owner, aclEntries, optimizer, totalCharsDecoded, ref issues, subOptimizers, ruleStats, bufferOffset);
                    }
                    diagnostics?.RecordRuleEvaluation(Stopwatch.GetTimestamp() - ruleEvaluationStarted);
                    if (stop) break;

                    totalCharsDecoded += charsUsed;

                    bufferOffset = Math.Min(validLength, OverlapSize);
                    span[^bufferOffset..].CopyTo(buffer);
                    if (flushDecoder && completed) break;
                }

                if (flushDecoder) break;
            }
        }
        finally
        {
            bytePool.Return(byteBuffer);
            if (buffer != null) charPool.Return(buffer);
        }

        result.Issues = AggregateIssues(issues, policyLookup);
        return result;
    }

    private ScanResult ScanBuffer(ReadOnlySpan<char> content, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, string filePath, string ext, string name, string exposure, string owner, List<AclEntry> aclEntries, List<ClassifierOptimizer>? subOptimizers = null, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null, Dictionary<string, Policy>? policyLookup = null)
    {
        var result = new ScanResult();
        var classifiers = new HashSet<Classifier>();
        optimizer.PopulateClassifiersForContent(content, classifiers, ext);
        if (subOptimizers != null)
        {
            foreach (var subOpt in subOptimizers)
            {
                subOpt.PopulateClassifiersForContent(content, classifiers, ext);
            }
        }

        foreach (var c in classifiers) result.AddMatchedClassifier(c.Name);

        if (classifiers.Count == 0) return result;

        List<ScanFinding>? issues = null;
        ScanChunk(content, classifiers, policyMap, filePath, ext, name, exposure, owner, aclEntries, optimizer, 0, ref issues, subOptimizers, ruleStats);
        result.Issues = AggregateIssues(issues, policyLookup);
        return result;
    }

    private bool ScanChunk(ReadOnlySpan<char> chunk, IEnumerable<Classifier> classifiers, Dictionary<Guid, List<Policy>> policyMap, string filePath, string ext, string name, string exposure, string owner, List<AclEntry> aclEntries, ClassifierOptimizer optimizer, long offset, ref List<ScanFinding>? issues, List<ClassifierOptimizer>? subOptimizers = null, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null, int overlapLength = 0)
    {
        foreach (var classifier in classifiers)
        {
            var regex = optimizer.GetRegex(classifier);
            if (regex == null && subOptimizers != null)
            {
                foreach (var subOpt in subOptimizers)
                {
                    regex = subOpt.GetRegex(classifier);
                    if (regex != null)
                    {
                        break;
                    }
                }
            }

            if (regex == null) continue;

            var evaluation = SiftMatchEngine.FindMatches(
                chunk,
                regex,
                overlapLength,
                classifier.EntropyThreshold);
            foreach (var match in evaluation.Matches)
            {
                // Enterprise policy, validation and evidence handling remain outside the neutral matcher.
                bool stop = false;
                if (policyMap.TryGetValue(classifier.Id, out var policies))
                {
                    // Validation is classifier-owned, so evaluate it once per match rather than
                    // repeating the same context allocation and validator call for every policy.
                    double confidence = match.Confidence;
                    var secret = match.Value;
                    var enableLlmValidation = classifier.EnableLlmValidation;
                    var needsValidationContext = enableLlmValidation || !string.IsNullOrEmpty(classifier.Validator);
                    var validationContext = needsValidationContext
                        ? BuildValidationContext(chunk, match.Index, match.Length)
                        : string.Empty;
                    if (!string.IsNullOrEmpty(classifier.Validator))
                    {
                        var validator = _validatorFactory.GetValidator(classifier.Validator);
                        if (validator == null)
                        {
                            _logger.LogWarning(
                                "Skipping match for classifier {ClassifierName} in {Path} because validator {ValidatorName} is not registered.",
                                classifier.Name,
                                filePath,
                                classifier.Validator);
                            continue;
                        }

                        var contextStart = Math.Max(0, match.Index - ValidationContextRadius);
                        var validation = validator.Validate(new ValidationContext
                        {
                            Candidate = secret,
                            FilePath = filePath,
                            FullFileContent = validationContext,
                            Index = match.Index - contextStart
                        });
                        if (!validation.IsValid)
                        {
                            continue;
                        }

                        confidence = validation.Confidence;
                    }

                    var valueHash = HashSecret(secret);
                    var snippet = BuildSnippet(chunk, match.Index, match.Length);
                    var detectedAt = DateTime.UtcNow;
                    foreach (var policy in policies)
                    {
                        if (ruleStats != null) ruleStats.AddOrUpdate(classifier.Name, 1, (_, c) => c + 1);
                        (issues ??= new List<ScanFinding>()).Add(new ScanFinding
                        {
                            RuleName = policy.Name,
                            PolicyName = policy.Name,
                            ClassifierName = classifier.Name,
                            ResourcePath = filePath,
                            Severity = policy.Severity,
                            RedactedValue = secret,
                            ValueHash = valueHash,
                            DetectedAt = detectedAt,
                            Snippet = snippet,
                            Exposure = exposure,
                            Owner = owner,
                            AclEntries = aclEntries,
                            Confidence = confidence,
                            ConfidenceLevel = ConfidenceLevel.Medium,
                            LlmValidationCandidate = enableLlmValidation ? secret : string.Empty,
                            LlmValidationContext = enableLlmValidation ? validationContext : string.Empty,
                            LlmPromptVersion = enableLlmValidation ? OllamaLlmClassifierValidator.PromptVersion : string.Empty,
                            LlmDeterministicValidator = enableLlmValidation ? classifier.Validator ?? string.Empty : string.Empty
                        });

                        if (policy.StopOnMatch) stop = true;
                    }
                }

                if (stop) return true;
            }

            if (evaluation.TimedOut)
            {
                _logger.LogWarning(
                    "Skipping timed-out content regex for classifier {ClassifierName} in {Path}.",
                    classifier.Name,
                    filePath);
            }
        }
        return false;
    }

    private static bool PathsReferToSameScope(string left, string right)
    {
        return string.Equals(
            left.TrimEnd('\\', '/'),
            right.TrimEnd('\\', '/'),
            StringComparison.OrdinalIgnoreCase);
    }

    protected virtual Stream? OpenStream(string filePath)
    {
        try
        {
            return new FileStream(filePath, FileMode.Open, FileAccess.Read, System.IO.FileShare.ReadWrite, 4096, FileOptions.SequentialScan);
        }
        catch (IOException)
        {
            return null;
        }
    }

    // Helpers
    public List<AclEntry> GetAclEntries(string filePath)
    {
        var entries = new List<AclEntry>();
        if (!OperatingSystem.IsWindows()) return entries;
        try
        {
            FileSystemSecurity fs = Directory.Exists(filePath)
                ? new DirectoryInfo(filePath).GetAccessControl()
                : new FileInfo(filePath).GetAccessControl();

            // Use SecurityIdentifier to avoid slow LSA lookups (especially for domain accounts when offline)
            foreach (FileSystemAccessRule rule in fs.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                entries.Add(new AclEntry
                {
                    Identity = rule.IdentityReference.Value, // Returns SID (e.g. S-1-5-...)
                    Permissions = rule.FileSystemRights.ToString(),
                    AccessControlType = rule.AccessControlType.ToString(),
                    IsInherited = rule.IsInherited
                });
            }
        }
        catch { }
        return entries;
    }

    public string GetExposure(string filePath)
    {
        if (!OperatingSystem.IsWindows()) return "Unix/Unknown";
        try
        {
            var fs = new FileInfo(filePath).GetAccessControl();
            // Use SecurityIdentifier to avoid slow LSA lookups
            var rules = fs.GetAccessRules(true, true, typeof(SecurityIdentifier));
            bool everyone = false, domainUsers = false, authUsers = false;
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType == AccessControlType.Allow)
                {
                    if (rule.IdentityReference is SecurityIdentifier sid)
                    {
                        if (sid.IsWellKnown(WellKnownSidType.WorldSid) || sid.IsWellKnown(WellKnownSidType.AnonymousSid)) everyone = true;
                        else if (sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid)) authUsers = true;
                        // Domain Users is usually S-1-5-21-<Domain>-513. 
                        // We can't easily check WellKnownSidType.AccountDomainUsersSid without the domain SID.
                        // But checking for RID 513 is a reasonable heuristic for "Domain Users" group.
                        else if (sid.Value.EndsWith("-513")) domainUsers = true;
                    }
                }
            }
            if (everyone) return "Everyone";
            if (domainUsers) return "Domain Users";
            if (authUsers) return "Authenticated Users";
            return "Restricted";
        }
        catch { return "Unknown"; }
    }

    private static string RedactSecret(string secret) => SiftEvidence.MaskValue(secret);

    private static string HashSecret(string secret) => SiftEvidence.ComputeSha256Base64(secret);

    private static string BuildSnippet(ReadOnlySpan<char> chunk, int matchIndex, int matchLength)
        => SiftEvidence.BuildSurroundingContext(chunk, matchIndex, matchLength, 50);

    private static string BuildValidationContext(ReadOnlySpan<char> chunk, int matchIndex, int matchLength)
        => SiftEvidence.BuildSurroundingContext(chunk, matchIndex, matchLength, ValidationContextRadius);

    public static double CalculateShannonEntropy(string input)
    {
        return CalculateShannonEntropy(input.AsSpan());
    }

    public static double CalculateShannonEntropy(ReadOnlySpan<char> input)
        => SiftEvidence.CalculateShannonEntropy(input);

    private static Encoding DetectEncoding(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 2) return Encoding.Default;

        // Check for BOMs
        if (buffer[0] == 0xFF && buffer[1] == 0xFE) return Encoding.Unicode;
        if (buffer[0] == 0xFE && buffer[1] == 0xFF) return Encoding.BigEndianUnicode;
        if (buffer.Length >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) return Encoding.UTF8;

        // Heuristic for BOM-less UTF-16
        int nulls = 0;
        for (int i = 0; i < buffer.Length; i++) if (buffer[i] == 0) nulls++;

        double ratio = (double)nulls / buffer.Length;
        if (ratio >= 0.3)
        {
            int oddNulls = 0;
            int evenNulls = 0;
            for (int i = 0; i < buffer.Length; i++)
            {
                if (buffer[i] == 0)
                {
                    if (i % 2 == 0) evenNulls++;
                    else oddNulls++;
                }
            }

            if (oddNulls > evenNulls && oddNulls > buffer.Length * 0.3) return Encoding.Unicode;
            if (evenNulls > oddNulls && evenNulls > buffer.Length * 0.3) return Encoding.BigEndianUnicode;
        }

        return Encoding.Default;
    }

    private static IReadOnlyList<ScanFinding> AggregateIssues(List<ScanFinding>? rawIssues, Dictionary<string, Policy>? policyLookup)
    {
        if (rawIssues is not { Count: > 0 }) return [];

        if (rawIssues.Count == 1)
        {
            var only = rawIssues[0];
            if (policyLookup != null
                && policyLookup.TryGetValue(only.RuleName, out var onlyPolicy)
                && only.InstanceCount < (onlyPolicy.Configuration?.MinMatchCount ?? 1))
            {
                return [];
            }

            return rawIssues;
        }

        var uniqueCount = 0;
        for (var readIndex = 0; readIndex < rawIssues.Count; readIndex++)
        {
            var candidate = rawIssues[readIndex];
            var existingIndex = -1;
            for (var index = 0; index < uniqueCount; index++)
            {
                var existing = rawIssues[index];
                if (existing.RuleName == candidate.RuleName
                    && existing.ClassifierName == candidate.ClassifierName
                    && existing.ResourcePath == candidate.ResourcePath)
                {
                    existingIndex = index;
                    break;
                }
            }

            if (existingIndex >= 0)
            {
                rawIssues[existingIndex].InstanceCount += candidate.InstanceCount;
            }
            else
            {
                rawIssues[uniqueCount++] = candidate;
            }
        }

        if (uniqueCount < rawIssues.Count)
        {
            rawIssues.RemoveRange(uniqueCount, rawIssues.Count - uniqueCount);
        }

        if (policyLookup != null)
        {
            for (var index = rawIssues.Count - 1; index >= 0; index--)
            {
                var finding = rawIssues[index];
                if (policyLookup.TryGetValue(finding.RuleName, out var policy)
                    && finding.InstanceCount < (policy.Configuration?.MinMatchCount ?? 1))
                {
                    rawIssues.RemoveAt(index);
                }
            }
        }

        return rawIssues;
    }
}


