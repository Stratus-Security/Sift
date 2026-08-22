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

        return ScanFileInternalAsync(filePath, optimizer, policyMap, options, null, "Unknown", null, null, null, null, ruleStats, null, CancellationToken.None).GetAwaiter().GetResult();
    }

    public IEnumerable<ScanFinding> ScanFile(string filePath, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, ScanOptions? options = null, string? exposure = null, string owner = "Unknown", List<AclEntry>? aclEntries = null, long? fileSize = null, string? ext = null, string? name = null, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null, IEnumerable<IgnoreRule>? ignoreRules = null)
    {
        return ScanFileInternalAsync(filePath, optimizer, policyMap, options, exposure, owner, aclEntries, ext, name, fileSize, ruleStats, ignoreRules, CancellationToken.None).GetAwaiter().GetResult().Issues;
    }

    public ScanResult ScanFileWithResult(string filePath, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, ScanOptions? options = null, string? exposure = null, string owner = "Unknown", List<AclEntry>? aclEntries = null, long? fileSize = null, string? ext = null, string? name = null, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null, IEnumerable<IgnoreRule>? ignoreRules = null)
    {
        return ScanFileInternalAsync(filePath, optimizer, policyMap, options, exposure, owner, aclEntries, ext, name, fileSize, ruleStats, ignoreRules, CancellationToken.None).GetAwaiter().GetResult();
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
            optimizer,
            policyMap,
            options,
            exposure,
            owner,
            aclEntries,
            ext,
            name,
            fileSize,
            ruleStats,
            ignoreRules,
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

    private static Dictionary<Guid, List<Policy>> ScopePolicyMap(string filePath, Dictionary<Guid, List<Policy>> policyMap)
    {
        var scopedPolicyMap = new Dictionary<Guid, List<Policy>>();
        foreach (var kvp in policyMap)
        {
            var validPolicies = kvp.Value.Where(p => p.Active && IsPathIncluded(filePath, p)).ToList();
            if (validPolicies.Any())
            {
                scopedPolicyMap[kvp.Key] = validPolicies;
            }
        }

        return scopedPolicyMap;
    }

    private async Task<ScanResult> ScanFileInternalAsync(string filePath, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, ScanOptions? options, string? exposure, string owner, List<AclEntry>? aclEntries, string? ext, string? name, long? fileSize, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats, IEnumerable<IgnoreRule>? ignoreRules, CancellationToken cancellationToken)
    {
        options ??= new ScanOptions();

        ext ??= Path.GetExtension(filePath);
        name ??= Path.GetFileName(filePath);
        exposure ??= "Unknown";
        owner ??= "Unknown";
        aclEntries ??= _emptyAclEntries;

        // Create a lookup for policies by name for aggregation logic
        var policyNameLookup = policyMap.Values
            .SelectMany(list => list)
            .GroupBy(p => p.Name) // Handle duplicate names if any, though ID preferred
            .ToDictionary(g => g.Key, g => g.First());

        // Pre-filter Policies based on Path Scope
        // We only want to evaluate policies that apply to this file path.
        // This optimizes performance by reducing the number of active policies.
        var scopedPolicyMap = ScopePolicyMap(filePath, policyMap);

        var matchedIgnoreRules = IgnoreRuleEvaluator.GetMatchedRules(filePath, ignoreRules);
        if (IgnoreRuleEvaluator.ShouldIgnoreDespiteMetadata(matchedIgnoreRules, []))
        {
            return new ScanResult { Issues = Enumerable.Empty<ScanFinding>() };
        }

        var metadataMatches = optimizer.GetMetadataMatches(filePath).ToList();
        var directMetadataMatches = metadataMatches
            .Where(match => PathsReferToSameScope(match.ResourcePath, filePath))
            .ToList();
        var metadataClassifiers = directMetadataMatches
            .Select(match => match.Classifier)
            .DistinctBy(classifier => classifier.Id)
            .ToList();

        // If no policies apply to this path, we can skip content scanning entirely 
        // UNLESS we are in discovery mode (not implemented yet, assumed false for optimization).
        if (scopedPolicyMap.Count == 0)
        {
            return new ScanResult { Issues = Enumerable.Empty<ScanFinding>() };
        }

        var result = new ScanResult();
        var issues = new List<ScanFinding>();
        List<ClassifierOptimizer>? subOptimizers = null;
        bool metadataClassifierMatched = false;

        try
        {
            // 2. Check Metadata Classifiers
            foreach (var metadataMatch in directMetadataMatches)
            {
                var classifier = metadataMatch.Classifier;
                metadataClassifierMatched = true;
                result.MatchedClassifiers.Add(classifier.Name);

                if (scopedPolicyMap.TryGetValue(classifier.Id, out var policies))
                {
                    foreach (var policy in policies)
                    {
                        if (ruleStats != null) ruleStats.AddOrUpdate(classifier.Name, 1, (_, c) => c + 1);

                        issues.Add(new ScanFinding
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
                result.Issues = Enumerable.Empty<ScanFinding>();
                return result;
            }

            if (!optimizer.HasContentClassifiers && (subOptimizers == null || subOptimizers.Count == 0))
            {
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
                        issues.AddRange(bufferIssues.Issues);
                        foreach (var c in bufferIssues.MatchedClassifiers) result.MatchedClassifiers.Add(c);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to extract content from file: {Path}", filePath);
                }
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            // Binary Check & Stream Opening
            if (fileSize.HasValue && fileSize.Value == 0)
            {
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            Stream? streamObj = null;
            try
            {
                streamObj = OpenStream(filePath);
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }

            if (streamObj == null)
            {
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            using var stream = options.MaxDiskReadBytesPerSecond > 0
                ? new RateLimitedReadStream(streamObj, _readRateLimiter, options.MaxDiskReadBytesPerSecond)
                : streamObj;

            if (!options.EnableBinaryDocuments && IsLikelyBinary(stream))
            {
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

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

                var scanRes = await ScanStreamInternalAsync(stream, optimizer, scopedPolicyMap, filePath, ext, name, exposure, owner, aclEntries, cancellationToken, ruleStats, forwardScanLimit, ignoreRules, policyNameLookup);
                issues.AddRange(scanRes.Issues);
                foreach (var c in scanRes.MatchedClassifiers) result.MatchedClassifiers.Add(c);
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            // Full Scan
            if (effectiveFileSize!.Value <= options.MaxFileSize)
            {
                var scanRes = await ScanStreamInternalAsync(stream, optimizer, scopedPolicyMap, filePath, ext, name, exposure, owner, aclEntries, cancellationToken, ruleStats, null, ignoreRules, policyNameLookup);
                issues.AddRange(scanRes.Issues);
                foreach (var c in scanRes.MatchedClassifiers) result.MatchedClassifiers.Add(c);
                result.Issues = AggregateIssues(issues, policyNameLookup);
                return result;
            }

            // Large File: Head + Tail
            // Head
            var headResults = await ScanStreamInternalAsync(stream, optimizer, scopedPolicyMap, filePath, ext, name, exposure, owner, aclEntries, cancellationToken, ruleStats, options.HeadSize, ignoreRules, policyNameLookup);
            if (headResults != null)
            {
                issues.AddRange(headResults.Issues);
                foreach (var c in headResults.MatchedClassifiers) result.MatchedClassifiers.Add(c);
            }

            // Tail
            if (effectiveFileSize.Value > options.TailSize)
            {
                stream.Seek(-options.TailSize, SeekOrigin.End);
                var tailResults = await ScanStreamInternalAsync(stream, optimizer, scopedPolicyMap, filePath, ext, name, exposure, owner, aclEntries, cancellationToken, ruleStats, options.TailSize, ignoreRules, policyNameLookup);
                if (tailResults != null)
                {
                    issues.AddRange(tailResults.Issues);
                    foreach (var c in tailResults.MatchedClassifiers) result.MatchedClassifiers.Add(c);
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
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning file: {Path}", filePath);
        }

        result.Issues = AggregateIssues(issues ?? Enumerable.Empty<ScanFinding>(), policyNameLookup);
        return result;
    }

    private sealed class SharedReadRateLimiter
    {
        private long _nextAvailableTimestamp;

        public async ValueTask AccountAsync(
            int bytes,
            long bytesPerSecond,
            CancellationToken cancellationToken)
        {
            if (bytes <= 0 || bytesPerSecond <= 0) return;
            var now = Stopwatch.GetTimestamp();
            var duration = Math.Max(1L, checked(bytes * Stopwatch.Frequency / bytesPerSecond));
            long start;
            long next;
            long observed;
            do
            {
                observed = Volatile.Read(ref _nextAvailableTimestamp);
                start = Math.Max(now, observed);
                next = checked(start + duration);
            }
            while (Interlocked.CompareExchange(ref _nextAvailableTimestamp, next, observed) != observed);

            var waitTicks = start - now;
            if (waitTicks > 0)
            {
                await Task.Delay(
                    TimeSpan.FromSeconds((double)waitTicks / Stopwatch.Frequency),
                    cancellationToken);
            }
        }
    }

    private sealed class RateLimitedReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly SharedReadRateLimiter _limiter;
        private readonly long _bytesPerSecond;

        public RateLimitedReadStream(
            Stream inner,
            SharedReadRateLimiter limiter,
            long bytesPerSecond)
        {
            _inner = inner;
            _limiter = limiter;
            _bytesPerSecond = bytesPerSecond;
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
            var read = _inner.Read(buffer, offset, count);
            _limiter.AccountAsync(read, _bytesPerSecond, CancellationToken.None)
                .AsTask()
                .GetAwaiter()
                .GetResult();
            return read;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = await _inner.ReadAsync(buffer, cancellationToken);
            await _limiter.AccountAsync(read, _bytesPerSecond, cancellationToken);
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
            var read = await _inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
            await _limiter.AccountAsync(read, _bytesPerSecond, cancellationToken);
            return read;
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
        var ext = Path.GetExtension(fileName);
        var name = Path.GetFileName(fileName);
        aclEntries ??= new List<AclEntry>();
        var scopedPolicyMap = ScopePolicyMap(fileName, policyMap);
        if (scopedPolicyMap.Count == 0)
        {
            return new ScanResult { Issues = Enumerable.Empty<ScanFinding>() };
        }

        // Create lookup
        var policyNameLookup = scopedPolicyMap.Values
            .SelectMany(list => list)
            .GroupBy(p => p.Name)
            .ToDictionary(g => g.Key, g => g.First());

        return await ScanStreamInternalAsync(stream, optimizer, scopedPolicyMap, fileName, ext, name, exposure, owner, aclEntries, cancellationToken, ruleStats, null, ignoreRules, policyNameLookup);
    }

    private async Task<ScanResult> ScanStreamInternalAsync(Stream stream, ClassifierOptimizer optimizer, Dictionary<Guid, List<Policy>> policyMap, string fileName, string ext, string name, string exposure, string owner, List<AclEntry> aclEntries, CancellationToken cancellationToken, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null, long? limitBytes = null, IEnumerable<IgnoreRule>? ignoreRules = null, Dictionary<string, Policy>? policyLookup = null)
    {
        var result = new ScanResult();
        var issues = new List<ScanFinding>();
        var subOptimizers = new List<ClassifierOptimizer>();

        var matchedIgnoreRules = IgnoreRuleEvaluator.GetMatchedRules(fileName, ignoreRules);
        if (IgnoreRuleEvaluator.ShouldIgnoreDespiteMetadata(matchedIgnoreRules, []))
        {
            return new ScanResult { Issues = Enumerable.Empty<ScanFinding>() };
        }

        // 1. Check Metadata Classifiers
        var metadataMatches = optimizer.GetMetadataMatches(fileName).ToList();
        var directMetadataMatches = metadataMatches
            .Where(match => PathsReferToSameScope(match.ResourcePath, fileName))
            .ToList();
        var metadataClassifiers = directMetadataMatches
            .Select(match => match.Classifier)
            .DistinctBy(classifier => classifier.Id)
            .ToList();

        foreach (var metadataMatch in directMetadataMatches)
        {
            var classifier = metadataMatch.Classifier;
            result.MatchedClassifiers.Add(classifier.Name);

            // Evaluate Policies
            if (policyMap.TryGetValue(classifier.Id, out var policies))
            {
                foreach (var policy in policies)
                {
                    if (ruleStats != null) ruleStats.AddOrUpdate(classifier.Name, 1, (_, c) => c + 1);

                    issues.Add(new ScanFinding
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
                subOptimizers.Add(subOpt);
            }
        }

        var encoding = DetectEncoding(stream);
        using var reader = new StreamReader(stream, encoding, true, BufferSize, leaveOpen: true);

        var pool = ArrayPool<char>.Shared;
        char[] buffer = pool.Rent(BufferSize);
        var chunkClassifiers = new HashSet<Classifier>();

        try
        {
            int charsRead;
            int bufferOffset = 0;
            long totalRead = 0;

            while ((charsRead = await reader.ReadBlockAsync(buffer, bufferOffset, BufferSize - bufferOffset)) > 0)
            {
                if (cancellationToken.IsCancellationRequested) break;

                int validLength = bufferOffset + charsRead;
                var span = buffer.AsSpan(0, validLength);

                // Check limits
                if (limitBytes.HasValue && totalRead > limitBytes.Value) break;

                chunkClassifiers.Clear();
                optimizer.PopulateClassifiersForContent(span, chunkClassifiers, ext);

                if (subOptimizers.Count > 0)
                {
                    foreach (var subOpt in subOptimizers)
                    {
                        subOpt.PopulateClassifiersForContent(span, chunkClassifiers, ext);
                    }
                }

                if (chunkClassifiers.Count > 0)
                {
                    foreach (var c in chunkClassifiers) result.MatchedClassifiers.Add(c.Name);

                    bool stop = ScanChunk(span, chunkClassifiers, policyMap, fileName, ext, name, exposure, owner, aclEntries, optimizer, totalRead, issues, subOptimizers, ruleStats, bufferOffset);
                    if (stop) break;
                }

                totalRead += charsRead;

                if (validLength > OverlapSize)
                {
                    span = buffer.AsSpan(0, validLength);
                    var tail = span.Slice(validLength - OverlapSize, OverlapSize);
                    tail.CopyTo(buffer.AsSpan(0, OverlapSize));
                    bufferOffset = OverlapSize;
                }
                else
                {
                    if (charsRead < BufferSize - bufferOffset) break;
                }
            }
        }
        finally
        {
            pool.Return(buffer);
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

        foreach (var c in classifiers) result.MatchedClassifiers.Add(c.Name);

        if (classifiers.Count == 0) return result;

        var issues = new List<ScanFinding>();
        ScanChunk(content, classifiers, policyMap, filePath, ext, name, exposure, owner, aclEntries, optimizer, 0, issues, subOptimizers, ruleStats);
        result.Issues = AggregateIssues(issues, policyLookup);
        return result;
    }

    private bool ScanChunk(ReadOnlySpan<char> chunk, IEnumerable<Classifier> classifiers, Dictionary<Guid, List<Policy>> policyMap, string filePath, string ext, string name, string exposure, string owner, List<AclEntry> aclEntries, ClassifierOptimizer optimizer, long offset, List<ScanFinding> issues, List<ClassifierOptimizer>? subOptimizers = null, System.Collections.Concurrent.ConcurrentDictionary<string, int>? ruleStats = null, int overlapLength = 0)
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
                    foreach (var policy in policies)
                    {
                        double confidence = match.Confidence;
                        var secret = match.Value;
                        var validationContext = BuildValidationContext(chunk, match.Index, match.Length);
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

                            var contextStart = Math.Max(0, match.Index - 100);
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

                        if (ruleStats != null) ruleStats.AddOrUpdate(classifier.Name, 1, (_, c) => c + 1);
                        var enableLlmValidation = classifier.EnableLlmValidation;

                        issues.Add(new ScanFinding
                        {
                            Id = Guid.NewGuid(),
                            RuleName = policy.Name,
                            PolicyName = policy.Name,
                            ClassifierName = classifier.Name,
                            ResourcePath = filePath,
                            Severity = policy.Severity,
                            RedactedValue = secret,
                            ValueHash = HashSecret(secret),
                            DetectedAt = DateTime.UtcNow,
                            Snippet = BuildSnippet(chunk, match.Index, match.Length),
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

    private bool IsLikelyBinary(Stream stream)
    {
        if (!stream.CanSeek)
        {
            return false;
        }

        var originalPosition = stream.Position;
        try
        {
            var sampleSize = (int)Math.Min(stream.Length, 512);
            if (sampleSize <= 0)
            {
                return false;
            }

            byte[] buffer = new byte[sampleSize];
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read <= 0)
            {
                return false;
            }

            return SiftEvidence.LooksBinary(buffer.AsSpan(0, read));
        }
        finally
        {
            stream.Position = originalPosition;
        }
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
        => SiftEvidence.BuildSurroundingContext(chunk, matchIndex, matchLength, 100);

    public static double CalculateShannonEntropy(string input)
    {
        return CalculateShannonEntropy(input.AsSpan());
    }

    public static double CalculateShannonEntropy(ReadOnlySpan<char> input)
        => SiftEvidence.CalculateShannonEntropy(input);

    private Encoding DetectEncoding(Stream stream)
    {
        if (!stream.CanSeek || stream.Length < 2) return Encoding.Default;

        long originalPos = stream.Position;
        byte[] buffer = new byte[(int)Math.Min(stream.Length, 512)];
        int read = stream.Read(buffer, 0, buffer.Length);
        stream.Position = originalPos;

        if (read < 2) return Encoding.Default;

        // Check for BOMs
        if (buffer[0] == 0xFF && buffer[1] == 0xFE) return Encoding.Unicode;
        if (buffer[0] == 0xFE && buffer[1] == 0xFF) return Encoding.BigEndianUnicode;
        if (read >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) return Encoding.UTF8;

        // Heuristic for BOM-less UTF-16
        int nulls = 0;
        for (int i = 0; i < read; i++) if (buffer[i] == 0) nulls++;

        double ratio = (double)nulls / read;
        if (ratio >= 0.3)
        {
            int oddNulls = 0;
            int evenNulls = 0;
            for (int i = 0; i < read; i++)
            {
                if (buffer[i] == 0)
                {
                    if (i % 2 == 0) evenNulls++;
                    else oddNulls++;
                }
            }

            if (oddNulls > evenNulls && oddNulls > read * 0.3) return Encoding.Unicode;
            if (evenNulls > oddNulls && evenNulls > read * 0.3) return Encoding.BigEndianUnicode;
        }

        return Encoding.Default;
    }

    private List<ScanFinding> AggregateIssues(IEnumerable<ScanFinding> rawIssues, Dictionary<string, Policy>? policyLookup)
    {
        var aggregated = new List<ScanFinding>();
        if (rawIssues == null) return aggregated;

        var groups = rawIssues.GroupBy(i => new { i.RuleName, i.ClassifierName, i.ResourcePath });

        foreach (var group in groups)
        {
            var matchCount = group.Sum(i => i.InstanceCount);

            // Check Minimum Match Count
            if (policyLookup != null && policyLookup.TryGetValue(group.Key.RuleName, out var policy))
            {
                int threshold = policy.Configuration?.MinMatchCount ?? 1;
                if (matchCount < threshold) continue;
            }

            var primary = group.First();
            primary.InstanceCount = matchCount;
            aggregated.Add(primary);
        }

        return aggregated;
    }
}


