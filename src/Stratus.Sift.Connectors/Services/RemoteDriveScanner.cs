using System.IO.Enumeration;
using System.Runtime.ExceptionServices;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Kiota.Abstractions;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Models;
using Stratus.Sift.Scanner.Services;

namespace Stratus.Sift.Connectors.Services;

public class RemoteDriveScanner
{
    private readonly ILogger<RemoteDriveScanner> _logger;
    private readonly IScanner _scanner;
    private readonly ContentExtractor _contentExtractor;

    public RemoteDriveScanner(
        ILogger<RemoteDriveScanner> logger,
        IScanner scanner,
        ContentExtractor contentExtractor)
    {
        _logger = logger;
        _scanner = scanner;
        _contentExtractor = contentExtractor;
    }

    public async Task ScanDriveChangesAsync(
        IRemoteDrive drive,
        string? deltaToken,
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        List<IgnoreRule> ignoreRules,
        ScanOptions options,
        Func<ScanFinding, Task> onIssueFound,
        Func<string, Task>? onCheckpointToken,
        Func<string, Task> onNewDeltaToken,
        Action<int>? onFilesScanned,
        Action<int>? onQueueDepth,
        Action<string>? onCurrentPath,
        Func<CancellationToken, ValueTask>? ensureScanActive,
        CancellationToken cancellationToken)
    {
        await ScanDriveChangesAsync(
            drive,
            deltaToken,
            optimizer,
            policyMap,
            ignoreRules,
            options,
            onIssueFound,
            onCheckpointToken,
            onNewDeltaToken,
            onFilesDiscovered: null,
            onFilesScanned,
            onQueueDepth,
            onCurrentPath,
            ensureScanActive,
            cancellationToken);
    }

    public async Task ScanDriveChangesAsync(
        IRemoteDrive drive,
        string? deltaToken,
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        List<IgnoreRule> ignoreRules,
        ScanOptions options,
        Func<ScanFinding, Task> onIssueFound,
        Func<string, Task>? onCheckpointToken,
        Func<string, Task> onNewDeltaToken,
        Action<int>? onFilesDiscovered,
        Action<int>? onFilesScanned,
        Action<int>? onQueueDepth,
        Action<string>? onCurrentPath,
        Func<CancellationToken, ValueTask>? ensureScanActive,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Scanning Drive: {DriveName} ({DriveId})", drive.Name, drive.Id);

        var pendingItems = 0;
        long queuedItems = 0;
        long completedItems = 0;
        long deferredContentItems = 0;
        var channel = Channel.CreateBounded<RemoteScanItem>(new BoundedChannelOptions(256)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleWriter = true,
            SingleReader = false
        });

        Exception? producerException = null;
        string newDeltaToken = string.Empty;

        var workers = Enumerable.Range(0, 4).Select(_ => Task.Run(async () =>
        {
            await foreach (var scanItem in channel.Reader.ReadAllAsync(cancellationToken))
            {
                try
                {
                    if (ensureScanActive != null)
                    {
                        await ensureScanActive(cancellationToken);
                    }

                    onCurrentPath?.Invoke(GetFindingResourcePath(scanItem.Item));
                    var outcome = await ProcessItemAsync(scanItem, optimizer, policyMap, ignoreRules, options, onIssueFound, cancellationToken);
                    if (outcome == RemoteScanOutcome.DeferredRetry)
                    {
                        Interlocked.Increment(ref deferredContentItems);
                    }
                    else
                    {
                        onFilesScanned?.Invoke(1);
                    }
                }
                finally
                {
                    Interlocked.Increment(ref completedItems);
                    var depth = Interlocked.Decrement(ref pendingItems);
                    onQueueDepth?.Invoke(Math.Max(depth, 0));
                }
            }
        }, cancellationToken)).ToArray();

        try
        {
            if (ensureScanActive != null)
            {
                await ensureScanActive(cancellationToken);
            }

            newDeltaToken = await drive.ProcessChangesAsync(
                deltaToken,
                async item =>
                {
                    if (ensureScanActive != null)
                    {
                        await ensureScanActive(cancellationToken);
                    }

                    onCurrentPath?.Invoke(GetFindingResourcePath(item));

                    if (item.IsDeleted)
                    {
                        return;
                    }

                    if (item.IsLink && (!item.IsExternal || !options.ScanExternalFiles))
                    {
                        return;
                    }

                    var matchedIgnoreRules = IgnoreRuleEvaluator.GetMatchedRules(item.Path, ignoreRules);
                    if (IgnoreRuleEvaluator.ShouldIgnoreDespiteMetadata(matchedIgnoreRules, []))
                    {
                        return;
                    }

                    onFilesDiscovered?.Invoke(1);

                    var ext = item.IsDirectory ? string.Empty : Path.GetExtension(item.Name);
                    var metadataPath = item.IsDirectory ? EnsureDirectoryMetadataPath(item.Path) : item.Path;
                    var metadataMatches = optimizer.GetMetadataMatches(metadataPath).ToList();
                    var directMetadataMatches = metadataMatches
                        .Where(match => PathsReferToSameScope(match.ResourcePath, metadataPath))
                        .ToList();
                    var metadataClassifiers = directMetadataMatches
                        .Select(match => match.Classifier)
                        .DistinctBy(classifier => classifier.Id)
                        .ToList();

                    var hasContentRules = !item.IsDirectory && optimizer.HasRulesForExtension(ext);
                    if (!metadataClassifiers.Any() && !hasContentRules)
                    {
                        return;
                    }

                    var depth = Interlocked.Increment(ref pendingItems);
                    Interlocked.Increment(ref queuedItems);
                    onQueueDepth?.Invoke(depth);

                    await channel.Writer.WriteAsync(
                        new RemoteScanItem(item, directMetadataMatches, hasContentRules),
                        cancellationToken);
                },
                async checkpointToken =>
                {
                    if (onCheckpointToken == null || string.IsNullOrWhiteSpace(checkpointToken))
                    {
                        return;
                    }

                    var requiredCompletedItems = Interlocked.Read(ref queuedItems);
                    await WaitForQueuedItemsAsync(requiredCompletedItems, () => Interlocked.Read(ref completedItems), cancellationToken);

                    if (Interlocked.Read(ref deferredContentItems) > 0)
                    {
                        _logger.LogWarning(
                            "Skipping delta checkpoint for drive {DriveName} ({DriveId}) because one or more file downloads will be retried before advancing the token.",
                            drive.Name,
                            drive.Id);
                        return;
                    }

                    await onCheckpointToken(checkpointToken);
                },
                cancellationToken);
        }
        catch (Exception ex) when (IsRetriableThrottleFailure(ex, out var statusCode))
        {
            _logger.LogWarning(
                ex,
                "Drive enumeration for {DriveName} ({DriveId}) was throttled with status {StatusCode}. The scan will resume on the next cycle.",
                drive.Name,
                drive.Id,
                statusCode);
        }
        catch (Exception ex)
        {
            producerException = ex;
        }
        finally
        {
            channel.Writer.TryComplete(producerException);
        }

        try
        {
            await Task.WhenAll(workers);
        }
        catch (Exception ex) when (producerException == null)
        {
            producerException = ex;
        }

        if (producerException != null)
        {
            ExceptionDispatchInfo.Capture(producerException).Throw();
        }

        if (!string.IsNullOrEmpty(newDeltaToken))
        {
            if (Interlocked.Read(ref deferredContentItems) > 0)
            {
                _logger.LogWarning(
                    "Skipping final delta token update for drive {DriveName} ({DriveId}) because one or more file downloads will be retried before advancing the token.",
                    drive.Name,
                    drive.Id);
                return;
            }

            await onNewDeltaToken(newDeltaToken);
        }
    }

    private async Task<RemoteScanOutcome> ProcessItemAsync(
        RemoteScanItem scanItem,
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        List<IgnoreRule> ignoreRules,
        ScanOptions options,
        Func<ScanFinding, Task> onIssueFound,
        CancellationToken cancellationToken)
    {
        var item = scanItem.Item;
        try
        {
            var exposure = item.IsExternal ? "External" : "Internal";
            var ext = Path.GetExtension(item.Name ?? string.Empty);
            var scopedPolicyMap = ScopePolicyMap(item.Path, policyMap);
            var findingResourcePath = GetFindingResourcePath(item);
            if (scopedPolicyMap.Count == 0)
            {
                return RemoteScanOutcome.Completed;
            }

            if (item.IsDirectory)
            {
                await ReportMetadataIssuesAsync(scanItem.MetadataMatches, scopedPolicyMap, exposure, findingResourcePath, onIssueFound);
                return RemoteScanOutcome.Completed;
            }

            if (item.Size.HasValue && item.Size.Value > options.MaxFileSize)
            {
                if (options.EnableBinaryDocuments && _contentExtractor.Supports(ext))
                {
                    return RemoteScanOutcome.Completed;
                }

                try
                {
                    using var headStream = await item.GetContentRangeAsync(0, options.HeadSize - 1, cancellationToken);
                    if (headStream == null)
                    {
                        _logger.LogDebug("Skipping large-file head scan for {ItemPath} because no content stream was available.", item.Path);
                        return RemoteScanOutcome.Completed;
                    }

                    var headScanResult = await _scanner.ScanStreamAsync(
                        headStream,
                        item.Path,
                        optimizer,
                        scopedPolicyMap,
                        ignoreRules,
                        exposure,
                        "Cloud",
                        null,
                        cancellationToken);

                    foreach (var issue in headScanResult.Issues)
                    {
                        issue.ResourcePath = findingResourcePath;
                        await onIssueFound(issue);
                    }

                    return RemoteScanOutcome.Completed;
                }
                catch (RemoteContentUnavailableException ex)
                {
                    return HandleContentUnavailable(ex, item);
                }
            }

            var needContentScan = true;
            if (!scanItem.HasContentRules)
            {
                var hasSubRules = scanItem.MetadataMatches.Any(match => optimizer.GetSubOptimizer(match.Classifier) != null);
                if (!hasSubRules)
                {
                    needContentScan = false;
                }
            }

            if (!needContentScan)
            {
                await ReportMetadataIssuesAsync(scanItem.MetadataMatches, scopedPolicyMap, exposure, findingResourcePath, onIssueFound);
                return RemoteScanOutcome.Completed;
            }

            try
            {
                using var stream = await item.GetContentAsync(cancellationToken);
                if (stream == null)
                {
                    _logger.LogDebug("Skipping content scan for {ItemPath} because no content stream was available.", item.Path);
                    return RemoteScanOutcome.Completed;
                }

                ScanResult scanResult;
                if (options.EnableBinaryDocuments && _contentExtractor.Supports(ext))
                {
                    var text = _contentExtractor.Extract(stream, ext);
                    using var textStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(text));
                    scanResult = await ((FileScanner)_scanner).ScanStreamAsync(textStream, item.Path, optimizer, scopedPolicyMap, ignoreRules, exposure, "Cloud", null, cancellationToken);
                }
                else
                {
                    scanResult = await ((FileScanner)_scanner).ScanStreamAsync(stream, item.Path, optimizer, scopedPolicyMap, ignoreRules, exposure, "Cloud", null, cancellationToken);
                }

                foreach (var issue in scanResult.Issues)
                {
                    issue.ResourcePath = findingResourcePath;
                    await onIssueFound(issue);
                }

                return RemoteScanOutcome.Completed;
            }
            catch (RemoteContentUnavailableException ex)
            {
                return HandleContentUnavailable(ex, item);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning item {ItemName}", item.Name);
            return RemoteScanOutcome.Completed;
        }
    }

    private RemoteScanOutcome HandleContentUnavailable(RemoteContentUnavailableException exception, IRemoteFile item)
    {
        var statusSuffix = exception.StatusCode is int httpStatusCode ? $" HTTP {httpStatusCode}." : string.Empty;
        if (exception.ShouldRetry)
        {
            _logger.LogWarning(
                exception,
                "Deferring file scan for {ItemPath} because content download will be retried before advancing the delta token.{StatusSuffix}",
                item.Path,
                statusSuffix);
            return RemoteScanOutcome.DeferredRetry;
        }

        _logger.LogWarning(
            "Skipping file scan for {ItemPath}. {Reason}{StatusSuffix}",
            item.Path,
            exception.Message,
            statusSuffix);
        _logger.LogDebug(exception, "Non-retryable content download failure for {ItemPath}", item.Path);
        return RemoteScanOutcome.Completed;
    }

    private static async Task WaitForQueuedItemsAsync(long requiredCompletedItems, Func<long> getCompletedItems, CancellationToken cancellationToken)
    {
        while (getCompletedItems() < requiredCompletedItems)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken);
        }
    }

    private static async Task ReportMetadataIssuesAsync(
        IEnumerable<ClassifierOptimizer.MetadataMatch> metadataMatches,
        Dictionary<Guid, List<Policy>> policyMap,
        string exposure,
        string resourcePath,
        Func<ScanFinding, Task> onIssueFound)
    {
        foreach (var metadataMatch in metadataMatches)
        {
            var classifier = metadataMatch.Classifier;
            if (!policyMap.TryGetValue(classifier.Id, out var policies))
            {
                continue;
            }

            foreach (var policy in policies)
            {
                await onIssueFound(new ScanFinding
                {
                    Id = Guid.NewGuid(),
                    RuleName = policy.Name,
                    ClassifierName = classifier.Name,
                    ResourcePath = resourcePath,
                    ConfidenceLevel = ConfidenceLevel.High,
                    DetectedAt = DateTime.UtcNow,
                    IsReportOnly = policy.IsReportOnly,
                    Exposure = exposure,
                    Severity = policy.Severity,
                    Owner = policy.Name,
                    Snippet = policy.Description ?? string.Empty,
                });
            }
        }
    }

    internal static string GetFindingResourcePath(IRemoteFile item)
    {
        if (Uri.TryCreate(item.WebUrl, UriKind.Absolute, out var webUri)
            && (webUri.Scheme == Uri.UriSchemeHttps || webUri.Scheme == Uri.UriSchemeHttp))
        {
            return webUri.AbsoluteUri;
        }

        return item.Path;
    }

    private static bool IsPathIncluded(string filePath, Policy policy)
    {
        if (policy.Configuration == null)
        {
            return true;
        }

        if (policy.Configuration.IncludePaths != null && policy.Configuration.IncludePaths.Any())
        {
            var included = false;
            foreach (var pattern in policy.Configuration.IncludePaths)
            {
                if (FileSystemName.MatchesSimpleExpression(pattern, filePath))
                {
                    included = true;
                    break;
                }
            }

            if (!included)
            {
                return false;
            }
        }

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
            var validPolicies = kvp.Value.Where(p => IsPathIncluded(filePath, p)).ToList();
            if (validPolicies.Any())
            {
                scopedPolicyMap[kvp.Key] = validPolicies;
            }
        }

        return scopedPolicyMap;
    }

    private static bool IsRetriableThrottleFailure(Exception exception, out int? statusCode)
    {
        statusCode = exception switch
        {
            ApiException apiException => apiException.ResponseStatusCode,
            HttpRequestException httpRequestException when httpRequestException.StatusCode.HasValue => (int)httpRequestException.StatusCode.Value,
            _ => null
        };

        return statusCode is 429 or 503 or 504;
    }

    private static string EnsureDirectoryMetadataPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.EndsWith('\\') || path.EndsWith('/'))
        {
            return path;
        }

        return path.Contains('/') ? path + "/" : path + "\\";
    }

    private static bool PathsReferToSameScope(string left, string right)
    {
        return string.Equals(
            left.TrimEnd('\\', '/'),
            right.TrimEnd('\\', '/'),
            StringComparison.OrdinalIgnoreCase);
    }

    private readonly record struct RemoteScanItem(IRemoteFile Item, IReadOnlyList<ClassifierOptimizer.MetadataMatch> MetadataMatches, bool HasContentRules);

    private enum RemoteScanOutcome
    {
        Completed,
        DeferredRetry
    }
}

