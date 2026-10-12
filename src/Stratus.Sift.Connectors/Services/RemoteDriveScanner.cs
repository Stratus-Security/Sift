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
        CancellationToken cancellationToken,
        RemoteDriveScanExecutionOptions? executionOptions = null)
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
            cancellationToken,
            executionOptions,
            shouldSkipItem: null,
            onItemProcessed: null,
            onScanIncomplete: null);
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
        CancellationToken cancellationToken,
        RemoteDriveScanExecutionOptions? executionOptions = null,
        Func<IRemoteFile, bool>? shouldSkipItem = null,
        Func<IRemoteFile, CancellationToken, ValueTask>? onItemProcessed = null,
        Action? onScanIncomplete = null)
    {
        _logger.LogInformation("Scanning Drive: {DriveName} ({DriveId})", drive.Name, drive.Id);

        executionOptions ??= new RemoteDriveScanExecutionOptions();
        var workerCount = Math.Clamp(executionOptions.WorkerCount, 1, 256);
        var queueCapacity = Math.Clamp(executionOptions.QueueCapacity, workerCount, 4096);
        var executionPlan = ScannerExecutionPlan.Create(optimizer, policyMap, ignoreRules);
        var callerCancellationToken = cancellationToken;
        using var pipelineCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cancellationToken = pipelineCancellation.Token;

        var pendingItems = 0;
        long queuedItems = 0;
        long completedItems = 0;
        long deferredContentItems = 0;
        long failedContentItems = 0;
        long incompleteInspectionItems = 0;
        long additionalInspectionFailures = 0;
        var failureLog = new RemoteScanFailureLog(_logger);
        var channel = Channel.CreateBounded<RemoteScanItem>(new BoundedChannelOptions(queueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleWriter = true,
            SingleReader = false
        });

        Exception? producerException = null;
        Exception? workerException = null;
        string newDeltaToken = string.Empty;
        var traversal = new RemoteFileTraversal(options.ScanExternalFiles, ignoreRules);

        var workers = Enumerable.Range(0, workerCount).Select(_ => Task.Run(async () =>
        {
            try
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
                        var outcome = await ProcessItemAsync(scanItem, executionPlan, policyMap, options, onIssueFound, failureLog, cancellationToken);
                        if (outcome == RemoteScanOutcome.DeferredRetry)
                        {
                            Interlocked.Increment(ref deferredContentItems);
                        }
                        else if (outcome == RemoteScanOutcome.Failed)
                        {
                            Interlocked.Increment(ref failedContentItems);
                        }
                        else
                        {
                            // Content was processed even when permission/history inspection
                            // is incomplete. Count the work, but never journal it as complete.
                            if (!scanItem.Item.IsContentComplete)
                                Interlocked.Increment(ref incompleteInspectionItems);
                            else if (onItemProcessed != null)
                            {
                                await onItemProcessed(scanItem.Item, cancellationToken);
                            }
                            onFilesScanned?.Invoke(1);
                        }
                    }
                    finally
                    {
                        var depth = Interlocked.Decrement(ref pendingItems);
                        onQueueDepth?.Invoke(Math.Max(depth, 0));
                    }
                    // A failed completion callback must never satisfy a checkpoint barrier.
                    Interlocked.Increment(ref completedItems);
                }
            }
            catch (Exception ex)
            {
                Interlocked.CompareExchange(ref workerException, ex, null);
                pipelineCancellation.Cancel();
                throw;
            }
        }, cancellationToken)).ToArray();

        try
        {
            if (ensureScanActive != null)
            {
                await ensureScanActive(cancellationToken);
            }

            async Task EnqueueItemAsync(IRemoteFile item)
            {
                if (ensureScanActive != null)
                {
                    await ensureScanActive(cancellationToken);
                }

                onCurrentPath?.Invoke(GetFindingResourcePath(item));

                if (item is IRemoteFileInspection inspection && !executionOptions.EnumerateOnly && !item.IsDeleted && !item.IsLink)
                {
                    try { await inspection.PrepareAsync(cancellationToken); }
                    catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
                    {
                        failureLog.Record("Could not completely inspect sharing for", item.Path, ex);
                    }
                }

                if (item.IsContentComplete && shouldSkipItem?.Invoke(item) == true)
                {
                    return;
                }

                if (item.IsDeleted)
                {
                    if (onItemProcessed != null)
                    {
                        await onItemProcessed(item, cancellationToken);
                    }
                    return;
                }

                if (item.IsLink && (!item.IsExternal || !options.ScanExternalFiles))
                {
                    if (onItemProcessed != null)
                    {
                        await onItemProcessed(item, cancellationToken);
                    }
                    return;
                }

                var matchedIgnoreRules = IgnoreRuleEvaluator.GetMatchedRules(item.Path, ignoreRules);
                if (IgnoreRuleEvaluator.ShouldIgnoreDespiteMetadata(matchedIgnoreRules, []))
                {
                    if (onItemProcessed != null)
                    {
                        await onItemProcessed(item, cancellationToken);
                    }
                    return;
                }

                onFilesDiscovered?.Invoke(1);

                if (executionOptions.EnumerateOnly)
                {
                    return;
                }

                var ext = item.IsDirectory ? string.Empty : Path.GetExtension(item.ContentName);
                var metadataPath = item.IsDirectory ? EnsureDirectoryMetadataPath(item.Path) : item.Path;
                var metadataMatches = optimizer.GetMetadataMatches(metadataPath, item.IsDirectory ? null : item.Name).ToList();
                var directMetadataMatches = metadataMatches
                    .Where(match => PathsReferToSameScope(match.ResourcePath, metadataPath))
                    .ToList();
                var metadataClassifiers = directMetadataMatches
                    .Select(match => match.Classifier)
                    .DistinctBy(classifier => classifier.Id)
                    .ToList();

                var requiresContentScan = !item.IsDirectory
                    && (optimizer.HasRulesForExtension(ext) || ShouldInspectZip(ext, options));
                if (!metadataClassifiers.Any() && !requiresContentScan)
                {
                    if (!item.IsContentComplete)
                    {
                        Interlocked.Increment(ref incompleteInspectionItems);
                        return;
                    }
                    if (onItemProcessed != null)
                    {
                        await onItemProcessed(item, cancellationToken);
                    }
                    return;
                }

                var depth = Interlocked.Increment(ref pendingItems);
                Interlocked.Increment(ref queuedItems);
                onQueueDepth?.Invoke(depth);

                await channel.Writer.WriteAsync(
                    new RemoteScanItem(item, directMetadataMatches, requiresContentScan),
                    cancellationToken);
            }

            newDeltaToken = await drive.ProcessChangesAsync(
                deltaToken,
                item => traversal.ProcessAsync(item, EnqueueItemAsync, (failedItem, exception) =>
                {
                    additionalInspectionFailures++;
                    failureLog.Record(failedItem.IsLink ? "Could not follow remote shortcut"
                        : failedItem.IsDirectory ? "Could not enumerate remote folder"
                        : "Could not inspect additional remote content for", failedItem.Path, exception);
                }, cancellationToken),
                async checkpointToken =>
                {
                    var requiredCompletedItems = Interlocked.Read(ref queuedItems);
                    await WaitForQueuedItemsAsync(requiredCompletedItems, () => Interlocked.Read(ref completedItems), cancellationToken);
                    cancellationToken.ThrowIfCancellationRequested();

                    if (string.IsNullOrWhiteSpace(checkpointToken))
                    {
                        // All abandoned work has drained. The fresh crawl determines completeness now.
                        Interlocked.Exchange(ref deferredContentItems, 0);
                        Interlocked.Exchange(ref failedContentItems, 0);
                        Interlocked.Exchange(ref incompleteInspectionItems, 0);
                        additionalInspectionFailures = 0;
                        failureLog.Reset();
                        traversal.Reset();
                    }
                    else if (traversal.HasFollowedLinks)
                    {
                        return;
                    }
                    else if (drive is IRemoteDriveEnumerationReportProvider { EnumerationFailureCount: > 0 }
                        || Interlocked.Read(ref deferredContentItems) > 0 || Interlocked.Read(ref failedContentItems) > 0
                        || Interlocked.Read(ref incompleteInspectionItems) > 0 || additionalInspectionFailures > 0)
                    {
                        _logger.LogDebug(
                            "Skipping delta checkpoint for drive {DriveName} ({DriveId}) because one or more files could not be scanned.",
                            drive.Name,
                            drive.Id);
                        return;
                    }

                    if (onCheckpointToken != null)
                    {
                        await onCheckpointToken(checkpointToken);
                    }
                },
                cancellationToken);
        }
        catch (Exception ex) when (IsRetriableThrottleFailure(ex, out var statusCode))
        {
            onScanIncomplete?.Invoke();
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
        catch (Exception ex)
        {
            producerException ??= ex;
        }

        callerCancellationToken.ThrowIfCancellationRequested();
        var pipelineException = workerException ?? producerException;
        if (pipelineException != null)
        {
            onScanIncomplete?.Invoke();
            ExceptionDispatchInfo.Capture(pipelineException).Throw();
        }

        var deferredCount = Interlocked.Read(ref deferredContentItems);
        if (deferredCount > 0)
        {
            onScanIncomplete?.Invoke();
        }

        var failedCount = Interlocked.Read(ref failedContentItems);
        if (failedCount > 0)
        {
            onScanIncomplete?.Invoke();
        }

        var inspectionCount = Interlocked.Read(ref incompleteInspectionItems);
        long enumerationFailureCount = 0;
        if (drive is IRemoteDriveEnumerationReportProvider enumerationReport)
        {
            enumerationFailureCount = enumerationReport.EnumerationFailureCount;
            foreach (var failure in enumerationReport.EnumerationFailures)
                failureLog.Record("Could not enumerate remote folder", failure.Path, failure.Exception,
                    expected: RemoteScanExceptionClassifier.IsExpectedForEnumeration(failure.Exception));
        }
        if (inspectionCount > 0 || additionalInspectionFailures > 0 || enumerationFailureCount > 0) onScanIncomplete?.Invoke();
        failureLog.WriteSummary(drive.Name, failedCount, inspectionCount, additionalInspectionFailures, deferredCount, enumerationFailureCount);

        if (!string.IsNullOrEmpty(newDeltaToken))
        {
            if (deferredCount > 0 || failedCount > 0 || inspectionCount > 0 || additionalInspectionFailures > 0 || enumerationFailureCount > 0)
            {
                _logger.LogDebug(
                    "Skipping final delta token update for drive {DriveName} ({DriveId}) because one or more files could not be scanned.",
                    drive.Name,
                    drive.Id);
                return;
            }

            // A source-drive delta cannot track changes in a shortcut's backing drive.
            // Use item-version resume instead, re-enumerating links on the next run.
            await onNewDeltaToken(traversal.HasFollowedLinks ? string.Empty : newDeltaToken);
        }
    }

    private async Task<RemoteScanOutcome> ProcessItemAsync(
        RemoteScanItem scanItem,
        ScannerExecutionPlan executionPlan,
        Dictionary<Guid, List<Policy>> policyMap,
        ScanOptions options,
        Func<ScanFinding, Task> onIssueFound,
        RemoteScanFailureLog failureLog,
        CancellationToken cancellationToken)
    {
        var item = scanItem.Item;
        var metadataHandled = false;
        async Task ReportFallbackMetadata()
        {
            if (metadataHandled) return;
            metadataHandled = true;
            var inspection = item as IRemoteFileInspection;
            await ReportMetadataIssuesAsync(scanItem.MetadataMatches, ScopePolicyMap(item.Path, policyMap),
                inspection?.Exposure ?? (item.IsExternal ? "External" : "Internal"), GetFindingResourcePath(item),
                onIssueFound, inspection?.Owner ?? "Cloud", inspection?.AclEntries.ToList());
        }
        try
        {
            var optimizer = executionPlan.Optimizer;
            var inspection = item as IRemoteFileInspection;
            var exposure = inspection?.Exposure ?? (item.IsExternal ? "External" : "Internal");
            var owner = inspection?.Owner ?? "Cloud";
            var acls = inspection?.AclEntries.ToList();
            var ext = Path.GetExtension(item.ContentName ?? string.Empty);
            var scopedPolicyMap = ScopePolicyMap(item.Path, policyMap);
            var findingResourcePath = GetFindingResourcePath(item);
            var inspectZip = !item.IsDirectory && ShouldInspectZip(ext, options);
            // Archive entries have their own policy paths, which may not match the container.
            if (scopedPolicyMap.Count == 0 && !inspectZip)
            {
                return RemoteScanOutcome.Completed;
            }

            if (item.IsDirectory)
            {
                await ReportFallbackMetadata();
                return RemoteScanOutcome.Completed;
            }

            if (!options.EnableBinaryDocuments && _contentExtractor.Supports(ext))
            {
                await ReportFallbackMetadata();
                return RemoteScanOutcome.Completed;
            }

            var needContentScan = scanItem.RequiresContentScan
                || scanItem.MetadataMatches.Any(match => optimizer.GetSubOptimizer(match.Classifier) != null);
            if (!needContentScan)
            {
                await ReportFallbackMetadata();
                return RemoteScanOutcome.Completed;
            }

            // ZIPs need the complete central directory. The archive scanner enforces its
            // own buffering/expansion limits; a ranged head is not a valid archive.
            if (!inspectZip && item.SampleLargeContent && item.Size.HasValue
                && item.Size.Value > (_contentExtractor.Supports(ext) ? options.MaxBinaryDocumentBytes : options.MaxFileSize))
            {
                if (options.EnableBinaryDocuments && _contentExtractor.Supports(ext))
                {
                    await ReportFallbackMetadata();
                    failureLog.Record("Document exceeds the configured size limit:", item.Path, expected: true);
                    return RemoteScanOutcome.Failed;
                }

                try
                {
                    using var headStream = await item.GetContentRangeAsync(0, options.HeadSize - 1, cancellationToken);
                    if (headStream == null)
                    {
                        await ReportFallbackMetadata();
                        failureLog.Record("No content stream was available for", item.Path, expected: true);
                        return RemoteScanOutcome.Failed;
                    }

                    using var limitedHead = new LengthLimitedReadStream(headStream, options.HeadSize);
                    var headScanResult = await ((FileScanner)_scanner).ScanStreamAsync(
                        limitedHead,
                        item.Path,
                        executionPlan,
                        options,
                        exposure,
                        owner,
                        acls,
                        cancellationToken,
                        contentFileName: item.ContentName, metadataFileName: item.Name);

                    metadataHandled = true;
                    foreach (var issue in headScanResult.Issues)
                    {
                        issue.ResourcePath = findingResourcePath;
                        await onIssueFound(issue);
                    }

                    return RemoteScanOutcome.Completed;
                }
                catch (RemoteContentUnavailableException ex)
                {
                    await ReportFallbackMetadata();
                    return HandleContentUnavailable(ex, item, failureLog);
                }
            }

            try
            {
                using var stream = await item.GetContentAsync(cancellationToken);
                if (stream == null)
                {
                    await ReportFallbackMetadata();
                    failureLog.Record("No content stream was available for", item.Path, expected: true);
                    return RemoteScanOutcome.Failed;
                }

                var scanResult = await ((FileScanner)_scanner).ScanStreamAsync(stream, item.Path, executionPlan,
                    options, exposure, owner, acls, cancellationToken, contentFileName: item.ContentName, metadataFileName: item.Name);

                metadataHandled = true;
                foreach (var issue in scanResult.Issues)
                {
                    issue.ResourcePath = GetScanFindingResourcePath(item, issue.ResourcePath);
                    await onIssueFound(issue);
                }

                if (!scanResult.IsComplete)
                {
                    failureLog.Record("Content extraction or archive inspection was incomplete for", item.Path,
                        expected: !scanResult.HasUnexpectedInspectionFailure, detail: scanResult.IncompleteReason);
                    return RemoteScanOutcome.Failed;
                }
                return RemoteScanOutcome.Completed;
            }
            catch (RemoteContentUnavailableException ex)
            {
                await ReportFallbackMetadata();
                return HandleContentUnavailable(ex, item, failureLog);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (RemoteScanExceptionClassifier.IsExpected(ex))
        {
            await ReportFallbackMetadata();
            _logger.LogDebug(ex, "Skipping inaccessible item {ItemPath}", item.Path);
            return RemoteScanOutcome.Failed;
        }
        catch (Exception ex)
        {
            await ReportFallbackMetadata();
            failureLog.Record("Error scanning item", item.Path, ex);
            return RemoteScanOutcome.Failed;
        }
    }

    private RemoteScanOutcome HandleContentUnavailable(RemoteContentUnavailableException exception, IRemoteFile item, RemoteScanFailureLog failureLog)
    {
        if (RemoteScanExceptionClassifier.IsExpected(exception))
        {
            _logger.LogDebug(exception, "Skipping temporarily unavailable item {ItemPath}", item.Path);
            return RemoteScanOutcome.Failed;
        }

        if (exception.ShouldRetry)
        {
            failureLog.Record("Deferring file scan for", item.Path, exception);
            return RemoteScanOutcome.DeferredRetry;
        }

        failureLog.Record("Skipping file scan for", item.Path, exception);
        return RemoteScanOutcome.Failed;
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
        Func<ScanFinding, Task> onIssueFound,
        string owner = "Unknown",
        List<AclEntry>? acls = null)
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
                    Owner = owner,
                    AclEntries = acls ?? [],
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

    private static string GetScanFindingResourcePath(IRemoteFile item, string resourcePath)
    {
        var root = GetFindingResourcePath(item);
        return resourcePath.StartsWith(item.Path + "!/", StringComparison.OrdinalIgnoreCase)
            ? root + resourcePath[item.Path.Length..]
            : root;
    }

    private static bool ShouldInspectZip(string extension, ScanOptions options)
        => options.EnableZipArchives && FileScanner.IsSupportedArchive(extension);

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

    private readonly record struct RemoteScanItem(IRemoteFile Item, IReadOnlyList<ClassifierOptimizer.MetadataMatch> MetadataMatches, bool RequiresContentScan);

    private enum RemoteScanOutcome
    {
        Completed,
        DeferredRetry,
        Failed
    }
}

