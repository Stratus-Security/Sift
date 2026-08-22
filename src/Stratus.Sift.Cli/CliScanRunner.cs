using Microsoft.Extensions.DependencyInjection;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.FileSystem;
using Stratus.Sift.Core;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;
using System.Runtime.Versioning;

namespace Stratus.Sift.Cli;

internal static class CliScanRunner
{
    internal const bool DefaultFullScan = true;

    internal static async Task<int> RunConnectorScanAsync(
        string providerName,
        Dictionary<string, string> config,
        bool includeBinary,
        bool enumerateOnly,
        string? rulesPath,
        CliLlmOptions? llmOptions = null,
        CliOutputOptions? outputOptions = null,
        IConnector? connectorOverride = null,
        bool fullScan = DefaultFullScan,
        CancellationToken cancellationToken = default)
    {
        var effectiveOutputOptions = ResolveOutputOptions(outputOptions, fullScan);
        await using var display = new CliProgressDisplay($"Remote {providerName} scan", effectiveOutputOptions);
        await using var session = await CliScannerBootstrap.InitializeScannerAsync(rulesPath, Program.CreateHost, cancellationToken);
        var throttleNotifications = session.Host.Services.GetRequiredService<ThrottleNotificationHub>();
        var checkpointStore = session.Host.Services.GetRequiredService<CliCheckpointStore>();
        display.AttachThrottleMonitor(throttleNotifications);

        var connectors = session.Host.Services.GetServices<IConnector>();
        var normalizedProviderName = CliConnectorConfiguration.NormalizeProviderName(providerName);
        var connector = connectorOverride
            ?? connectors.FirstOrDefault(c => c.ProviderName.Equals(normalizedProviderName, StringComparison.OrdinalIgnoreCase));

        if (connector == null)
        {
            display.WriteEvent(
                $"Error: connector provider '{providerName}' not found. Available: {string.Join(", ", connectors.Select(c => c.ProviderName))}",
                ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Remote scan failed");
            return CliExitCodes.Failed;
        }

        display.SetPhase($"Initializing {connector.ProviderName}");

        try
        {
            await connector.InitializeAsync(config).WaitAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            display.WriteEvent($"Error: failed to initialize {connector.ProviderName}: {GetErrorMessage(ex)}", ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Remote scan failed");
            return CliExitCodes.Failed;
        }

        display.SetPhase($"Discovering {connector.ProviderName} drives");

        List<IRemoteDrive> drives;
        try
        {
            drives = (await connector.GetDrivesAsync().WaitAsync(cancellationToken)).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            display.WriteEvent($"Error: failed to discover {connector.ProviderName} drives: {GetErrorMessage(ex)}", ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Remote scan failed");
            return CliExitCodes.Failed;
        }

        foreach (var drive in drives.OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase))
        {
            display.WriteDiscoveryDrive(drive.Name, drive.Id, drive.DriveType.ToString(), drive.WebUrl);
        }

        if (connector is IConnectorDiscoveryReportProvider reportProvider)
        {
            var report = reportProvider.DiscoveryReport;
            var counts = string.Join(
                ", ",
                report.SourceCounts
                    .Where(entry => entry.Value > 0)
                    .OrderBy(entry => entry.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(entry => $"{entry.Key} {entry.Value:N0}"));
            display.WriteEvent(
                string.IsNullOrWhiteSpace(counts)
                    ? $"Discovery coverage: {report.Coverage}."
                    : $"Discovery coverage: {report.Coverage} | {counts}.",
                ConsoleColor.Cyan);

            foreach (var warning in report.Warnings)
            {
                display.WriteEvent($"Discovery warning: {warning}", ConsoleColor.Yellow);
            }
        }

        if (enumerateOnly)
        {
            display.Complete("Remote enumeration complete");
            return CliExitCodes.Success;
        }

        var llmValidator = await CliLlmValidationSupport.CreateValidatorAsync(session.Host.Services, llmOptions, display, cancellationToken);
        var remoteDriveScanner = session.Host.Services.GetRequiredService<RemoteDriveScanner>();
        display.SetTotalDrives(drives.Count);
        display.SetPhase($"Scanning {connector.ProviderName}");
        var scanOptions = CreateScanOptions(includeBinary, llmOptions);

        if (fullScan)
        {
            display.WriteEvent("Full scan: saved incremental checkpoints will be ignored for this run.", ConsoleColor.Cyan);
        }
        else
        {
            var resumedDrives = drives.Count(drive => !string.IsNullOrWhiteSpace(GetDeltaToken(checkpointStore, drive)));
            if (resumedDrives > 0)
            {
                display.WriteEvent(
                    $"Incremental {connector.ProviderName} scan: resuming {resumedDrives:N0} of {drives.Count:N0} drive(s) from saved checkpoints. Drives without a completed checkpoint will restart from the beginning.",
                    ConsoleColor.Cyan);
            }
            else
            {
                display.WriteEvent(
                    $"Incremental {connector.ProviderName} scan: no saved checkpoints were found, so all {drives.Count:N0} drive(s) will start from the beginning.",
                    ConsoleColor.Cyan);
            }
        }

        foreach (var drive in drives)
        {
            cancellationToken.ThrowIfCancellationRequested();
            display.SetCurrentDrive(drive.Name);
            display.ClearCurrentPath();

            try
            {
                var deltaToken = fullScan ? null : GetDeltaToken(checkpointStore, drive);
                await ScanRemoteDriveAsync(drive, deltaToken, remoteDriveScanner, checkpointStore, session, scanOptions, display, llmValidator, llmOptions, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                display.IncrementErrors();
                display.WriteEvent($"Warning: failed to enumerate drive {drive.Name}: {GetErrorMessage(ex)}", ConsoleColor.Yellow);
            }
            finally
            {
                display.ClearCurrentPath();
                display.MarkDriveCompleted();
            }
        }

        display.Complete("Remote scan complete");
        return display.ErrorCount > 0 ? CliExitCodes.Partial : CliExitCodes.Success;
    }

    internal static CliOutputOptions? ResolveOutputOptions(CliOutputOptions? outputOptions, bool fullScan)
    {
        return !fullScan && outputOptions != null
            ? outputOptions with { Append = true }
            : outputOptions;
    }

    internal static async Task<int> RunScanAsync(
        FileSystemScanTarget target,
        bool includeBinary,
        string? rulesPath,
        bool enumerateOnly,
        CliWindowsCredential? credential = null,
        CliLlmOptions? llmOptions = null,
        CliOutputOptions? outputOptions = null,
        bool kerberos = false,
        CancellationToken cancellationToken = default)
    {
        await using var display = new CliProgressDisplay(target.Mode == FileSystemScanMode.Folder
            ? $"Local scan of {target.Value}"
            : $"{target.DisplayName} crawl", outputOptions);

        await using var session = await CliScannerBootstrap.InitializeScannerAsync(rulesPath, Program.CreateHost, cancellationToken);
        var fileScanner = session.Host.Services.GetRequiredService<FileScanner>();
        var standardEnumerator = session.Host.Services.GetRequiredService<StandardFileSystemEnumerator>();
        var scanOptions = CreateScanOptions(includeBinary, llmOptions);
        Stratus.Sift.Core.Validation.ILlmClassifierValidator? llmValidator = null;

        if (target.Mode == FileSystemScanMode.Folder)
        {
            if (!Directory.Exists(target.Value))
            {
                display.WriteEvent($"Error: folder path '{target.Value}' was not found.", ConsoleColor.Red);
                display.IncrementErrors();
                display.Complete("Local scan failed");
                return CliExitCodes.Failed;
            }

            var localRootInfo = GetRootDisplayInfo(target.Value, standardEnumerator);
            display.WriteDiscoveryRoot("root", target.Value, localRootInfo.Exposure, localRootInfo.Access);
            if (enumerateOnly)
            {
                display.Complete("Local enumeration complete");
                return CliExitCodes.Success;
            }

            llmValidator = await CliLlmValidationSupport.CreateValidatorAsync(session.Host.Services, llmOptions, display, cancellationToken);
            display.SetPhase("Scanning local filesystem");
            await ScanFileSystemRootAsync(
                target.Value,
                standardEnumerator,
                fileScanner,
                session.Optimizer,
                session.PolicyMap,
                session.IgnoreRules,
                scanOptions,
                display,
                llmValidator,
                llmOptions,
                cancellationToken);
            display.Complete("Local scan complete");
            return display.ErrorCount > 0 ? CliExitCodes.Partial : CliExitCodes.Success;
        }

        if (!OperatingSystem.IsWindows())
        {
            display.WriteEvent("Error: domain, subnet, and device crawl modes are currently supported only on Windows.", ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Network crawl failed");
            return CliExitCodes.Failed;
        }

        if (ShouldUseKerberosPreferredAuthentication(credential))
        {
            return await RunKerberosDiscoveryScanAsync(
                target,
                credential,
                enumerateOnly,
                session,
                display,
                scanOptions,
                llmValidator,
                llmOptions,
                allowNtlmFallback: !kerberos,
                cancellationToken);
        }

        if (kerberos)
        {
            display.WriteEvent("Error: Kerberos cannot authenticate a local machine account. Use an Active Directory identity or remove --kerberos.", ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Network crawl failed");
            return CliExitCodes.Failed;
        }

        return await RunWindowsDiscoveryScanAsync(target, credential, enumerateOnly, session, display, scanOptions, fileScanner, standardEnumerator, llmValidator, llmOptions, cancellationToken);
    }

    internal static bool ShouldUseKerberosPreferredAuthentication(CliWindowsCredential? credential) =>
        credential?.IsLocalMachineAccount != true;

    [SupportedOSPlatform("windows")]
    private static async Task<int> RunKerberosDiscoveryScanAsync(
        FileSystemScanTarget target,
        CliWindowsCredential? credential,
        bool enumerateOnly,
        CliScannerSession session,
        CliProgressDisplay display,
        Stratus.Sift.Scanner.Models.ScanOptions scanOptions,
        Stratus.Sift.Core.Validation.ILlmClassifierValidator? llmValidator,
        CliLlmOptions? llmOptions,
        bool allowNtlmFallback,
        CancellationToken cancellationToken)
    {
        var kerberosService = session.Host.Services.GetRequiredService<SmbKerberosService>();
        display.SetPhase($"Discovering {target.DisplayName.ToLowerInvariant()} SMB shares");
        display.WriteEvent(
            allowNtlmFallback
                ? "Authentication mode: Kerberos preferred; NTLM is attempted only per host when Kerberos is unavailable."
                : "Authentication mode: strict Kerberos (cifs SPN); NTLM fallback is disabled.",
            ConsoleColor.Cyan);

        SmbKerberosDiscoveryResult discovery;
        try
        {
            discovery = await kerberosService.DiscoverDrivesAsync(
                target,
                credential,
                allowNtlmFallback,
                path => IgnoreRuleEvaluator.ShouldPruneDirectory(path, session.IgnoreRules),
                display.SetCurrentPath,
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            display.WriteEvent($"Error: failed to discover SMB shares with Kerberos: {GetErrorMessage(ex)}", ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Network crawl failed");
            return CliExitCodes.Failed;
        }

        foreach (var warning in discovery.Warnings)
        {
            display.WriteEvent($"Warning: {warning}", ConsoleColor.Yellow);
        }


        if (discovery.NtlmFallbackHostCount > 0)
        {
            display.WriteEvent(
                $"Authentication summary: {discovery.NtlmFallbackHostCount:N0} host(s) required explicit NTLM fallback.",
                ConsoleColor.Yellow);
        }

        if (discovery.Drives.Count == 0)
        {
            display.WriteEvent(
                allowNtlmFallback
                    ? "Warning: no readable SMB shares were discovered through Kerberos or NTLM fallback."
                    : "Warning: no readable SMB shares were discovered through strict Kerberos authentication.",
                ConsoleColor.Yellow);
            display.Complete("Network crawl complete");
            return CliExitCodes.Success;
        }

        display.WriteEvent($"Discovered {discovery.Drives.Count:N0} readable SMB share(s).", ConsoleColor.Cyan);
        foreach (var drive in discovery.Drives)
        {
            var authentication = drive is SmbKerberosDrive smbDrive
                ? smbDrive.AuthenticationProtocol.ToString()
                : "SMB";
            display.WriteDiscoveryRoot("share", drive.WebUrl, "R", authentication);
        }

        if (enumerateOnly)
        {
            display.Complete("Network enumeration complete");
            return CliExitCodes.Success;
        }

        llmValidator ??= await CliLlmValidationSupport.CreateValidatorAsync(session.Host.Services, llmOptions, display, cancellationToken);
        var remoteDriveScanner = session.Host.Services.GetRequiredService<RemoteDriveScanner>();
        var checkpointStore = session.Host.Services.GetRequiredService<CliCheckpointStore>();
        display.SetTotalDrives(discovery.Drives.Count);
        display.SetPhase("Scanning SMB shares");

        foreach (var drive in discovery.Drives)
        {
            cancellationToken.ThrowIfCancellationRequested();
            display.SetCurrentDrive(drive.Name);
            display.ClearCurrentPath();
            try
            {
                await ScanRemoteDriveAsync(
                    drive,
                    deltaToken: null,
                    remoteDriveScanner,
                    checkpointStore,
                    session,
                    scanOptions,
                    display,
                    llmValidator,
                    llmOptions,
                    cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                display.IncrementErrors();
                display.WriteEvent($"Warning: failed to scan {drive.Name}: {GetErrorMessage(ex)}", ConsoleColor.Yellow);
            }
            finally
            {
                display.ClearCurrentPath();
                display.MarkDriveCompleted();
            }
        }

        display.Complete("Network crawl complete");
        return display.ErrorCount > 0 ? CliExitCodes.Partial : CliExitCodes.Success;
    }

    [SupportedOSPlatform("windows")]
    private static async Task<int> RunWindowsDiscoveryScanAsync(
        FileSystemScanTarget target,
        CliWindowsCredential? credential,
        bool enumerateOnly,
        CliScannerSession session,
        CliProgressDisplay display,
        Stratus.Sift.Scanner.Models.ScanOptions scanOptions,
        FileScanner fileScanner,
        StandardFileSystemEnumerator standardEnumerator,
        Stratus.Sift.Core.Validation.ILlmClassifierValidator? llmValidator,
        CliLlmOptions? llmOptions,
        CancellationToken cancellationToken)
    {
        var smbDiscovery = session.Host.Services.GetRequiredService<SmbDiscoveryService>();
        WindowsImpersonationSession impersonationSession;
        try
        {
            impersonationSession = WindowsImpersonationSession.Create(credential);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            display.WriteEvent($"Error: failed to initialize Windows impersonation: {GetErrorMessage(ex)}", ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Network crawl failed");
            return CliExitCodes.Failed;
        }

        using (impersonationSession)
        {
            display.SetPhase($"Discovering {target.DisplayName.ToLowerInvariant()} SMB shares");

            IReadOnlyList<string> roots;
            try
            {
                roots = target.Mode == FileSystemScanMode.Domain && credential?.IsLocalMachineAccount == true
                    ? await DiscoverDomainRootsWithLocalCredentialAsync(smbDiscovery, impersonationSession, display, cancellationToken)
                    : await impersonationSession.RunAsync(() => smbDiscovery.DiscoverRootsAsync(target, credential, cancellationToken));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                display.WriteEvent($"Error: failed to discover SMB shares: {GetErrorMessage(ex)}", ConsoleColor.Red);
                display.IncrementErrors();
                display.Complete("Network crawl failed");
                return CliExitCodes.Failed;
            }

            if (roots.Count == 0)
            {
                display.WriteEvent("Warning: no accessible SMB shares were discovered for the requested target.", ConsoleColor.Yellow);
                display.Complete("Network crawl complete");
                return CliExitCodes.Success;
            }

            display.WriteEvent($"Discovered {roots.Count:N0} accessible SMB share(s).", ConsoleColor.Cyan);
            foreach (var root in roots)
            {
                var rootInfo = await impersonationSession.RunAsync(() => Task.FromResult(GetRootDisplayInfo(root, standardEnumerator)));
                display.WriteDiscoveryRoot("share", root, rootInfo.Exposure, rootInfo.Access);
            }

            if (enumerateOnly)
            {
                display.Complete("Network enumeration complete");
                return CliExitCodes.Success;
            }

            llmValidator ??= await CliLlmValidationSupport.CreateValidatorAsync(session.Host.Services, llmOptions, display, cancellationToken);
            display.SetTotalDrives(roots.Count);
            display.SetPhase("Scanning SMB shares");

            foreach (var root in roots)
            {
                cancellationToken.ThrowIfCancellationRequested();
                display.SetCurrentDrive(root);
                display.ClearCurrentPath();

                try
                {
                    await impersonationSession.RunAsync(() => ScanFileSystemRootAsync(
                        root,
                        standardEnumerator,
                        fileScanner,
                        session.Optimizer,
                        session.PolicyMap,
                        session.IgnoreRules,
                        scanOptions,
                        display,
                        llmValidator,
                        llmOptions,
                        cancellationToken));
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    display.IncrementErrors();
                    display.WriteEvent($"Warning: failed to scan {root}: {GetErrorMessage(ex)}", ConsoleColor.Yellow);
                }
                finally
                {
                    display.MarkDriveCompleted();
                }
            }

            display.Complete("Network crawl complete");
            return display.ErrorCount > 0 ? CliExitCodes.Partial : CliExitCodes.Success;
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task<IReadOnlyList<string>> DiscoverDomainRootsWithLocalCredentialAsync(
        SmbDiscoveryService smbDiscovery,
        WindowsImpersonationSession impersonationSession,
        CliProgressDisplay display,
        CancellationToken cancellationToken)
    {
        display.WriteEvent("Info: using the current Windows identity for AD computer discovery and the supplied local credentials for SMB access.", ConsoleColor.Cyan);
        var hosts = smbDiscovery.EnumerateDomainHostsForScan(null);
        return await impersonationSession.RunAsync(() => smbDiscovery.DiscoverRootsForHostsAsync(hosts, cancellationToken));
    }

    private static async Task ScanRemoteDriveAsync(
        IRemoteDrive drive,
        string? deltaToken,
        RemoteDriveScanner remoteDriveScanner,
        CliCheckpointStore checkpointStore,
        CliScannerSession session,
        Stratus.Sift.Scanner.Models.ScanOptions scanOptions,
        CliProgressDisplay display,
        Stratus.Sift.Core.Validation.ILlmClassifierValidator? llmValidator,
        CliLlmOptions? llmOptions,
        CancellationToken cancellationToken)
    {
        await remoteDriveScanner.ScanDriveChangesAsync(
            drive,
            deltaToken,
            session.Optimizer,
            session.PolicyMap,
            session.IgnoreRules,
            scanOptions,
            onIssueFound: async issue =>
            {
                var validatedIssue = await CliLlmValidationSupport.ValidateFindingAsync(llmValidator, issue, llmOptions, cancellationToken);
                if (validatedIssue == null)
                {
                    return;
                }

                display.AddFindings(1);
                display.WriteFinding(validatedIssue, string.IsNullOrWhiteSpace(validatedIssue.ResourcePath) ? drive.WebUrl : validatedIssue.ResourcePath);
            },
            onCheckpointToken: token =>
            {
                SetDeltaToken(checkpointStore, drive, token);
                return Task.CompletedTask;
            },
            onNewDeltaToken: token =>
            {
                SetDeltaToken(checkpointStore, drive, token);
                return Task.CompletedTask;
            },
            onFilesDiscovered: display.AddFilesDiscovered,
            onFilesScanned: display.AddFilesScanned,
            onQueueDepth: null,
            onCurrentPath: display.SetCurrentPath,
            ensureScanActive: null,
            cancellationToken: cancellationToken);
    }

    private static string? GetDeltaToken(CliCheckpointStore checkpointStore, IRemoteDrive drive)
    {
        return checkpointStore.GetRemoteDriveToken(drive.ConnectionId)
            ?? checkpointStore.GetRemoteDriveToken(drive.Id);
    }

    private static void SetDeltaToken(CliCheckpointStore checkpointStore, IRemoteDrive drive, string token)
    {
        if (!string.IsNullOrWhiteSpace(token))
        {
            checkpointStore.SetRemoteDriveToken(drive.ConnectionId, token);
        }
    }

    private static async Task ScanFileSystemRootAsync(
        string rootPath,
        StandardFileSystemEnumerator standardEnumerator,
        FileScanner fileScanner,
        ClassifierOptimizer optimizer,
        Dictionary<Guid, List<Policy>> policyMap,
        List<IgnoreRule> ignoreRules,
        Stratus.Sift.Scanner.Models.ScanOptions scanOptions,
        CliProgressDisplay display,
        Stratus.Sift.Core.Validation.ILlmClassifierValidator? llmValidator,
        CliLlmOptions? llmOptions,
        CancellationToken cancellationToken)
    {
        PathFilter? directoryFilter = ignoreRules.Count == 0
            ? null
            : path => IgnoreRuleEvaluator.ShouldPruneDirectory(path.ToString(), ignoreRules);

        var entries = standardEnumerator.EnumeratePath(rootPath, directoryFilter, includeAcls: false);
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = cancellationToken
        };

        await Parallel.ForEachAsync(entries, parallelOptions, async (entry, itemCancellationToken) =>
        {
            try
            {
                var scanPath = entry.IsDirectory ? EnsureDirectoryMetadataPath(entry.Path) : entry.Path;
                if (IgnoreRuleEvaluator.ShouldIgnoreDespiteMetadata(IgnoreRuleEvaluator.GetMatchedRules(scanPath, ignoreRules), []))
                {
                    return;
                }

                if (!entry.IsDirectory)
                {
                    display.AddFilesDiscovered(1);
                    display.IncrementFiles();
                }

                var findings = fileScanner.ScanFile(
                        scanPath,
                        optimizer,
                        policyMap,
                        scanOptions,
                        exposure: entry.Exposure,
                        owner: entry.Owner,
                        aclEntries: entry.AclEntries,
                        fileSize: entry.Size,
                        ext: Path.GetExtension(entry.Path),
                        name: entry.Name,
                        ignoreRules: ignoreRules)
                    .ToList();

                var validatedFindings = await ValidateFindingsAsync(findings, llmValidator, llmOptions, itemCancellationToken);
                ReportFindings(display, validatedFindings, entry);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                display.IncrementErrors();
                display.WriteEvent($"Warning: failed to scan {entry.Path}: {GetErrorMessage(ex)}", ConsoleColor.Yellow);
            }
        });
    }

    private static void ReportFindings(CliProgressDisplay display, IReadOnlyCollection<ScanFinding> findings, FileSystemEntryInfo entry)
    {
        if (findings.Count == 0)
        {
            return;
        }

        display.AddFindings(findings.Count);
        var kind = entry.IsDirectory
            ? (entry.Path.StartsWith(@"\\", StringComparison.Ordinal) && IsUncShareRoot(entry.Path)
                ? CliSnafflerFormatter.CliSnafflerResultKind.Share
                : CliSnafflerFormatter.CliSnafflerResultKind.Directory)
            : CliSnafflerFormatter.CliSnafflerResultKind.File;
        var context = new CliSnafflerFormatter.CliFindingDisplayContext(
            kind,
            entry.IsDirectory ? null : entry.Size,
            entry.Modified,
            "R",
            string.IsNullOrWhiteSpace(entry.Exposure) || string.Equals(entry.Exposure, "Unknown", StringComparison.OrdinalIgnoreCase)
                ? null
                : entry.Exposure);

        foreach (var finding in findings)
        {
            display.WriteFinding(finding, finding.ResourcePath, context);
        }
    }

    private static Stratus.Sift.Scanner.Models.ScanOptions CreateScanOptions(bool includeBinary, CliLlmOptions? llmOptions)
    {
        return new Stratus.Sift.Scanner.Models.ScanOptions
        {
            EnableBinaryDocuments = includeBinary,
            EnableLlmValidation = llmOptions?.Enabled == true,
            OllamaUrl = llmOptions?.OllamaUrl ?? "http://localhost:11434",
            OllamaModel = llmOptions?.OllamaModel ?? string.Empty,
            LlmTimeoutSeconds = llmOptions?.TimeoutSeconds ?? 20
        };
    }

    private static async Task<List<ScanFinding>> ValidateFindingsAsync(
        List<ScanFinding> findings,
        Stratus.Sift.Core.Validation.ILlmClassifierValidator? llmValidator,
        CliLlmOptions? llmOptions,
        CancellationToken cancellationToken)
    {
        if (llmValidator == null || findings.Count == 0)
        {
            return findings;
        }

        var validated = new List<ScanFinding>(findings.Count);
        foreach (var finding in findings)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var accepted = await CliLlmValidationSupport.ValidateFindingAsync(llmValidator, finding, llmOptions, cancellationToken);
            if (accepted != null)
            {
                validated.Add(accepted);
            }
        }

        return validated;
    }

    private static string GetErrorMessage(Exception exception)
    {
        return exception.GetBaseException().Message;
    }

    private static RootDisplayInfo GetRootDisplayInfo(string path, StandardFileSystemEnumerator standardEnumerator)
    {
        try
        {
            var rootEntry = standardEnumerator.EnumeratePath(path, includeAcls: true).FirstOrDefault();
            if (string.IsNullOrWhiteSpace(rootEntry.Path))
            {
                return new RootDisplayInfo(null, "R");
            }

            var exposure = string.IsNullOrWhiteSpace(rootEntry.Exposure) || string.Equals(rootEntry.Exposure, "Unknown", StringComparison.OrdinalIgnoreCase)
                ? null
                : rootEntry.Exposure;
            var access = CliAccessSummary.ForReadableRoot(rootEntry.AclEntries);
            return new RootDisplayInfo(exposure, string.IsNullOrWhiteSpace(access) ? "R" : access);
        }
        catch
        {
            return new RootDisplayInfo(null, "R");
        }
    }

    private static string EnsureDirectoryMetadataPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.EndsWith('\\') || path.EndsWith('/'))
        {
            return path;
        }

        return path + Path.DirectorySeparatorChar;
    }

    private static bool IsUncShareRoot(string path)
    {
        if (!path.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return false;
        }

        var trimmed = path.TrimEnd('\\', '/');
        var segments = trimmed.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return segments.Length == 2;
    }

    private sealed record RootDisplayInfo(string? Exposure, string Access);
}
