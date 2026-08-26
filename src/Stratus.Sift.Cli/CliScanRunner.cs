using Microsoft.Extensions.DependencyInjection;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.FileSystem;
using Stratus.Sift.Core;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Services;
using Stratus.Sift.Scanner.Models;
using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using System.Threading.Channels;

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
        CancellationToken cancellationToken = default,
        bool showBanner = true)
    {
        var effectiveOutputOptions = ResolveOutputOptions(outputOptions, fullScan);
        await using var display = new CliProgressDisplay(
            $"Remote {providerName} scan",
            effectiveOutputOptions,
            showBanner);
        await using var session = await CliScannerBootstrap.InitializeScannerAsync(rulesPath, Program.CreateHost, cancellationToken);
        var throttleNotifications = session.Host.Services.GetRequiredService<ThrottleNotificationHub>();
        var checkpointStore = session.Host.Services.GetRequiredService<CliCheckpointStore>();
        var resumeStore = session.Host.Services.GetRequiredService<CliResumeStore>();
        display.AttachThrottleMonitor(throttleNotifications);

        var connectors = session.Host.Services.GetServices<IConnector>();
        var connector = connectorOverride
            ?? connectors.FirstOrDefault(c => c.ProviderName.Equals(providerName, StringComparison.OrdinalIgnoreCase));

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

        // Discovery normally performs the first authenticated request. Resolve the
        // account-bound checkpoint scope afterwards so interactive connectors can
        // identify the principal without starting authentication during setup.
        var connectorScope = CliResumeIdentity.CreateConnectorScope(
            providerName,
            config,
            connector is IConnectorCheckpointScopeProvider scopeProvider ? scopeProvider.CheckpointScope : string.Empty,
            session.RuleFingerprint,
            includeBinary,
            llmOptions);

        var llmValidator = await CliLlmValidationSupport.CreateValidatorAsync(session.Host.Services, llmOptions, display, cancellationToken);
        var remoteDriveScanner = session.Host.Services.GetRequiredService<RemoteDriveScanner>();
        display.SetTotalDrives(drives.Count);
        display.SetPhase($"Scanning {connector.ProviderName}");
        var scanOptions = CreateScanOptions(includeBinary, llmOptions);

        if (fullScan)
        {
            display.WriteEvent("Full scan: saved resume checkpoints will be ignored for this run.", ConsoleColor.Cyan);
        }
        else
        {
            var resumedDrives = drives.Count(drive => !string.IsNullOrWhiteSpace(GetDeltaToken(checkpointStore, connectorScope, drive)));
            if (resumedDrives > 0)
            {
                display.WriteEvent(
                    $"Resumed {connector.ProviderName} scan: continuing {resumedDrives:N0} of {drives.Count:N0} drive(s) from saved checkpoints. Drives without a completed checkpoint will restart from the beginning.",
                    ConsoleColor.Cyan);
            }
            else
            {
                display.WriteEvent(
                    $"Resumed {connector.ProviderName} scan: no matching checkpoints were found, so all {drives.Count:N0} drive(s) will start from the beginning.",
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
                var checkpointKey = GetRemoteCheckpointKey(connectorScope, drive);
                if (fullScan)
                {
                    checkpointStore.ClearRemoteDriveToken(checkpointKey);
                }
                var deltaToken = fullScan ? null : checkpointStore.GetRemoteDriveToken(checkpointKey);
                await using var resumeSession = resumeStore.OpenSession($"remote:{checkpointKey}", resume: !fullScan);
                await ScanRemoteDriveAsync(
                    drive,
                    deltaToken,
                    remoteDriveScanner,
                    checkpointStore,
                    checkpointKey,
                    resumeSession,
                    session,
                    scanOptions,
                    display,
                    llmValidator,
                    llmOptions,
                    diagnostics: null,
                    enumerateOnly: false,
                    cancellationToken);
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
        CliFilesystemPerformanceOptions? performanceOptions = null,
        bool kerberos = false,
        IPAddress? dnsServer = null,
        bool fullScan = DefaultFullScan,
        CancellationToken cancellationToken = default,
        bool showBanner = true)
    {
        var effectiveOutputOptions = ResolveOutputOptions(outputOptions, fullScan);
        performanceOptions ??= new CliFilesystemPerformanceOptions();
        var workerCount = performanceOptions.ResolveWorkerCount();
        var queueCapacity = Math.Clamp(workerCount * 32, 512, 4096);
        await using var diagnostics = new CliScanDiagnostics(
            workerCount,
            queueCapacity,
            performanceOptions.MaxReadBytesPerSecond,
            performanceOptions.DiagnosticsOutputPath);
        await using var display = new CliProgressDisplay(target.Mode == FileSystemScanMode.Folder
            ? $"Local scan of {target.Value}"
            : $"{target.DisplayName} crawl", effectiveOutputOptions, showBanner);

        await using var session = await CliScannerBootstrap.InitializeScannerAsync(rulesPath, Program.CreateHost, cancellationToken);
        var fileScanner = session.Host.Services.GetRequiredService<FileScanner>();
        var standardEnumerator = session.Host.Services.GetRequiredService<StandardFileSystemEnumerator>();
        var resumeStore = session.Host.Services.GetRequiredService<CliResumeStore>();
        var scanOptions = CreateScanOptions(includeBinary, llmOptions, performanceOptions.MaxReadBytesPerSecond, diagnostics.Scanner);
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
            if (!enumerateOnly)
            {
                llmValidator = await CliLlmValidationSupport.CreateValidatorAsync(session.Host.Services, llmOptions, display, cancellationToken);
            }
            display.SetPhase(enumerateOnly ? "Enumerating local filesystem" : "Scanning local filesystem");
            await using var resumeSession = enumerateOnly
                ? null
                : OpenFilesystemResumeSession(
                    resumeStore,
                    target,
                    target.Value,
                    session,
                    includeBinary,
                    llmOptions,
                    credential,
                    kerberos,
                    dnsServer,
                    fullScan,
                    display);
            await ScanFileSystemRootAsync(
                target.Value,
                standardEnumerator,
                fileScanner,
                session.Plan,
                scanOptions,
                display,
                llmValidator,
                llmOptions,
                diagnostics,
                enumerateOnly,
                resumeSession,
                cancellationToken);
            display.Complete(enumerateOnly ? "Local enumeration complete" : "Local scan complete");
            return display.ErrorCount > 0 ? CliExitCodes.Partial : CliExitCodes.Success;
        }

        if (!OperatingSystem.IsWindows() && (credential?.UsesNtHash != true || target.Mode == FileSystemScanMode.Domain))
        {
            display.WriteEvent(
                "Error: domain discovery and password/Kerberos SMB authentication are currently supported only on Windows. Cross-platform network scans require --nt-hash.",
                ConsoleColor.Red);
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
                dnsServer,
                fullScan,
                diagnostics,
                cancellationToken);
        }

        if (kerberos)
        {
            display.WriteEvent("Error: Kerberos cannot authenticate a local machine account. Use an Active Directory identity or remove --kerberos.", ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Network crawl failed");
            return CliExitCodes.Failed;
        }

        if (!OperatingSystem.IsWindows())
        {
            display.WriteEvent("Error: this SMB authentication path requires Windows.", ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Network crawl failed");
            return CliExitCodes.Failed;
        }

        return await RunWindowsDiscoveryScanAsync(target, credential, enumerateOnly, session, display, scanOptions, fileScanner, standardEnumerator, llmValidator, llmOptions, resumeStore, includeBinary, kerberos, dnsServer, fullScan, diagnostics, cancellationToken);
    }

    internal static bool ShouldUseKerberosPreferredAuthentication(CliWindowsCredential? credential) =>
        credential?.UsesNtHash == true || credential?.IsLocalMachineAccount != true;

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
        IPAddress? dnsServer,
        bool fullScan,
        CliScanDiagnostics diagnostics,
        CancellationToken cancellationToken)
    {
        var kerberosService = session.Host.Services.GetRequiredService<SmbKerberosService>();
        var usesNtHash = credential?.UsesNtHash == true;
        display.SetPhase($"Discovering {target.DisplayName.ToLowerInvariant()} SMB shares");
        display.WriteEvent(
            usesNtHash
                ? "Authentication mode: explicit NTLMv2 pass-the-hash; Kerberos is disabled."
                : allowNtlmFallback
                ? "Authentication mode: Kerberos preferred; NTLM is attempted only per host when Kerberos is unavailable."
                : "Authentication mode: strict Kerberos (cifs SPN); NTLM fallback is disabled.",
            ConsoleColor.Cyan);
        if (dnsServer != null)
        {
            display.WriteEvent($"DNS mode: direct queries to {dnsServer}; local DNS and local fallback are disabled.", ConsoleColor.Cyan);
        }

        SmbKerberosDiscoveryResult discovery;
        try
        {
            discovery = await kerberosService.DiscoverDrivesAsync(
                target,
                credential,
                allowNtlmFallback,
                dnsServer,
                path => IgnoreRuleEvaluator.ShouldPruneDirectory(path, session.IgnoreRules),
                display.SetCurrentPath,
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            display.WriteEvent($"Error: failed to discover SMB shares: {GetErrorMessage(ex)}", ConsoleColor.Red);
            display.IncrementErrors();
            display.Complete("Network crawl failed");
            return CliExitCodes.Failed;
        }

        foreach (var warning in discovery.Warnings)
        {
            display.WriteEvent($"Warning: {warning}", ConsoleColor.Yellow);
        }


        if (!usesNtHash && discovery.NtlmFallbackHostCount > 0)
        {
            display.WriteEvent(
                $"Authentication summary: {discovery.NtlmFallbackHostCount:N0} host(s) required explicit NTLM fallback.",
                ConsoleColor.Yellow);
        }

        if (discovery.Drives.Count == 0)
        {
            display.WriteEvent(
                usesNtHash
                    ? "Warning: no readable SMB shares were discovered with the supplied NT hash."
                    : allowNtlmFallback
                    ? "Warning: no readable SMB shares were discovered through Kerberos or NTLM fallback."
                    : "Warning: no readable SMB shares were discovered through strict Kerberos authentication.",
                ConsoleColor.Yellow);
            if (usesNtHash && discovery.AuthenticationFailureCount > 0)
            {
                display.IncrementErrors();
                display.Complete("Network crawl failed");
                return CliExitCodes.Failed;
            }

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

        if (!enumerateOnly)
        {
            llmValidator ??= await CliLlmValidationSupport.CreateValidatorAsync(session.Host.Services, llmOptions, display, cancellationToken);
        }
        var remoteDriveScanner = session.Host.Services.GetRequiredService<RemoteDriveScanner>();
        var checkpointStore = session.Host.Services.GetRequiredService<CliCheckpointStore>();
        var resumeStore = session.Host.Services.GetRequiredService<CliResumeStore>();
        display.SetTotalDrives(discovery.Drives.Count);
        display.SetPhase(enumerateOnly ? "Enumerating SMB shares" : "Scanning SMB shares");

        foreach (var drive in discovery.Drives)
        {
            cancellationToken.ThrowIfCancellationRequested();
            display.SetCurrentDrive(drive.Name);
            display.ClearCurrentPath();
            try
            {
                var filesystemScope = CliResumeIdentity.CreateFilesystemScope(
                    target,
                    drive.WebUrl,
                    session.RuleFingerprint,
                    scanOptions.EnableBinaryDocuments,
                    llmOptions,
                    credential,
                    strictKerberos: !allowNtlmFallback,
                    dnsServer);
                var checkpointKey = $"filesystem-smb:{filesystemScope}:{drive.ConnectionId}";
                if (fullScan)
                {
                    checkpointStore.ClearRemoteDriveToken(checkpointKey);
                }
                var deltaToken = fullScan ? null : checkpointStore.GetRemoteDriveToken(checkpointKey);
                await using var resumeSession = resumeStore.OpenSession(checkpointKey, resume: !fullScan);
                await ScanRemoteDriveAsync(
                    drive,
                    deltaToken,
                    remoteDriveScanner,
                    checkpointStore,
                    checkpointKey,
                    resumeSession,
                    session,
                    scanOptions,
                    display,
                    llmValidator,
                    llmOptions,
                    diagnostics,
                    enumerateOnly,
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

        display.Complete(enumerateOnly ? "Network enumeration complete" : "Network crawl complete");
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
        CliResumeStore resumeStore,
        bool includeBinary,
        bool strictKerberos,
        IPAddress? dnsServer,
        bool fullScan,
        CliScanDiagnostics diagnostics,
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
            if (dnsServer != null)
            {
                display.WriteEvent($"DNS mode: direct queries to {dnsServer}; local DNS and local fallback are disabled.", ConsoleColor.Cyan);
            }

            IReadOnlyList<string> roots;
            try
            {
                roots = target.Mode == FileSystemScanMode.Domain && credential?.IsLocalMachineAccount == true
                    ? await DiscoverDomainRootsWithLocalCredentialAsync(smbDiscovery, impersonationSession, display, dnsServer, cancellationToken)
                    : await impersonationSession.RunAsync(() => smbDiscovery.DiscoverRootsAsync(target, credential, dnsServer, cancellationToken));
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

            if (!enumerateOnly)
            {
                llmValidator ??= await CliLlmValidationSupport.CreateValidatorAsync(session.Host.Services, llmOptions, display, cancellationToken);
            }
            display.SetTotalDrives(roots.Count);
            display.SetPhase(enumerateOnly ? "Enumerating SMB shares" : "Scanning SMB shares");

            foreach (var root in roots)
            {
                cancellationToken.ThrowIfCancellationRequested();
                display.SetCurrentDrive(root);
                display.ClearCurrentPath();

                try
                {
                    await using var resumeSession = enumerateOnly
                        ? null
                        : OpenFilesystemResumeSession(
                            resumeStore,
                            target,
                            root,
                            session,
                            includeBinary,
                            llmOptions,
                            credential,
                            strictKerberos,
                            dnsServer,
                            fullScan,
                            display);
                    await impersonationSession.RunAsync(() => ScanFileSystemRootAsync(
                        root,
                        standardEnumerator,
                        fileScanner,
                        session.Plan,
                        scanOptions,
                        display,
                        llmValidator,
                        llmOptions,
                        diagnostics,
                        enumerateOnly,
                        resumeSession,
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

            display.Complete(enumerateOnly ? "Network enumeration complete" : "Network crawl complete");
            return display.ErrorCount > 0 ? CliExitCodes.Partial : CliExitCodes.Success;
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task<IReadOnlyList<string>> DiscoverDomainRootsWithLocalCredentialAsync(
        SmbDiscoveryService smbDiscovery,
        WindowsImpersonationSession impersonationSession,
        CliProgressDisplay display,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        display.WriteEvent("Info: using the current Windows identity for AD computer discovery and the supplied local credentials for SMB access.", ConsoleColor.Cyan);
        var hosts = await smbDiscovery.EnumerateDomainHostsForScanAsync(
            credential: null,
            strictKerberos: false,
            dnsServer,
            cancellationToken).ConfigureAwait(false);
        return await impersonationSession.RunAsync(() => smbDiscovery.DiscoverRootsForHostsAsync(hosts, dnsServer, cancellationToken));
    }

    private static async Task ScanRemoteDriveAsync(
        IRemoteDrive drive,
        string? deltaToken,
        RemoteDriveScanner remoteDriveScanner,
        CliCheckpointStore checkpointStore,
        string checkpointKey,
        CliResumeSession resumeSession,
        CliScannerSession session,
        Stratus.Sift.Scanner.Models.ScanOptions scanOptions,
        CliProgressDisplay display,
        Stratus.Sift.Core.Validation.ILlmClassifierValidator? llmValidator,
        CliLlmOptions? llmOptions,
        CliScanDiagnostics? diagnostics,
        bool enumerateOnly,
        CancellationToken cancellationToken)
    {
        var scanCompleted = true;
        var finalTokenWritten = false;
        var sourceCheckpointAge = Stopwatch.StartNew();
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
            onCheckpointToken: async token =>
            {
                if (enumerateOnly || sourceCheckpointAge.Elapsed < TimeSpan.FromSeconds(30)) return;
                await display.FlushOutputCheckpointAsync(cancellationToken);
                SetDeltaToken(checkpointStore, checkpointKey, token);
                await resumeSession.ClearAsync(cancellationToken);
                sourceCheckpointAge.Restart();
            },
            onNewDeltaToken: async token =>
            {
                if (enumerateOnly) return;
                await display.FlushOutputCheckpointAsync(cancellationToken);
                SetDeltaToken(checkpointStore, checkpointKey, token);
                finalTokenWritten = !string.IsNullOrWhiteSpace(token);
                await resumeSession.ClearAsync(cancellationToken);
                sourceCheckpointAge.Restart();
            },
            onFilesDiscovered: count =>
            {
                display.AddFilesDiscovered(count);
                if (diagnostics != null)
                {
                    for (var index = 0; index < count; index++) diagnostics.RecordCandidate(directory: false);
                }
            },
            onFilesScanned: enumerateOnly ? null : display.AddFilesScanned,
            onQueueDepth: diagnostics is null ? null : depth => diagnostics.ObserveQueueDepth(depth),
            onCurrentPath: display.SetCurrentPath,
            ensureScanActive: null,
            cancellationToken: cancellationToken,
            executionOptions: diagnostics is null
                ? null
                : new RemoteDriveScanExecutionOptions(
                    diagnostics.Workers,
                    diagnostics.QueueCapacity,
                    enumerateOnly),
            shouldSkipItem: enumerateOnly
                ? null
                : item => resumeSession.ContainsRemote(drive.ConnectionId, item.Id, item.Path, item.Size),
            onItemProcessed: enumerateOnly
                ? null
                : (item, token) => resumeSession.MarkRemoteCompletedAsync(
                    drive.ConnectionId,
                    item.Id,
                    item.Path,
                    item.Size,
                    display.FlushOutputCheckpointAsync,
                    token),
            onScanIncomplete: () => scanCompleted = false);

        if (!enumerateOnly)
        {
            await resumeSession.CommitAsync(display.FlushOutputCheckpointAsync, cancellationToken);
            if (scanCompleted)
            {
                if (finalTokenWritten)
                {
                    await resumeSession.ClearAsync(cancellationToken);
                }
                else
                {
                    // Sources without an authoritative final delta token (for example SMB)
                    // retain their item journal so a later --resume can skip unchanged content.
                    checkpointStore.ClearRemoteDriveToken(checkpointKey);
                }
            }
        }
    }

    private static string? GetDeltaToken(CliCheckpointStore checkpointStore, string connectorScope, IRemoteDrive drive)
    {
        return checkpointStore.GetRemoteDriveToken(GetRemoteCheckpointKey(connectorScope, drive));
    }

    private static string GetRemoteCheckpointKey(string connectorScope, IRemoteDrive drive)
        => $"{connectorScope}:{drive.ConnectionId}";

    private static void SetDeltaToken(CliCheckpointStore checkpointStore, string checkpointKey, string token)
    {
        if (!string.IsNullOrWhiteSpace(token))
        {
            checkpointStore.SetRemoteDriveToken(checkpointKey, token);
        }
    }

    private static CliResumeSession OpenFilesystemResumeSession(
        CliResumeStore resumeStore,
        FileSystemScanTarget target,
        string rootPath,
        CliScannerSession session,
        bool includeBinary,
        CliLlmOptions? llmOptions,
        CliWindowsCredential? credential,
        bool strictKerberos,
        IPAddress? dnsServer,
        bool fullScan,
        CliProgressDisplay display)
    {
        var scope = CliResumeIdentity.CreateFilesystemScope(
            target,
            rootPath,
            session.RuleFingerprint,
            includeBinary,
            llmOptions,
            credential,
            strictKerberos,
            dnsServer);
        var resumeSession = resumeStore.OpenSession(scope, resume: !fullScan);
        if (!fullScan && resumeSession.CompletedCount > 0)
        {
            display.WriteEvent(
                $"Resume: {resumeSession.CompletedCount:N0} unchanged item(s) already have durable results and will be skipped.",
                ConsoleColor.Cyan);
        }

        return resumeSession;
    }

    private static async Task ScanFileSystemRootAsync(
        string rootPath,
        StandardFileSystemEnumerator standardEnumerator,
        FileScanner fileScanner,
        ScannerExecutionPlan plan,
        Stratus.Sift.Scanner.Models.ScanOptions scanOptions,
        CliProgressDisplay display,
        Stratus.Sift.Core.Validation.ILlmClassifierValidator? llmValidator,
        CliLlmOptions? llmOptions,
        CliScanDiagnostics diagnostics,
        bool enumerateOnly,
        CliResumeSession? resumeSession,
        CancellationToken cancellationToken)
    {
        PathFilter? directoryFilter = plan.IgnoreRules.Count == 0
            ? null
            : path => IgnoreRuleEvaluator.ShouldPruneDirectory(path.ToString(), plan.IgnoreRules);

        var channel = Channel.CreateBounded<FileScanCandidate>(new BoundedChannelOptions(diagnostics.QueueCapacity)
        {
            SingleWriter = true,
            SingleReader = false,
            FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false
        });

        var producer = Task.Run(async () =>
        {
            var enumerationStarted = diagnostics.BeginEnumeration();
            Exception? failure = null;
            try
            {
                var pendingFiles = 0;
                var pendingDirectories = 0;
                var pendingQueueSamples = 0;
                foreach (var entry in standardEnumerator.EnumerateScanCandidates(rootPath, directoryFilter))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!enumerateOnly && resumeSession?.Contains(entry) == true)
                    {
                        continue;
                    }
                    if (entry.IsDirectory) pendingDirectories++;
                    else pendingFiles++;
                    await channel.Writer.WriteAsync(entry, cancellationToken);
                    if (++pendingQueueSamples >= 128)
                    {
                        diagnostics.RecordCandidates(pendingFiles, pendingDirectories);
                        diagnostics.ObserveQueueDepth(channel.Reader.Count);
                        pendingFiles = 0;
                        pendingDirectories = 0;
                        pendingQueueSamples = 0;
                    }
                }

                diagnostics.RecordCandidates(pendingFiles, pendingDirectories);
                diagnostics.ObserveQueueDepth(channel.Reader.Count);
            }
            catch (Exception exception)
            {
                failure = exception;
                throw;
            }
            finally
            {
                diagnostics.CompleteEnumeration(enumerationStarted);
                channel.Writer.TryComplete(failure);
            }
        }, cancellationToken);

        var consumers = Enumerable.Range(0, diagnostics.Workers)
            .Select(_ => ConsumeFileSystemCandidatesAsync(
                channel.Reader,
                fileScanner,
                plan,
                scanOptions,
                display,
                llmValidator,
                llmOptions,
                enumerateOnly,
                resumeSession,
                display.FlushOutputCheckpointAsync,
                cancellationToken))
            .ToArray();

        await Task.WhenAll(consumers.Prepend(producer));
    }

    private static async Task ConsumeFileSystemCandidatesAsync(
        ChannelReader<FileScanCandidate> reader,
        FileScanner fileScanner,
        ScannerExecutionPlan plan,
        Stratus.Sift.Scanner.Models.ScanOptions scanOptions,
        CliProgressDisplay display,
        Stratus.Sift.Core.Validation.ILlmClassifierValidator? llmValidator,
        CliLlmOptions? llmOptions,
        bool enumerateOnly,
        CliResumeSession? resumeSession,
        Func<CancellationToken, Task> beforeCheckpoint,
        CancellationToken cancellationToken)
    {
        var pendingDiscovered = 0;
        var pendingScanned = 0;
        var lastProgressFlush = Environment.TickCount64;

        try
        {
            await foreach (var entry in reader.ReadAllAsync(cancellationToken))
            {
                if (!entry.IsDirectory)
                {
                    pendingDiscovered++;
                }

                if (!enumerateOnly)
                {
                    var completed = false;
                    try
                    {
                        var scanPath = entry.IsDirectory ? EnsureDirectoryMetadataPath(entry.Path) : entry.Path;
                        var result = await fileScanner.ScanFileWithResultAsync(
                            scanPath,
                            plan,
                            scanOptions,
                            exposure: "Unknown",
                            owner: "Unknown",
                            aclEntries: null,
                            fileSize: entry.Size,
                            ext: Path.GetExtension(entry.Path),
                            name: entry.Name,
                            cancellationToken: cancellationToken);

                        var findings = result.Issues as List<ScanFinding> ?? result.Issues.ToList();
                        var validatedFindings = await ValidateFindingsAsync(findings, llmValidator, llmOptions, cancellationToken);
                        ReportFindings(display, validatedFindings, entry);
                        completed = true;
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        display.IncrementErrors();
                        display.WriteEvent($"Warning: failed to scan {entry.Path}: {GetErrorMessage(ex)}", ConsoleColor.Yellow);
                    }

                    if (completed && resumeSession != null)
                    {
                        await resumeSession.MarkCompletedAsync(entry, beforeCheckpoint, cancellationToken);
                    }
                }

                if (!entry.IsDirectory && !enumerateOnly)
                {
                    pendingScanned++;
                }

                var now = Environment.TickCount64;
                if (pendingDiscovered >= 128 || now - lastProgressFlush >= 250)
                {
                    FlushProgress(display, ref pendingDiscovered, ref pendingScanned);
                    lastProgressFlush = now;
                }
            }
        }
        finally
        {
            FlushProgress(display, ref pendingDiscovered, ref pendingScanned);
        }

        if (!enumerateOnly && resumeSession != null)
        {
            await resumeSession.CommitAsync(beforeCheckpoint, cancellationToken);
        }
    }

    private static void FlushProgress(CliProgressDisplay display, ref int discovered, ref int scanned)
    {
        if (discovered > 0) display.AddFilesDiscovered(discovered);
        if (scanned > 0) display.AddFilesScanned(scanned);
        discovered = 0;
        scanned = 0;
    }

    private static void ReportFindings(CliProgressDisplay display, IReadOnlyCollection<ScanFinding> findings, FileScanCandidate entry)
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
            Comment: null);

        foreach (var finding in findings)
        {
            display.WriteFinding(finding, finding.ResourcePath, context);
        }
    }

    private static Stratus.Sift.Scanner.Models.ScanOptions CreateScanOptions(
        bool includeBinary,
        CliLlmOptions? llmOptions,
        long maxReadBytesPerSecond = 0,
        ScanDiagnostics? diagnostics = null)
    {
        return new Stratus.Sift.Scanner.Models.ScanOptions
        {
            EnableBinaryDocuments = includeBinary,
            EnableZipArchives = true,
            EnableLlmValidation = llmOptions?.Enabled == true,
            OllamaUrl = llmOptions?.OllamaUrl ?? "http://localhost:11434",
            OllamaModel = llmOptions?.OllamaModel ?? string.Empty,
            LlmTimeoutSeconds = llmOptions?.TimeoutSeconds ?? 20,
            MaxDiskReadBytesPerSecond = maxReadBytesPerSecond,
            Diagnostics = diagnostics
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
