using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Client.Authentication;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Core.Enums;
using FileAttributes = SMBLibrary.FileAttributes;

namespace Stratus.Sift.Cli;

internal sealed class SmbKerberosService(SmbDiscoveryService discoveryService, CliDnsResolver dnsResolver, DomainControllerLocator controllerLocator)
{
    private const int HostParallelism = 16;
    internal const int ResponseTimeoutMs = 30_000;
    private static readonly TimeSpan TcpConnectTimeout = TimeSpan.FromSeconds(10);

    internal async Task<SmbKerberosDiscoveryResult> DiscoverDrivesAsync(
        FileSystemScanTarget target,
        CliWindowsCredential? credential,
        bool allowNtlmFallback,
        IPAddress? dnsServer,
        Func<string, bool>? shouldPruneDirectory,
        Action<string>? onCurrentPath,
        CancellationToken cancellationToken,
        CliDiscoveryProgress? progress = null)
    {
        var hostTargets = await GetHostTargetsAsync(
            target,
            credential,
            strictKerberos: !allowNtlmFallback,
            dnsServer,
            cancellationToken, progress).ConfigureAwait(false);
        progress?.FindingShares(hostTargets.Count);
        var kdcLookups = OperatingSystem.IsWindows()
            ? null
            : new ConcurrentDictionary<KdcLookupKey, Lazy<Task<string?>>>();
        var drives = new ConcurrentBag<IRemoteDrive>();
        var warnings = new ConcurrentBag<string>();
        var ntlmFallbackHosts = 0;
        var authenticationFailures = 0;
        var authenticatedHosts = 0;
        var timedOutHosts = 0;

        await Parallel.ForEachAsync(
            hostTargets,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = HostParallelism,
                CancellationToken = cancellationToken
            },
            async (hostTarget, token) =>
            {
                progress?.ServerStarted();
                var failed = false;
                try
                {
                    var connection = await ResolveConnectionAsync(hostTarget.Host, credential, dnsServer, token, kdcLookups);
                    await CheckTcpConnectionAsync(connection.Address, token).ConfigureAwait(false);
                    var result = await SmbHostOperation.RunAsync(
                        operationToken => DiscoverHostDrives(
                            connection, hostTarget, credential, allowNtlmFallback,
                            shouldPruneDirectory, onCurrentPath, operationToken),
                        $"SMB discovery for {hostTarget.Host}", token).ConfigureAwait(false);

                    foreach (var drive in result.Drives)
                    {
                        drives.Add(drive);
                    }
                    foreach (var warning in result.Warnings)
                    {
                        warnings.Add(warning);
                        progress?.Warning(warning);
                    }
                    progress?.SharesListed(result.SharesListed);
                    progress?.SharesReadable(result.Drives.Count);
                    if (result.Authenticated && credential?.UsesNtHash == true)
                    {
                        Interlocked.Increment(ref authenticatedHosts);
                    }
                    if (result.UsedNtlmFallback) Interlocked.Increment(ref ntlmFallbackHosts);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    failed = true;
                    if (ex is TimeoutException) Interlocked.Increment(ref timedOutHosts);
                    if (ex is SmbAuthenticationException)
                    {
                        Interlocked.Increment(ref authenticationFailures);
                    }

                    var warning = $"{hostTarget.Host}: {ex.Message}";
                    warnings.Add(warning);
                    progress?.Warning(warning);
                }
                finally { progress?.ServerCompleted(failed); }
            });

        return new SmbKerberosDiscoveryResult(
            drives.OrderBy(drive => drive.Name, StringComparer.OrdinalIgnoreCase).ToArray(),
            warnings.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray(),
            ntlmFallbackHosts,
            authenticationFailures,
            hostTargets.Count,
            authenticatedHosts,
            timedOutHosts);
    }

    private static HostDiscoveryResult DiscoverHostDrives(
        SmbKerberosConnection connection,
        SmbHostTarget hostTarget,
        CliWindowsCredential? credential,
        bool allowNtlmFallback,
        Func<string, bool>? shouldPruneDirectory,
        Action<string>? onCurrentPath,
        CancellationToken cancellationToken)
    {
        var result = new HostDiscoveryResult();
        if (credential?.UsesNtHash == true ||
            (!OperatingSystem.IsWindows() && credential?.IsLocalMachineAccount == true))
        {
            DiscoverSharesOnHost(connection with { AuthenticationProtocol = SmbAuthenticationProtocol.Ntlm },
                hostTarget, result, shouldPruneDirectory, onCurrentPath, cancellationToken);
            return result;
        }

        try
        {
            if (!connection.IsKerberosReady)
            {
                throw new InvalidOperationException(
                    "Kerberos requires the target's DNS hostname for its cifs service principal, but the target could not be mapped to one.");
            }
            DiscoverSharesOnHost(connection, hostTarget, result, shouldPruneDirectory, onCurrentPath, cancellationToken);
        }
        catch (Exception kerberosException) when (allowNtlmFallback && ShouldFallbackToNtlm(kerberosException))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                DiscoverSharesOnHost(connection with { AuthenticationProtocol = SmbAuthenticationProtocol.Ntlm },
                    hostTarget, result, shouldPruneDirectory, onCurrentPath, cancellationToken);
                result.UsedNtlmFallback = true;
                result.Warnings.Add($"{hostTarget.Host}: Kerberos was unavailable ({kerberosException.Message}) Using explicit NTLM fallback.");
            }
            catch (Exception ntlmException)
            {
                throw new InvalidOperationException(
                    $"Kerberos failed ({kerberosException.Message}) NTLM fallback also failed ({ntlmException.Message})",
                    ntlmException);
            }
        }
        return result;
    }

    private static void DiscoverSharesOnHost(
        SmbKerberosConnection connection,
        SmbHostTarget hostTarget,
        HostDiscoveryResult result,
        Func<string, bool>? shouldPruneDirectory,
        Action<string>? onCurrentPath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var session = SmbKerberosSession.Connect(connection);
        cancellationToken.ThrowIfCancellationRequested();
        result.Authenticated = true;
        var shareNames = session.Client.ListShares(out var listStatus);
        cancellationToken.ThrowIfCancellationRequested();
        if (listStatus != NTStatus.STATUS_SUCCESS)
        {
            throw new InvalidOperationException($"share enumeration failed with {FormatStatus(listStatus)}");
        }

        var readableShares = new List<string>();
        var candidateShares = shareNames
            .Where(name => SmbDiscoveryService.IsCandidateShare(name, 0))
            .Where(name => hostTarget.Share is null || name.Equals(hostTarget.Share, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        result.SharesListed += candidateShares.Length;
        foreach (var shareName in candidateShares)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!session.CanReadShare(shareName, out var accessStatus))
            {
                if (hostTarget.Share != null)
                {
                    var warning = $"{connection.DisplayHost}\\{shareName}: {connection.AuthenticationProtocol} authentication succeeded, but the share is not readable ({FormatStatus(accessStatus)}).";
                    result.Warnings.Add(warning);
                }

                continue;
            }

            readableShares.Add(shareName);
        }

        var selectedShares = hostTarget.Share is null
            ? SmbDiscoveryService.SelectSharesForCoverage(readableShares)
            : readableShares;
        foreach (var shareName in selectedShares)
        {
            cancellationToken.ThrowIfCancellationRequested();
            result.Drives.Add(new SmbKerberosDrive(connection, shareName, shouldPruneDirectory, onCurrentPath));
        }
    }

    private sealed class HostDiscoveryResult
    {
        internal List<IRemoteDrive> Drives { get; } = [];
        internal List<string> Warnings { get; } = [];
        internal int SharesListed { get; set; }
        internal bool Authenticated { get; set; }
        internal bool UsedNtlmFallback { get; set; }
    }

    private static async Task CheckTcpConnectionAsync(IPAddress address, CancellationToken cancellationToken)
    {
        using var client = new TcpClient(address.AddressFamily);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TcpConnectTimeout);
        try
        {
            await client.ConnectAsync(address, SMB2Client.DirectTCPPort, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"TCP port 445 did not connect within {TcpConnectTimeout.TotalSeconds:N0} seconds.", ex);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
            throw new TimeoutException($"TCP port 445 did not connect within {TcpConnectTimeout.TotalSeconds:N0} seconds.", ex);
        }
    }

    internal static bool ShouldFallbackToNtlm(Exception exception)
    {
        if (exception is not SmbAuthenticationException authenticationException)
        {
            return exception.Message.Contains("DNS hostname", StringComparison.OrdinalIgnoreCase)
                || exception.Message.Contains("service principal", StringComparison.OrdinalIgnoreCase)
                || exception.Message.Contains("KRB_AP_ERR_SKEW", StringComparison.OrdinalIgnoreCase)
                || exception.Message.Contains("KDC_ERR_S_PRINCIPAL_UNKNOWN", StringComparison.OrdinalIgnoreCase)
                || exception.Message.Contains("Cannot locate SRV record", StringComparison.OrdinalIgnoreCase)
                || exception.Message.Contains("No KDC", StringComparison.OrdinalIgnoreCase);
        }

        if (authenticationException.Status == NTStatus.STATUS_NOT_SUPPORTED)
        {
            return true;
        }

        return authenticationException.SecurityStatus is
            unchecked((int)0x80090302) or // SEC_E_UNSUPPORTED_FUNCTION
            unchecked((int)0x80090303) or // SEC_E_TARGET_UNKNOWN
            unchecked((int)0x80090305) or // SEC_E_SECPKG_NOT_FOUND
            unchecked((int)0x8009030E) or // SEC_E_NO_CREDENTIALS
            unchecked((int)0x80090311);   // SEC_E_NO_AUTHENTICATING_AUTHORITY
    }

    private async Task<IReadOnlyList<SmbHostTarget>> GetHostTargetsAsync(
        FileSystemScanTarget target,
        CliWindowsCredential? credential,
        bool strictKerberos,
        IPAddress? dnsServer,
        CancellationToken cancellationToken,
        CliDiscoveryProgress? progress)
    {
        if (target.Mode == FileSystemScanMode.Domain)
        {
            if (credential?.UsesNtHash == true)
            {
                throw new InvalidOperationException(
                    "Pass-the-hash supports targeted host and subnet SMB scans. Domain-wide discovery uses LDAP, which requires a password, Kerberos ticket, or the current Windows identity.");
            }

            var hosts = await discoveryService.EnumerateDomainHostsForScanAsync(
                target.Value.Equals("current domain", StringComparison.OrdinalIgnoreCase) ? null : target.Value,
                credential,
                strictKerberos,
                dnsServer,
                cancellationToken, progress).ConfigureAwait(false);
            return hosts
                .Select(host => new SmbHostTarget(host, null))
                .ToArray();
        }

        return target.Mode switch
        {
            FileSystemScanMode.Device => [ParseDeviceTarget(target.Value)],
            FileSystemScanMode.Subnet => SmbDiscoveryService.EnumerateSubnetHosts(target.Value)
                .Select(host => new SmbHostTarget(host, null))
                .ToArray(),
            _ => throw new ArgumentException($"Kerberos SMB discovery does not support target mode '{target.Mode}'.")
        };
    }

    private static SmbHostTarget ParseDeviceTarget(string value)
    {
        var normalized = value.Trim();
        if (!normalized.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return new SmbHostTarget(normalized, null);
        }

        var parts = normalized.TrimStart('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length >= 2
            ? new SmbHostTarget(parts[0], parts[1])
            : new SmbHostTarget(parts[0], null);
    }

    internal Task<SmbKerberosConnection> ResolveConnectionAsync(
        string host,
        CliWindowsCredential? credential,
        IPAddress? dnsServer,
        CancellationToken cancellationToken) =>
        ResolveConnectionAsync(host, credential, dnsServer, cancellationToken, null);

    private async Task<SmbKerberosConnection> ResolveConnectionAsync(
        string host,
        CliWindowsCredential? credential,
        IPAddress? dnsServer,
        CancellationToken cancellationToken,
        ConcurrentDictionary<KdcLookupKey, Lazy<Task<string?>>>? kdcLookups)
    {
        var normalizedHost = host.Trim().TrimStart('\\').TrimEnd('.');
        var realm = GetCredentialRealm(credential);
        var resolutionHost = !IPAddress.TryParse(normalizedHost, out _) &&
                             !normalizedHost.Contains('.') &&
                             !string.IsNullOrWhiteSpace(realm) &&
                             realm.Contains('.')
            ? $"{normalizedHost}.{realm}"
            : normalizedHost;
        var addresses = await dnsResolver.ResolveHostAddressesAsync(resolutionHost, dnsServer, cancellationToken).ConfigureAwait(false);
        var address = addresses.FirstOrDefault(candidate => candidate.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            ?? addresses.FirstOrDefault()
            ?? throw new InvalidOperationException("DNS did not return an address.");

        var kerberosHostName = !IPAddress.TryParse(normalizedHost, out _)
            ? resolutionHost
            : await dnsResolver.ResolveHostNameAsync(address, dnsServer, cancellationToken).ConfigureAwait(false) ?? string.Empty;

        SmbTargetNameProbeResult? probeResult = null;

        if (!IsUsableKerberosHostName(kerberosHostName))
        {
            probeResult = await SmbHostOperation.RunAsync(
                _ => TryProbeSmbTarget(address), $"SMB name probe for {address}", cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(probeResult?.DnsHostName))
            {
                kerberosHostName = probeResult.DnsHostName;
            }
        }

        if (!kerberosHostName.Contains('.') && !string.IsNullOrWhiteSpace(realm) && realm.Contains('.'))
        {
            kerberosHostName = $"{kerberosHostName}.{realm}";
        }

        var kerberosReady = IsUsableKerberosHostName(kerberosHostName);
        realm = string.IsNullOrWhiteSpace(realm)
            ? FirstNonEmpty(probeResult?.DnsDomainName, kerberosReady ? InferDnsDomain(kerberosHostName) : null)
            : realm;
        string? kdcHost = null;
        if (!OperatingSystem.IsWindows() && !string.IsNullOrWhiteSpace(realm) && kerberosReady &&
            credential?.UsesNtHash != true && credential?.IsLocalMachineAccount != true)
        {
            var lookup = kdcLookups is null
                ? ResolveKdcHostAsync(realm, dnsServer, cancellationToken)
                : kdcLookups.GetOrAdd(
                    new KdcLookupKey(realm.ToUpperInvariant(), dnsServer),
                    _ => new Lazy<Task<string?>>(() => ResolveKdcHostAsync(realm, dnsServer, cancellationToken))).Value;
            kdcHost = await lookup.ConfigureAwait(false);
        }
        var displayHost = kerberosReady ? kerberosHostName.TrimEnd('.') : normalizedHost;
        return new SmbKerberosConnection(
            address,
            displayHost,
            realm,
            credential,
            SmbAuthenticationProtocol.Kerberos,
            kerberosReady,
            kdcHost);
    }

    private async Task<string?> ResolveKdcHostAsync(string realm, IPAddress? dnsServer, CancellationToken cancellationToken)
    {
        try
        {
            var controller = await controllerLocator.LocateAsync(null, realm, dnsServer, cancellationToken).ConfigureAwait(false);
            return (await dnsResolver.ResolveHostAddressesAsync(controller, dnsServer, cancellationToken)
                .ConfigureAwait(false)).First().ToString();
        }
        catch when (!cancellationToken.IsCancellationRequested)
        {
            // NTLM fallback can still succeed when the realm's SRV records are unavailable.
            return null;
        }
    }

    private static SmbTargetNameProbeResult? TryProbeSmbTarget(IPAddress address)
    {
        var client = new SMB2Client(ResponseTimeoutMs);
        try
        {
            if (!client.Connect(address, SMBTransportType.DirectTCPTransport))
            {
                return null;
            }

            var inner = new NTLMAuthenticationClient(string.Empty, string.Empty, string.Empty, null, AuthenticationMethod.NTLMv2);
            var probe = new SmbTargetNameProbeAuthenticationClient(inner);
            _ = client.Login(probe);
            return new SmbTargetNameProbeResult(probe.RemoteDnsHostName, probe.RemoteDnsDomainName);
        }
        catch
        {
            return null;
        }
        finally
        {
            try { client.Disconnect(); } catch { }
        }
    }

    private static string? GetCredentialRealm(CliWindowsCredential? credential)
    {
        if (!string.IsNullOrWhiteSpace(credential?.Domain) && !credential.IsLocalMachineAccount)
        {
            return credential.Domain.Trim();
        }

        var username = credential?.UserName;
        var separator = username?.LastIndexOf('@') ?? -1;
        return separator > 0 && separator < username!.Length - 1 ? username[(separator + 1)..] : null;
    }

    private static bool IsUsableKerberosHostName(string value) =>
        !string.IsNullOrWhiteSpace(value) && !IPAddress.TryParse(value, out _) && value.Contains('.');

    private static string InferDnsDomain(string hostName)
    {
        var separator = hostName.IndexOf('.');
        return separator > 0 && separator < hostName.Length - 1 ? hostName[(separator + 1)..] : string.Empty;
    }

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

    internal static string FormatStatus(NTStatus status) => $"{status} (0x{(uint)status:X8})";

    internal static Exception CreateFileOpenException(string path, NTStatus status)
    {
        var message = $"Could not open remote file '{path}': {FormatStatus(status)}.";
        return status switch
        {
            NTStatus.STATUS_ACCESS_DENIED => new UnauthorizedAccessException(message),
            NTStatus.STATUS_SHARING_VIOLATION => new RemoteContentUnavailableException(
                message,
                shouldRetry: false,
                isExpected: true),
            _ when SmbTransientRetry.IsTransientStatus(status) => new SmbOperationException(status, message),
            _ => new IOException(message)
        };
    }

    private sealed record SmbHostTarget(string Host, string? Share);

    private readonly record struct KdcLookupKey(string Realm, IPAddress? DnsServer);
}

internal sealed record SmbKerberosDiscoveryResult(
    IReadOnlyList<IRemoteDrive> Drives,
    IReadOnlyList<string> Warnings,
    int NtlmFallbackHostCount,
    int AuthenticationFailureCount,
    int TargetHostCount,
    int AuthenticatedHostCount,
    int TimedOutHostCount = 0);

internal enum SmbAuthenticationProtocol
{
    Kerberos,
    Ntlm
}

internal sealed record SmbKerberosConnection(
    IPAddress Address,
    string KerberosHostName,
    string? Realm,
    CliWindowsCredential? Credential,
    SmbAuthenticationProtocol AuthenticationProtocol,
    bool IsKerberosReady,
    string? KdcHost = null)
{
    internal string DisplayHost => KerberosHostName;
}

internal sealed class SmbKerberosDrive(
    SmbKerberosConnection connection,
    string shareName,
    Func<string, bool>? shouldPruneDirectory,
    Action<string>? onCurrentPath) : IRemoteDrive, IDisposable
{
    private readonly SmbKerberosSessionPool _contentSessions = new(connection, shareName);

    public string Id => $"{connection.KerberosHostName}/{shareName}";
    public string Name => $@"\\{connection.DisplayHost}\{shareName}";
    public string ConnectionId => $"smb-{connection.AuthenticationProtocol.ToString().ToLowerInvariant()}://{connection.KerberosHostName}/{Uri.EscapeDataString(shareName)}";
    public string WebUrl => Name;
    public DatastoreType DriveType => DatastoreType.FileSystem;
    public long? TotalSize => null;
    public long? UsedSize => null;
    internal SmbAuthenticationProtocol AuthenticationProtocol => connection.AuthenticationProtocol;

    public async Task<(IEnumerable<IRemoteFile> Changes, string NewDeltaToken)> GetChangesAsync(
        string? deltaToken,
        CancellationToken cancellationToken = default)
    {
        var changes = new List<IRemoteFile>();
        await ProcessChangesAsync(deltaToken, file =>
        {
            changes.Add(file);
            return Task.CompletedTask;
        }, null, cancellationToken);
        return (changes, string.Empty);
    }

    public async Task<string> ProcessChangesAsync(
        string? deltaToken,
        Func<IRemoteFile, Task> onChange,
        Func<string, Task>? onCheckpoint = null,
        CancellationToken cancellationToken = default)
    {
        using var session = SmbKerberosSession.Connect(connection);
        using var store = session.ConnectShare(shareName);
        var pending = ParseCheckpoint(deltaToken);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { string.Empty };
        if (pending.Count == 0)
        {
            pending.Push(string.Empty);
        }
        else
        {
            foreach (var directory in pending)
            {
                visited.Add(directory);
            }
        }

        var directoriesSinceCheckpoint = 0;
        var lastCheckpointAt = Stopwatch.StartNew();

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = pending.Pop();
            var directoryPath = string.IsNullOrEmpty(directory)
                ? $@"\\{connection.DisplayHost}\{shareName}"
                : $@"\\{connection.DisplayHost}\{shareName}\{directory}";
            onCurrentPath?.Invoke(directoryPath);
            var entries = store.ListDirectory(directory, throwOnFailure: directory.Length == 0);
            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (entry.FileName is "." or "..")
                {
                    continue;
                }

                var relativePath = string.IsNullOrEmpty(directory)
                    ? entry.FileName
                    : $@"{directory}\{entry.FileName}";
                var isDirectory = (entry.FileAttributes & FileAttributes.Directory) != 0;
                var isReparsePoint = (entry.FileAttributes & FileAttributes.ReparsePoint) != 0;
                var item = new SmbKerberosRemoteFile(connection, shareName, relativePath, entry, isDirectory, _contentSessions);
                await onChange(item);

                if (isDirectory
                    && !isReparsePoint
                    && !(shouldPruneDirectory?.Invoke(item.Path) ?? false)
                    && visited.Add(relativePath))
                {
                    pending.Push(relativePath);
                }
            }

            directoriesSinceCheckpoint++;
            if (pending.Count > 0
                && onCheckpoint != null
                && (directoriesSinceCheckpoint >= 64 || lastCheckpointAt.Elapsed >= TimeSpan.FromSeconds(30)))
            {
                await onCheckpoint(CreateCheckpoint(pending));
                directoriesSinceCheckpoint = 0;
                lastCheckpointAt.Restart();
            }
        }

        return string.Empty;
    }

    internal static string CreateCheckpoint(Stack<string> pending)
        => "sift-smb-v2:" + string.Join('.', pending.Select(Encode));

    internal static Stack<string> ParseCheckpoint(string? token)
    {
        const string prefix = "sift-smb-v2:";
        if (string.IsNullOrWhiteSpace(token) || !token.StartsWith(prefix, StringComparison.Ordinal))
        {
            return new Stack<string>();
        }

        var topFirst = token[prefix.Length..]
            .Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Select(Decode)
            .Where(value => value != null)
            .Cast<string>()
            .ToArray();
        return new Stack<string>(topFirst.Reverse());
    }

    private static string Encode(string value)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string? Decode(string value)
    {
        try
        {
            var normalized = value.Replace('-', '+').Replace('_', '/');
            normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
            return Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
        }
        catch (FormatException)
        {
            return null;
        }
    }

    public void Dispose() => _contentSessions.Dispose();
}

internal sealed class SmbKerberosRemoteFile(
    SmbKerberosConnection connection,
    string shareName,
    string relativePath,
    FileDirectoryInformation information,
    bool isDirectory,
    SmbKerberosSessionPool contentSessions) : IRemoteFile
{
    private readonly string _uncPath = $@"\\{connection.DisplayHost}\{shareName}\{relativePath}";

    public string Id => $"{connection.KerberosHostName}/{shareName}/{relativePath}";
    public string Name => information.FileName;
    public string Path => _uncPath;
    public string WebUrl => _uncPath;
    public long? Size => isDirectory ? null : information.EndOfFile;
    public string? ContentType => null;
    public bool IsDeleted => false;
    public bool IsDirectory => isDirectory;
    public bool IsLink => false;
    public bool IsExternal => false;

    public async Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default)
    {
        if (IsDirectory)
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        return await SmbKerberosReadStream.OpenAsync(contentSessions, relativePath, 0, Size, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(start);
        if (end < start)
        {
            throw new ArgumentOutOfRangeException(nameof(end));
        }

        if (IsDirectory)
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var available = Size.HasValue ? Math.Max(0, Math.Min(end, Size.Value - 1) - start + 1) : end - start + 1;
        return await SmbKerberosReadStream.OpenAsync(contentSessions, relativePath, start, available, cancellationToken)
            .ConfigureAwait(false);
    }
}

internal sealed class SmbKerberosSession : IDisposable
{
    private readonly IAuthenticationClient _authentication;
    private bool _disposed;

    private SmbKerberosSession(SMB2Client client, IAuthenticationClient authentication)
    {
        Client = client;
        _authentication = authentication;
    }

    internal SMB2Client Client { get; }

    internal static SmbKerberosSession Connect(SmbKerberosConnection connection)
    {
        var client = new SMB2Client(SmbKerberosService.ResponseTimeoutMs);
        if (!client.Connect(connection.Address, SMBTransportType.DirectTCPTransport))
        {
            try { client.Disconnect(); } catch { }
            throw new SmbConnectionException($"SMB negotiation failed for {connection.Address}:445.");
        }

        var credential = connection.Credential;
        var securityPackage = connection.AuthenticationProtocol == SmbAuthenticationProtocol.Kerberos
            ? "Kerberos"
            : "NTLM";
        var authenticationUserName = credential?.UserName;
        var authenticationDomain = connection.Realm;
        if (credential?.IsLocalMachineAccount == true && connection.AuthenticationProtocol == SmbAuthenticationProtocol.Ntlm)
        {
            authenticationDomain = connection.KerberosHostName.Split('.')[0];
        }
        if (credential != null && connection.AuthenticationProtocol == SmbAuthenticationProtocol.Kerberos
            && credential.UserName.Contains('@', StringComparison.Ordinal))
        {
            authenticationDomain = null;
        }
        else if (credential != null && connection.AuthenticationProtocol == SmbAuthenticationProtocol.Ntlm)
        {
            var upnSeparator = credential.UserName.LastIndexOf('@');
            if (upnSeparator > 0 && upnSeparator < credential.UserName.Length - 1)
            {
                authenticationUserName = credential.UserName[..upnSeparator];
                authenticationDomain = credential.UserName[(upnSeparator + 1)..];
            }
        }

        IAuthenticationClient authentication;
        try
        {
            if (credential?.UsesNtHash == true)
            {
                if (connection.AuthenticationProtocol != SmbAuthenticationProtocol.Ntlm)
                {
                    throw new InvalidOperationException("An NT hash can only be used with explicit NTLM authentication.");
                }

                authentication = new NtlmHashAuthenticationClient(
                    authenticationDomain,
                    authenticationUserName!,
                    credential.NtHash!,
                    $"cifs/{connection.KerberosHostName}",
                    credential.IsLocalMachineAccount);
            }
            else if (!OperatingSystem.IsWindows() && connection.AuthenticationProtocol == SmbAuthenticationProtocol.Ntlm)
            {
                if (credential?.Password is null)
                {
                    throw new InvalidOperationException("NTLM password authentication requires explicit credentials on this platform.");
                }
                if (credential.IsLocalMachineAccount)
                {
                    var ntHash = SMBLibrary.Authentication.NTLM.NTLMCryptography.NTOWFv1(credential.Password);
                    try
                    {
                        authentication = new NtlmHashAuthenticationClient(
                            authenticationDomain, authenticationUserName!, ntHash,
                            $"cifs/{connection.KerberosHostName}", useServerTargetAsDomain: true);
                    }
                    finally
                    {
                        System.Security.Cryptography.CryptographicOperations.ZeroMemory(ntHash);
                    }
                }
                else
                {
                    authentication = new NTLMAuthenticationClient(
                        authenticationDomain ?? string.Empty,
                        authenticationUserName!,
                        credential.Password,
                        $"cifs/{connection.KerberosHostName}",
                        AuthenticationMethod.NTLMv2);
                }
            }
            else if (!OperatingSystem.IsWindows())
            {
                authentication = new PortableKerberosAuthenticationClient(
                    connection.KerberosHostName,
                    connection.Realm,
                    connection.KdcHost,
                    authenticationUserName,
                    credential?.Password);
            }
            else
            {
                authentication = credential == null
                    ? new SspiSmbAuthenticationClient(connection.KerberosHostName, securityPackage)
                    : new SspiSmbAuthenticationClient(
                        connection.KerberosHostName,
                        securityPackage,
                        authenticationDomain,
                        authenticationUserName,
                        credential.Password);
            }
        }
        catch
        {
            try { client.Disconnect(); } catch { }
            throw;
        }

        try
        {
            var status = client.Login(authentication);
            var sspiAuthentication = authentication as SspiSmbAuthenticationClient;
            if (status != NTStatus.STATUS_SUCCESS || sspiAuthentication?.AuthenticationCompleted == false)
            {
                var sspiError = string.IsNullOrWhiteSpace(sspiAuthentication?.LastSecurityError)
                    ? string.Empty
                    : $" SSPI: {sspiAuthentication.LastSecurityError}.";
                var targetName = sspiAuthentication?.TargetName ?? $"cifs/{connection.KerberosHostName}";
                throw new SmbAuthenticationException(
                    securityPackage,
                    status,
                    sspiAuthentication?.LastSecurityStatus,
                    $"explicit {securityPackage} SMB authentication to '{targetName}' failed with {SmbKerberosService.FormatStatus(status)}.{sspiError}");
            }

            return new SmbKerberosSession(client, authentication);
        }
        catch
        {
            (authentication as IDisposable)?.Dispose();
            try { client.Disconnect(); } catch { }
            throw;
        }
    }

    internal bool CanReadShare(string shareName, out NTStatus status)
    {
        ISMBFileStore? store = null;
        object? handle = null;
        try
        {
            store = Client.TreeConnect(shareName, out status);
            if (status != NTStatus.STATUS_SUCCESS || store == null)
            {
                return false;
            }

            status = store.CreateFile(
                out handle,
                out _,
                string.Empty,
                (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE,
                FileAttributes.Directory,
                ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE,
                null);
            return status == NTStatus.STATUS_SUCCESS && handle != null;
        }
        finally
        {
            if (handle != null) try { store?.CloseFile(handle); } catch { }
            try { store?.Disconnect(); } catch { }
        }
    }

    internal SmbKerberosStore ConnectShare(string shareName)
    {
        var store = Client.TreeConnect(shareName, out var status);
        if (status != NTStatus.STATUS_SUCCESS || store == null)
        {
            var message = $"Could not connect to share '{shareName}': {SmbKerberosService.FormatStatus(status)}.";
            throw SmbTransientRetry.IsTransientStatus(status)
                ? new SmbOperationException(status, message)
                : new IOException(message);
        }

        return new SmbKerberosStore(store);
    }

    public void Dispose()
    {
        if (_disposed) return;
        try { Client.Logoff(); } catch { }
        Abort();
    }

    internal void Abort()
    {
        if (_disposed) return;
        try { Client.Disconnect(); } catch { }
        (_authentication as IDisposable)?.Dispose();
        _disposed = true;
    }
}

internal sealed class SmbAuthenticationException(
    string protocol,
    NTStatus status,
    int? securityStatus,
    string message) : InvalidOperationException(message)
{
    internal string Protocol { get; } = protocol;
    internal NTStatus Status { get; } = status;
    internal int? SecurityStatus { get; } = securityStatus;
}

internal sealed class SmbKerberosStore(ISMBFileStore store) : IDisposable
{
    internal ISMBFileStore Inner => store;

    internal IReadOnlyList<FileDirectoryInformation> ListDirectory(string path, bool throwOnFailure)
    {
        object? handle = null;
        try
        {
            var status = store.CreateFile(
                out handle,
                out _,
                path,
                (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE,
                FileAttributes.Directory,
                ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE,
                null);
            if (status != NTStatus.STATUS_SUCCESS || handle == null)
            {
                if (throwOnFailure)
                {
                    throw new InvalidOperationException($"Could not open directory '{path}': {SmbKerberosService.FormatStatus(status)}.");
                }

                return [];
            }

            status = store.QueryDirectory(out var entries, handle, "*", FileInformationClass.FileDirectoryInformation);
            if (status != NTStatus.STATUS_SUCCESS && status != NTStatus.STATUS_NO_MORE_FILES)
            {
                if (throwOnFailure)
                {
                    throw new InvalidOperationException($"Could not enumerate directory '{path}': {SmbKerberosService.FormatStatus(status)}.");
                }

                return [];
            }

            return entries.OfType<FileDirectoryInformation>().ToArray();
        }
        finally
        {
            if (handle != null) try { store.CloseFile(handle); } catch { }
        }
    }

    public void Dispose()
    {
        try { store.Disconnect(); } catch { }
    }
}

internal sealed class SmbConnectionException(string message) : IOException(message);

internal sealed class SmbOperationException(NTStatus status, string message) : IOException(message)
{
    internal NTStatus Status { get; } = status;
}

internal static class SmbTransientRetry
{
    private const int MaxAttempts = 4;

    internal static bool IsTransientStatus(NTStatus status) => status is
        NTStatus.STATUS_INVALID_SMB or
        NTStatus.STATUS_IO_TIMEOUT or
        NTStatus.STATUS_NETWORK_NAME_DELETED or
        NTStatus.STATUS_USER_SESSION_DELETED or
        NTStatus.STATUS_TOO_MANY_SESSIONS or
        NTStatus.STATUS_INSUFF_SERVER_RESOURCES;

    internal static bool IsTransient(Exception exception) => exception switch
    {
        SmbAuthenticationException authentication => authentication.SecurityStatus == null
            && IsTransientStatus(authentication.Status),
        SmbOperationException operation => IsTransientStatus(operation.Status),
        SmbConnectionException => true,
        SocketException => true,
        TimeoutException => true,
        IOException { InnerException: SocketException or TimeoutException } => true,
        _ => false
    };

    internal static async Task<T> RunAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        string description,
        CancellationToken cancellationToken,
        Func<int, TimeSpan>? retryDelay = null)
    {
        for (var attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await operation(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (IsTransient(exception) && !cancellationToken.IsCancellationRequested)
            {
                if (attempt == MaxAttempts)
                {
                    throw new RemoteContentUnavailableException(
                        $"{description} failed after {MaxAttempts} attempts: {exception.Message}",
                        shouldRetry: true,
                        innerException: exception);
                }

                var delay = retryDelay?.Invoke(attempt)
                    ?? TimeSpan.FromMilliseconds(1000 * (1 << (attempt - 1)) + Random.Shared.Next(0, 500));
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}

// SMBLibrary clients and tree connections are used by one file at a time. Reuse
// authenticated sessions across files, with a small cap per share so a fast scan
// does not create dozens of concurrent Kerberos sessions against one server.
internal sealed class SmbKerberosSessionPool(SmbKerberosConnection connection, string shareName) : IDisposable
{
    internal const int MaxSessions = 8;
    private readonly SemaphoreSlim _slots = new(MaxSessions, MaxSessions);
    private readonly Stack<SmbKerberosShareSession> _idle = new();
    private readonly object _sync = new();
    private bool _disposed;

    internal async ValueTask<SmbKerberosShareSession> RentAsync(CancellationToken cancellationToken)
    {
        await _slots.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            while (true)
            {
                SmbKerberosShareSession? idle;
                lock (_sync)
                {
                    ObjectDisposedException.ThrowIf(_disposed, this);
                    idle = _idle.Count > 0 ? _idle.Pop() : null;
                }

                if (idle == null) break;
                if (idle.IsConnected)
                {
                    return idle;
                }

                idle.Abort();
            }

            cancellationToken.ThrowIfCancellationRequested();
            var created = SmbKerberosShareSession.Connect(connection, shareName);
            lock (_sync)
            {
                if (!_disposed) return created;
            }
            created.Abort();
            throw new ObjectDisposedException(nameof(SmbKerberosSessionPool));
        }
        catch
        {
            _slots.Release();
            throw;
        }
    }

    internal void Return(SmbKerberosShareSession session, bool reusable)
    {
        try
        {
            var retained = false;
            lock (_sync)
            {
                if (reusable && !_disposed && session.IsConnected)
                {
                    _idle.Push(session);
                    retained = true;
                }
            }
            if (!retained) session.Abort();
        }
        finally
        {
            _slots.Release();
        }
    }

    public void Dispose()
    {
        SmbKerberosShareSession[] idle;
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
            idle = _idle.ToArray();
            _idle.Clear();
        }
        foreach (var session in idle) session.Dispose();
    }
}

internal sealed class SmbKerberosShareSession : IDisposable
{
    private readonly SmbKerberosSession _session;
    internal SmbKerberosStore Store { get; }
    internal bool IsConnected => _session.Client.IsConnected;

    private SmbKerberosShareSession(SmbKerberosSession session, SmbKerberosStore store)
    {
        _session = session;
        Store = store;
    }

    internal static SmbKerberosShareSession Connect(SmbKerberosConnection connection, string shareName)
    {
        var session = SmbKerberosSession.Connect(connection);
        try
        {
            return new SmbKerberosShareSession(session, session.ConnectShare(shareName));
        }
        catch (Exception exception)
        {
            if (SmbTransientRetry.IsTransient(exception)) session.Abort();
            else session.Dispose();
            throw;
        }
    }

    internal void Abort() => _session.Abort();

    public void Dispose()
    {
        Store.Dispose();
        _session.Dispose();
    }
}

internal sealed class SmbKerberosReadStream : Stream
{
    private readonly SmbKerberosSessionPool _pool;
    private readonly SmbKerberosShareSession _shareSession;
    private readonly object _handle;
    private readonly long? _length;
    private long _remoteOffset;
    private long _position;
    private long? _remaining;
    private bool _disposed;
    private bool _reusable = true;

    private SmbKerberosReadStream(
        SmbKerberosSessionPool pool,
        SmbKerberosShareSession shareSession,
        object handle,
        long start,
        long? length)
    {
        _pool = pool;
        _shareSession = shareSession;
        _handle = handle;
        _remoteOffset = start;
        _length = length;
        _remaining = length;
    }

    internal static Task<SmbKerberosReadStream> OpenAsync(
        SmbKerberosSessionPool pool,
        string path,
        long start,
        long? length,
        CancellationToken cancellationToken)
        => SmbTransientRetry.RunAsync(async token =>
        {
            var shareSession = await pool.RentAsync(token).ConfigureAwait(false);
            object? handle = null;
            try
            {
                token.ThrowIfCancellationRequested();
                var status = shareSession.Store.Inner.CreateFile(
                    out handle,
                    out _,
                    path,
                    AccessMask.GENERIC_READ | AccessMask.SYNCHRONIZE,
                    FileAttributes.Normal,
                    ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete,
                    CreateDisposition.FILE_OPEN,
                    CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SEQUENTIAL_ONLY,
                    null);
                if (status != NTStatus.STATUS_SUCCESS || handle == null)
                {
                    throw SmbKerberosService.CreateFileOpenException(path, status);
                }

                return new SmbKerberosReadStream(pool, shareSession, handle, start, length);
            }
            catch (Exception exception)
            {
                var reusable = !SmbTransientRetry.IsTransient(exception);
                if (reusable && handle != null)
                {
                    try
                    {
                        reusable &= shareSession.Store.Inner.CloseFile(handle) == NTStatus.STATUS_SUCCESS;
                    }
                    catch { reusable = false; }
                }
                pool.Return(shareSession, reusable);
                throw;
            }
        }, $"Opening remote SMB file '{path}'", cancellationToken);

    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _length ?? throw new NotSupportedException();
    public override long Position { get => _position; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.Length == 0 || _remaining == 0)
        {
            return 0;
        }

        var requested = Math.Min(buffer.Length, checked((int)Math.Min(_shareSession.Store.Inner.MaxReadSize, int.MaxValue)));
        if (_remaining.HasValue)
        {
            requested = checked((int)Math.Min(requested, _remaining.Value));
        }

        try
        {
            var status = _shareSession.Store.Inner.ReadFile(out var data, _handle, _remoteOffset, requested);
            if (status == NTStatus.STATUS_END_OF_FILE) return 0;
            if (status != NTStatus.STATUS_SUCCESS)
            {
                throw new SmbOperationException(status, $"Remote SMB read failed: {SmbKerberosService.FormatStatus(status)}.");
            }

            if (data.Length == 0) return 0;
            var read = Math.Min(data.Length, requested);
            data.AsSpan(0, read).CopyTo(buffer);
            _remoteOffset += read;
            _position += read;
            if (_remaining.HasValue) _remaining -= read;
            return read;
        }
        catch (Exception exception) when (SmbTransientRetry.IsTransient(exception))
        {
            _reusable = false;
            throw new RemoteContentUnavailableException(
                $"Remote SMB read failed at offset {_remoteOffset}: {exception.Message}",
                shouldRetry: true,
                innerException: exception);
        }
        catch
        {
            _reusable = false;
            throw;
        }
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Read(buffer.Span));
    }

    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            if (_reusable)
            {
                try
                {
                    if (_shareSession.Store.Inner.CloseFile(_handle) != NTStatus.STATUS_SUCCESS)
                    {
                        _reusable = false;
                    }
                }
                catch { _reusable = false; }
            }
            _pool.Return(_shareSession, _reusable);
        }

        base.Dispose(disposing);
    }
}

internal sealed class SmbTargetNameProbeAuthenticationClient(IAuthenticationClient inner) : IAuthenticationClient
{
    private static readonly byte[] NtlmSignature = Encoding.ASCII.GetBytes("NTLMSSP\0");

    internal string? RemoteDnsHostName { get; private set; }
    internal string? RemoteDnsDomainName { get; private set; }

    public byte[]? InitializeSecurityContext(byte[]? securityBlob)
    {
        if (securityBlob == null)
        {
            RemoteDnsHostName = null;
            RemoteDnsDomainName = null;
        }
        else
        {
            TryParseChallenge(securityBlob);
        }

        return inner.InitializeSecurityContext(securityBlob!);
    }

    public byte[]? GetSessionKey() => inner.GetSessionKey();

    public void ResetSecurityContext(string serverName)
    {
        RemoteDnsHostName = null;
        RemoteDnsDomainName = null;
        inner.ResetSecurityContext(serverName);
    }

    private void TryParseChallenge(byte[] token)
    {
        try
        {
            var ntlmOffset = token.AsSpan().IndexOf(NtlmSignature);
            if (ntlmOffset < 0 || token.Length < ntlmOffset + 48 || BitConverter.ToUInt32(token, ntlmOffset + 8) != 2)
            {
                return;
            }

            var targetInfoLength = BitConverter.ToUInt16(token, ntlmOffset + 40);
            var targetInfoOffset = checked((int)BitConverter.ToUInt32(token, ntlmOffset + 44) + ntlmOffset);
            var end = targetInfoOffset + targetInfoLength;
            if (targetInfoOffset < 0 || end > token.Length)
            {
                return;
            }

            for (var offset = targetInfoOffset; offset + 4 <= end;)
            {
                var id = BitConverter.ToUInt16(token, offset);
                var length = BitConverter.ToUInt16(token, offset + 2);
                offset += 4;
                if (id == 0 || length == 0 || offset + length > end)
                {
                    break;
                }

                if (id == 3)
                {
                    RemoteDnsHostName = Encoding.Unicode.GetString(token, offset, length).TrimEnd('.');
                }
                else if (id == 4)
                {
                    RemoteDnsDomainName = Encoding.Unicode.GetString(token, offset, length).TrimEnd('.');
                }

                offset += length;
            }
        }
        catch
        {
            // The probe is advisory; the strict Kerberos login remains authoritative.
        }
    }
}

internal sealed record SmbTargetNameProbeResult(string? DnsHostName, string? DnsDomainName);
