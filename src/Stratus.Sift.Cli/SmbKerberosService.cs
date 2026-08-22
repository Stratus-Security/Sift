using System.Collections.Concurrent;
using System.Net;
using System.Runtime.Versioning;
using System.Text;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.Client.Authentication;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Enums;
using FileAttributes = SMBLibrary.FileAttributes;

namespace Stratus.Sift.Cli;

internal sealed class SmbKerberosService(SmbDiscoveryService discoveryService)
{
    private const int HostParallelism = 16;
    internal const int ConnectionTimeoutMs = 5_000;

    [SupportedOSPlatform("windows")]
    internal async Task<SmbKerberosDiscoveryResult> DiscoverDrivesAsync(
        FileSystemScanTarget target,
        CliWindowsCredential? credential,
        bool allowNtlmFallback,
        Func<string, bool>? shouldPruneDirectory,
        Action<string>? onCurrentPath,
        CancellationToken cancellationToken)
    {
        if (credential?.IsLocalMachineAccount == true)
        {
            throw new InvalidOperationException(
                "Kerberos requires an Active Directory identity. Qualify the username with --domain <ad-dns-domain> or use user@domain.");
        }

        var hostTargets = GetHostTargets(target, credential);
        var drives = new ConcurrentBag<IRemoteDrive>();
        var warnings = new ConcurrentBag<string>();
        var ntlmFallbackHosts = 0;

        await Parallel.ForEachAsync(
            hostTargets,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = HostParallelism,
                CancellationToken = cancellationToken
            },
            async (hostTarget, token) =>
            {
                try
                {
                    var connection = await ResolveConnectionAsync(hostTarget.Host, credential, token);
                    try
                    {
                        if (!connection.IsKerberosReady)
                        {
                            throw new InvalidOperationException(
                                "Kerberos requires the target's DNS hostname for its cifs service principal, but the target could not be mapped to one.");
                        }

                        DiscoverHostDrives(connection, hostTarget, drives, warnings, shouldPruneDirectory, onCurrentPath, token);
                    }
                    catch (Exception kerberosException) when (allowNtlmFallback && ShouldFallbackToNtlm(kerberosException))
                    {
                        var ntlmConnection = connection with { AuthenticationProtocol = SmbAuthenticationProtocol.Ntlm };
                        try
                        {
                            DiscoverHostDrives(ntlmConnection, hostTarget, drives, warnings, shouldPruneDirectory, onCurrentPath, token);
                            Interlocked.Increment(ref ntlmFallbackHosts);
                            warnings.Add($"{hostTarget.Host}: Kerberos was unavailable ({kerberosException.Message}) Using explicit NTLM fallback.");
                        }
                        catch (Exception ntlmException)
                        {
                            throw new InvalidOperationException(
                                $"Kerberos failed ({kerberosException.Message}) NTLM fallback also failed ({ntlmException.Message})",
                                ntlmException);
                        }
                    }
                }
                catch (Exception ex)
                {
                    warnings.Add($"{hostTarget.Host}: {ex.Message}");
                }
            });

        return new SmbKerberosDiscoveryResult(
            drives.OrderBy(drive => drive.Name, StringComparer.OrdinalIgnoreCase).ToArray(),
            warnings.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray(),
            ntlmFallbackHosts);
    }

    private static void DiscoverHostDrives(
        SmbKerberosConnection connection,
        SmbHostTarget hostTarget,
        ConcurrentBag<IRemoteDrive> drives,
        ConcurrentBag<string> warnings,
        Func<string, bool>? shouldPruneDirectory,
        Action<string>? onCurrentPath,
        CancellationToken cancellationToken)
    {
        using var session = SmbKerberosSession.Connect(connection);
        var shareNames = session.Client.ListShares(out var listStatus);
        if (listStatus != NTStatus.STATUS_SUCCESS)
        {
            throw new InvalidOperationException($"share enumeration failed with {FormatStatus(listStatus)}");
        }

        foreach (var shareName in shareNames
                     .Where(name => SmbDiscoveryService.IsCandidateShare(name, 0))
                     .Where(name => hostTarget.Share is null || name.Equals(hostTarget.Share, StringComparison.OrdinalIgnoreCase))
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!session.CanReadShare(shareName, out var accessStatus))
            {
                if (hostTarget.Share != null)
                {
                    warnings.Add($"{connection.DisplayHost}\\{shareName}: {connection.AuthenticationProtocol} authentication succeeded, but the share is not readable ({FormatStatus(accessStatus)}).");
                }

                continue;
            }

            drives.Add(new SmbKerberosDrive(connection, shareName, shouldPruneDirectory, onCurrentPath));
        }
    }

    internal static bool ShouldFallbackToNtlm(Exception exception)
    {
        if (exception is not SmbAuthenticationException authenticationException)
        {
            return exception.Message.Contains("DNS hostname", StringComparison.OrdinalIgnoreCase)
                || exception.Message.Contains("service principal", StringComparison.OrdinalIgnoreCase);
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

    [SupportedOSPlatform("windows")]
    private IReadOnlyList<SmbHostTarget> GetHostTargets(FileSystemScanTarget target, CliWindowsCredential? credential)
    {
        return target.Mode switch
        {
            FileSystemScanMode.Device => [ParseDeviceTarget(target.Value)],
            FileSystemScanMode.Subnet => SmbDiscoveryService.EnumerateSubnetHosts(target.Value)
                .Select(host => new SmbHostTarget(host, null))
                .ToArray(),
            FileSystemScanMode.Domain => discoveryService
                .EnumerateDomainHostsForScan(
                    target.Value.Equals("current domain", StringComparison.OrdinalIgnoreCase) ? null : target.Value,
                    credential)
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

    internal static async Task<SmbKerberosConnection> ResolveConnectionAsync(
        string host,
        CliWindowsCredential? credential,
        CancellationToken cancellationToken)
    {
        var normalizedHost = host.Trim().TrimStart('\\').TrimEnd('.');
        var addresses = await Dns.GetHostAddressesAsync(normalizedHost, cancellationToken);
        var address = addresses.FirstOrDefault(candidate => candidate.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            ?? addresses.FirstOrDefault()
            ?? throw new InvalidOperationException("DNS did not return an address.");

        var realm = GetCredentialRealm(credential);
        var kerberosHostName = !IPAddress.TryParse(normalizedHost, out _)
            ? normalizedHost
            : await TryReverseLookupAsync(address, cancellationToken) ?? string.Empty;

        SmbTargetNameProbeResult? probeResult = null;

        if (!IsUsableKerberosHostName(kerberosHostName))
        {
            probeResult = TryProbeSmbTarget(address);
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
        var displayHost = kerberosReady ? kerberosHostName.TrimEnd('.') : normalizedHost;
        return new SmbKerberosConnection(
            address,
            displayHost,
            realm,
            credential,
            SmbAuthenticationProtocol.Kerberos,
            kerberosReady);
    }

    private static async Task<string?> TryReverseLookupAsync(IPAddress address, CancellationToken cancellationToken)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(address).WaitAsync(cancellationToken);
            return string.IsNullOrWhiteSpace(entry.HostName) ? null : entry.HostName.TrimEnd('.');
        }
        catch
        {
            return null;
        }
    }

    private static SmbTargetNameProbeResult? TryProbeSmbTarget(IPAddress address)
    {
        var client = new SMB2Client(ConnectionTimeoutMs);
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

    private sealed record SmbHostTarget(string Host, string? Share);
}

internal sealed record SmbKerberosDiscoveryResult(
    IReadOnlyList<IRemoteDrive> Drives,
    IReadOnlyList<string> Warnings,
    int NtlmFallbackHostCount);

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
    bool IsKerberosReady)
{
    internal string DisplayHost => KerberosHostName;
}

internal sealed class SmbKerberosDrive(
    SmbKerberosConnection connection,
    string shareName,
    Func<string, bool>? shouldPruneDirectory,
    Action<string>? onCurrentPath) : IRemoteDrive
{
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
        var pending = new Queue<string>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { string.Empty };
        pending.Enqueue(string.Empty);

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = pending.Dequeue();
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
                var item = new SmbKerberosRemoteFile(connection, shareName, relativePath, entry, isDirectory);
                await onChange(item);

                if (isDirectory
                    && !isReparsePoint
                    && !(shouldPruneDirectory?.Invoke(item.Path) ?? false)
                    && visited.Add(relativePath))
                {
                    pending.Enqueue(relativePath);
                }
            }
        }

        return string.Empty;
    }
}

internal sealed class SmbKerberosRemoteFile(
    SmbKerberosConnection connection,
    string shareName,
    string relativePath,
    FileDirectoryInformation information,
    bool isDirectory) : IRemoteFile
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

    public Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default)
    {
        if (IsDirectory)
        {
            return Task.FromResult<Stream?>(null);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<Stream?>(SmbKerberosReadStream.Open(connection, shareName, relativePath, 0, Size));
    }

    public Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(start);
        if (end < start)
        {
            throw new ArgumentOutOfRangeException(nameof(end));
        }

        if (IsDirectory)
        {
            return Task.FromResult<Stream?>(null);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var available = Size.HasValue ? Math.Max(0, Math.Min(end, Size.Value - 1) - start + 1) : end - start + 1;
        return Task.FromResult<Stream?>(SmbKerberosReadStream.Open(connection, shareName, relativePath, start, available));
    }
}

internal sealed class SmbKerberosSession : IDisposable
{
    private readonly SspiSmbAuthenticationClient _authentication;
    private bool _disposed;

    private SmbKerberosSession(SMB2Client client, SspiSmbAuthenticationClient authentication)
    {
        Client = client;
        _authentication = authentication;
    }

    internal SMB2Client Client { get; }

    internal static SmbKerberosSession Connect(SmbKerberosConnection connection)
    {
        var client = new SMB2Client(SmbKerberosService.ConnectionTimeoutMs);
        if (!client.Connect(connection.Address, SMBTransportType.DirectTCPTransport))
        {
            throw new InvalidOperationException($"SMB negotiation failed for {connection.Address}:445.");
        }

        var credential = connection.Credential;
        var securityPackage = connection.AuthenticationProtocol == SmbAuthenticationProtocol.Kerberos
            ? "Kerberos"
            : "NTLM";
        var authenticationUserName = credential?.UserName;
        var authenticationDomain = connection.Realm;
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

        var authentication = credential == null
            ? new SspiSmbAuthenticationClient(connection.KerberosHostName, securityPackage)
            : new SspiSmbAuthenticationClient(
                connection.KerberosHostName,
                securityPackage,
                authenticationDomain,
                authenticationUserName,
                credential.Password);

        try
        {
            var status = client.Login(authentication);
            if (status != NTStatus.STATUS_SUCCESS || !authentication.AuthenticationCompleted)
            {
                var sspiError = string.IsNullOrWhiteSpace(authentication.LastSecurityError)
                    ? string.Empty
                    : $" SSPI: {authentication.LastSecurityError}.";
                throw new SmbAuthenticationException(
                    securityPackage,
                    status,
                    authentication.LastSecurityStatus,
                    $"explicit {securityPackage} SMB authentication to '{authentication.TargetName}' failed with {SmbKerberosService.FormatStatus(status)}.{sspiError}");
            }

            return new SmbKerberosSession(client, authentication);
        }
        catch
        {
            authentication.Dispose();
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
            throw new InvalidOperationException($"Could not connect to share '{shareName}': {SmbKerberosService.FormatStatus(status)}.");
        }

        return new SmbKerberosStore(store);
    }

    public void Dispose()
    {
        if (_disposed) return;
        try { Client.Logoff(); } catch { }
        try { Client.Disconnect(); } catch { }
        _authentication.Dispose();
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

internal sealed class SmbKerberosReadStream : Stream
{
    private readonly SmbKerberosSession _session;
    private readonly SmbKerberosStore _store;
    private readonly object _handle;
    private readonly long? _length;
    private long _remoteOffset;
    private long _position;
    private long? _remaining;
    private bool _disposed;

    private SmbKerberosReadStream(
        SmbKerberosSession session,
        SmbKerberosStore store,
        object handle,
        long start,
        long? length)
    {
        _session = session;
        _store = store;
        _handle = handle;
        _remoteOffset = start;
        _length = length;
        _remaining = length;
    }

    internal static SmbKerberosReadStream Open(
        SmbKerberosConnection connection,
        string shareName,
        string path,
        long start,
        long? length)
    {
        var session = SmbKerberosSession.Connect(connection);
        SmbKerberosStore? store = null;
        object? handle = null;
        try
        {
            store = session.ConnectShare(shareName);
            var status = store.Inner.CreateFile(
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
                throw new IOException($"Could not open remote file '{path}': {SmbKerberosService.FormatStatus(status)}.");
            }

            return new SmbKerberosReadStream(session, store, handle, start, length);
        }
        catch
        {
            if (handle != null) try { store?.Inner.CloseFile(handle); } catch { }
            store?.Dispose();
            session.Dispose();
            throw;
        }
    }

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

        var requested = Math.Min(buffer.Length, checked((int)Math.Min(_store.Inner.MaxReadSize, int.MaxValue)));
        if (_remaining.HasValue)
        {
            requested = checked((int)Math.Min(requested, _remaining.Value));
        }

        var status = _store.Inner.ReadFile(out var data, _handle, _remoteOffset, requested);
        if (status == NTStatus.STATUS_END_OF_FILE || data.Length == 0)
        {
            return 0;
        }

        if (status != NTStatus.STATUS_SUCCESS)
        {
            throw new IOException($"Remote SMB read failed: {SmbKerberosService.FormatStatus(status)}.");
        }

        var read = Math.Min(data.Length, requested);
        data.AsSpan(0, read).CopyTo(buffer);
        _remoteOffset += read;
        _position += read;
        if (_remaining.HasValue) _remaining -= read;
        return read;
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
            try { _store.Inner.CloseFile(_handle); } catch { }
            _store.Dispose();
            _session.Dispose();
            _disposed = true;
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
