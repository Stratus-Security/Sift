using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace Stratus.Sift.Cli;

internal sealed partial class SmbDiscoveryService
{
    private readonly ActiveDirectoryLdapDiscovery _activeDirectory;
    private readonly CliDnsResolver _dnsResolver;
    private readonly ILogger<SmbDiscoveryService> _logger;
    private const int ShareEnumerationLevel = 1;
    private const int MaxShareBufferLength = -1;
    private const int SmbPort = 445;
    private const int ConnectTimeoutMs = 750;
    private const int HostParallelism = 32;

    public SmbDiscoveryService(
        ActiveDirectoryLdapDiscovery activeDirectory,
        CliDnsResolver dnsResolver,
        ILogger<SmbDiscoveryService> logger)
    {
        _activeDirectory = activeDirectory;
        _dnsResolver = dnsResolver;
        _logger = logger;
    }

    [SupportedOSPlatform("windows")]
    public Task<IReadOnlyList<string>> DiscoverRootsAsync(
        FileSystemScanTarget target,
        CliWindowsCredential? credential,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("SMB discovery modes are currently supported only on Windows.");
        }

        return target.Mode switch
        {
            FileSystemScanMode.Domain => DiscoverDomainRootsAsync(
                target.Value.Equals("current domain", StringComparison.OrdinalIgnoreCase) ? null : target.Value,
                credential,
                dnsServer,
                cancellationToken),
            FileSystemScanMode.Subnet => DiscoverSubnetRootsAsync(target.Value, dnsServer, cancellationToken),
            FileSystemScanMode.Device => DiscoverDeviceRootsAsync(target.Value, dnsServer, cancellationToken),
            _ => throw new ArgumentException($"Unsupported discovery mode '{target.Mode}'.", nameof(target))
        };
    }

    [SupportedOSPlatform("windows")]
    private async Task<IReadOnlyList<string>> DiscoverDomainRootsAsync(
        string? domainController,
        CliWindowsCredential? credential,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        var hosts = await EnumerateDomainHostsForScanAsync(
            domainController,
            credential,
            strictKerberos: false,
            dnsServer,
            cancellationToken).ConfigureAwait(false);
        return await DiscoverSharesForHostsAsync(hosts, dnsServer, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    private async Task<IReadOnlyList<string>> DiscoverSubnetRootsAsync(string cidr, IPAddress? dnsServer, CancellationToken cancellationToken)
    {
        var hosts = EnumerateSubnetHosts(cidr);
        return await DiscoverSharesForHostsAsync(hosts, dnsServer, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    private async Task<IReadOnlyList<string>> DiscoverDeviceRootsAsync(string device, IPAddress? dnsServer, CancellationToken cancellationToken)
    {
        if (TryExtractExplicitShareRoot(device, out var explicitRoot))
        {
            if (dnsServer is null)
            {
                return IsAccessibleDirectory(explicitRoot)
                    ? [explicitRoot]
                    : [];
            }

            var resolvedRoots = await ResolveExplicitShareRootsAsync(explicitRoot, dnsServer, cancellationToken).ConfigureAwait(false);
            return resolvedRoots
                .Where(IsAccessibleDirectory)
                .ToArray();
        }

        return await DiscoverSharesForHostsAsync([NormalizeHost(device)], dnsServer, cancellationToken);
    }

    private async Task<IReadOnlyList<string>> DiscoverSharesForHostsAsync(
        IEnumerable<string> hosts,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        var discoveredRoots = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        var uniqueHosts = hosts
            .Where(host => !string.IsNullOrWhiteSpace(host))
            .Select(NormalizeHost)
            .Where(host => !string.IsNullOrWhiteSpace(host))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        await Parallel.ForEachAsync(
            uniqueHosts,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = HostParallelism,
                CancellationToken = cancellationToken
            },
            async (host, token) =>
            {
                try
                {
                    var connectionHosts = dnsServer is null
                        ? [(ReachabilityHost: host, UncHost: host)]
                        : (await _dnsResolver.ResolveHostAddressesAsync(host, dnsServer, token).ConfigureAwait(false))
                            .Select(address => (ReachabilityHost: address.ToString(), UncHost: FormatUncHost(address)))
                            .ToArray();
                    foreach (var connectionHost in connectionHosts)
                    {
                        if (!await IsSmbReachableAsync(connectionHost.ReachabilityHost, token))
                        {
                            continue;
                        }

                        var readableShares = EnumerateShares(connectionHost.UncHost)
                            .Where(share => IsAccessibleDirectory($@"\\{connectionHost.UncHost}\{share}"))
                            .ToArray();

                        foreach (var share in SelectSharesForCoverage(readableShares))
                        {
                            var root = $@"\\{connectionHost.UncHost}\{share}";
                            discoveredRoots.TryAdd(root, 0);
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (dnsServer is null)
                    {
                        _logger.LogDebug(ex, "Failed to discover SMB shares on host {Host}", host);
                    }
                    else
                    {
                        _logger.LogWarning(ex, "Failed to resolve or discover SMB shares on host {Host} through explicit DNS server {DnsServer}", host, dnsServer);
                    }
                }
            });

        return discoveredRoots.Keys
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    internal static bool IsValidSubnetOrSingleHost(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (IPAddress.TryParse(trimmed, out var singleAddress) && singleAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            return true;
        }

        var parts = trimmed.Split('/', 2, StringSplitOptions.TrimEntries);
        return parts.Length == 2
            && IPAddress.TryParse(parts[0], out var networkAddress)
            && networkAddress.AddressFamily == AddressFamily.InterNetwork
            && int.TryParse(parts[1], out var prefixLength)
            && prefixLength is >= 0 and <= 32;
    }

    internal static bool IsValidDomainController(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (IPAddress.TryParse(trimmed, out _))
        {
            return true;
        }

        return !trimmed.Contains('/')
            && !trimmed.Contains('\\')
            && !trimmed.Contains(':')
            && Uri.CheckHostName(trimmed) == UriHostNameType.Dns;
    }

    internal static IReadOnlyList<string> EnumerateSubnetHosts(string cidr)
    {
        var trimmed = cidr.Trim();
        if (IPAddress.TryParse(trimmed, out var singleAddress) && singleAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            return [singleAddress.ToString()];
        }

        var parts = trimmed.Split('/', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out var networkAddress) ||
            networkAddress.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out var prefixLength) ||
            prefixLength < 0 ||
            prefixLength > 32)
        {
            throw new ArgumentException($"Invalid subnet '{cidr}'. Use CIDR notation like 10.0.0.0/24.");
        }

        var addressValue = ToUInt32(networkAddress);
        var mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        var network = addressValue & mask;
        var broadcast = network | ~mask;

        var hosts = new List<string>();
        if (prefixLength >= 31)
        {
            for (var current = network; current <= broadcast; current++)
            {
                hosts.Add(FromUInt32(current).ToString());
                if (current == uint.MaxValue)
                {
                    break;
                }
            }

            return hosts;
        }

        for (var current = network + 1; current < broadcast; current++)
        {
            hosts.Add(FromUInt32(current).ToString());
        }

        return hosts;
    }

    internal static bool IsCandidateShare(string shareName, uint shareType)
    {
        if (string.IsNullOrWhiteSpace(shareName))
        {
            return false;
        }

        var normalizedType = shareType & ~SpecialShareType;
        if (normalizedType != DiskTreeShareType)
        {
            return false;
        }

        return !shareName.Equals("IPC$", StringComparison.OrdinalIgnoreCase)
            && !shareName.Equals("print$", StringComparison.OrdinalIgnoreCase);
    }

    internal static IReadOnlyList<string> SelectSharesForCoverage(IEnumerable<string> readableShares)
    {
        var shares = readableShares
            .Where(share => !string.IsNullOrWhiteSpace(share))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // ADMIN$ maps to the Windows directory and is already covered by C$ on
        // the normal system drive. Keep it as a fallback when C$ is not readable.
        if (shares.Contains("C$", StringComparer.OrdinalIgnoreCase))
        {
            shares.RemoveAll(share => share.Equals("ADMIN$", StringComparison.OrdinalIgnoreCase));
        }

        return shares;
    }

    [SupportedOSPlatform("windows")]
    internal Task<IReadOnlyList<string>> EnumerateDomainHostsForScanAsync(
        CliWindowsCredential? credential,
        bool strictKerberos,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        return EnumerateDomainHostsForScanAsync(null, credential, strictKerberos, dnsServer, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    internal Task<IReadOnlyList<string>> EnumerateDomainHostsForScanAsync(
        string? domainController,
        CliWindowsCredential? credential,
        bool strictKerberos,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        return _activeDirectory.EnumerateComputersAsync(domainController, credential, strictKerberos, dnsServer, cancellationToken);
    }

    internal Task<IReadOnlyList<string>> DiscoverRootsForHostsAsync(
        IEnumerable<string> hosts,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        return DiscoverSharesForHostsAsync(hosts, dnsServer, cancellationToken);
    }

    private IEnumerable<string> EnumerateShares(string host)
    {
        var serverName = host.StartsWith(@"\\", StringComparison.Ordinal) ? host : $@"\\{host}";
        var resultCode = NetShareEnum(serverName, ShareEnumerationLevel, out var buffer, MaxShareBufferLength, out var entriesRead, out _, out _);
        if (resultCode != 0)
        {
            yield break;
        }

        try
        {
            var current = buffer;
            var itemSize = Marshal.SizeOf<SHARE_INFO_1>();
            for (var index = 0; index < entriesRead; index++)
            {
                var shareInfo = Marshal.PtrToStructure<SHARE_INFO_1>(current);
                if (IsCandidateShare(shareInfo.NetName ?? string.Empty, shareInfo.Type))
                {
                    yield return shareInfo.NetName!;
                }

                current = IntPtr.Add(current, itemSize);
            }
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
    }

    private static string NormalizeHost(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith(@"\\", StringComparison.Ordinal))
        {
            trimmed = trimmed.TrimStart('\\');
        }

        var slashIndex = trimmed.IndexOf('\\');
        if (slashIndex >= 0)
        {
            trimmed = trimmed[..slashIndex];
        }

        return trimmed.Trim();
    }

    private static bool TryExtractExplicitShareRoot(string value, out string root)
    {
        root = string.Empty;
        if (!value.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return false;
        }

        var segments = value
            .TrimStart('\\')
            .Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (segments.Length < 2)
        {
            return false;
        }

        root = $@"\\{segments[0]}\{segments[1]}";
        return true;
    }

    internal async Task<IReadOnlyList<string>> ResolveExplicitShareRootsAsync(
        string explicitRoot,
        IPAddress dnsServer,
        CancellationToken cancellationToken)
    {
        var segments = explicitRoot
            .TrimStart('\\')
            .Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var addresses = await _dnsResolver.ResolveHostAddressesAsync(segments[0], dnsServer, cancellationToken).ConfigureAwait(false);
        return CreateExplicitShareRoots(explicitRoot, addresses);
    }

    internal static IReadOnlyList<string> CreateExplicitShareRoots(
        string explicitRoot,
        IEnumerable<IPAddress> addresses)
    {
        var segments = explicitRoot
            .TrimStart('\\')
            .Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return addresses
            .Select(address => $@"\\{FormatUncHost(address)}\{segments[1]}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    internal static string FormatUncHost(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        // Windows maps this reserved form directly to an IPv6 literal without a DNS query.
        return $"{address.ToString().Replace(':', '-').Replace('%', 's')}.ipv6-literal.net";
    }

    private static async Task<bool> IsSmbReachableAsync(string host, CancellationToken cancellationToken)
    {
        using var tcpClient = new TcpClient();
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(ConnectTimeoutMs);

        try
        {
            await tcpClient.ConnectAsync(host, SmbPort, timeoutCts.Token);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsAccessibleDirectory(string path)
    {
        return GetFileAttributesEx(path, 0, out var attributes)
            && (attributes.FileAttributes & FileAttributeDirectory) == FileAttributeDirectory;
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return BitConverter.ToUInt32(bytes, 0);
    }

    private static IPAddress FromUInt32(uint value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return new IPAddress(bytes);
    }

    private const uint FileAttributeDirectory = 0x10;
    private const uint DiskTreeShareType = 0;
    private const uint SpecialShareType = 0x80000000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHARE_INFO_1
    {
        public string? NetName;
        public uint Type;
        public string? Remark;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WIN32_FILE_ATTRIBUTE_DATA
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint FileSizeHigh;
        public uint FileSizeLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [LibraryImport("Netapi32.dll", EntryPoint = "NetShareEnum", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetShareEnum(
        string serverName,
        int level,
        out IntPtr buffer,
        int preferredMaximumLength,
        out int entriesRead,
        out int totalEntries,
        out int resumeHandle);

    [LibraryImport("Netapi32.dll", EntryPoint = "NetApiBufferFree")]
    private static partial int NetApiBufferFree(IntPtr buffer);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileAttributesExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileAttributesEx(
        string path,
        int infoLevelId,
        out WIN32_FILE_ATTRIBUTE_DATA fileInformation);
}
