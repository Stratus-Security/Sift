using System.Collections.Concurrent;
#if !SIFT_NATIVE_AOT
using System.DirectoryServices;
#endif
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace Stratus.Sift.Cli;

internal sealed partial class SmbDiscoveryService
{
    private readonly ILogger<SmbDiscoveryService> _logger;
    private const int ShareEnumerationLevel = 1;
    private const int MaxShareBufferLength = -1;
    private const int SmbPort = 445;
    private const int ConnectTimeoutMs = 750;
    private const int HostParallelism = 32;

    public SmbDiscoveryService(ILogger<SmbDiscoveryService> logger)
    {
        _logger = logger;
    }

    [SupportedOSPlatform("windows")]
    public Task<IReadOnlyList<string>> DiscoverRootsAsync(FileSystemScanTarget target, CliWindowsCredential? credential, CancellationToken cancellationToken)
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
                cancellationToken),
            FileSystemScanMode.Subnet => DiscoverSubnetRootsAsync(target.Value, cancellationToken),
            FileSystemScanMode.Device => DiscoverDeviceRootsAsync(target.Value, cancellationToken),
            _ => throw new ArgumentException($"Unsupported discovery mode '{target.Mode}'.", nameof(target))
        };
    }

    [SupportedOSPlatform("windows")]
    private async Task<IReadOnlyList<string>> DiscoverDomainRootsAsync(string? domainController, CliWindowsCredential? credential, CancellationToken cancellationToken)
    {
#if SIFT_NATIVE_AOT
        await Task.CompletedTask;
        throw new PlatformNotSupportedException("Active Directory discovery is not included in Native AOT builds. Use the network command with explicit hosts or subnets.");
#else
        var hosts = EnumerateDomainHosts(domainController, credential);
        return await DiscoverSharesForHostsAsync(hosts, cancellationToken);
#endif
    }

    [SupportedOSPlatform("windows")]
    private async Task<IReadOnlyList<string>> DiscoverSubnetRootsAsync(string cidr, CancellationToken cancellationToken)
    {
        var hosts = EnumerateSubnetHosts(cidr);
        return await DiscoverSharesForHostsAsync(hosts, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    private async Task<IReadOnlyList<string>> DiscoverDeviceRootsAsync(string device, CancellationToken cancellationToken)
    {
        if (TryExtractExplicitShareRoot(device, out var explicitRoot))
        {
            return IsAccessibleDirectory(explicitRoot)
                ? [explicitRoot]
                : [];
        }

        return await DiscoverSharesForHostsAsync([NormalizeHost(device)], cancellationToken);
    }

    private async Task<IReadOnlyList<string>> DiscoverSharesForHostsAsync(IEnumerable<string> hosts, CancellationToken cancellationToken)
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
                    if (!await IsSmbReachableAsync(host, token))
                    {
                        return;
                    }

                    foreach (var share in EnumerateShares(host))
                    {
                        var root = $@"\\{host}\{share}";
                        if (IsAccessibleDirectory(root))
                        {
                            discoveredRoots.TryAdd(root, 0);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to discover SMB shares on host {Host}", host);
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

    internal static string BuildLdapPath(string? domainController, string relativePath)
    {
        var server = string.Empty;
        if (!string.IsNullOrWhiteSpace(domainController))
        {
            var value = domainController.Trim();
            server = IPAddress.TryParse(value, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6
                ? $"[{value}]/"
                : $"{value}/";
        }

        return $"LDAP://{server}{relativePath}";
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
            && !shareName.Equals("print$", StringComparison.OrdinalIgnoreCase)
            && !shareName.Equals("ADMIN$", StringComparison.OrdinalIgnoreCase);
    }

    [SupportedOSPlatform("windows")]
    internal IReadOnlyList<string> EnumerateDomainHostsForScan(CliWindowsCredential? credential)
    {
#if SIFT_NATIVE_AOT
        throw new PlatformNotSupportedException("Active Directory discovery is not included in Native AOT builds.");
#else
        return EnumerateDomainHosts(null, credential);
#endif
    }

    [SupportedOSPlatform("windows")]
    internal IReadOnlyList<string> EnumerateDomainHostsForScan(string? domainController, CliWindowsCredential? credential)
    {
#if SIFT_NATIVE_AOT
        throw new PlatformNotSupportedException("Active Directory discovery is not included in Native AOT builds.");
#else
        return EnumerateDomainHosts(domainController, credential);
#endif
    }

    internal Task<IReadOnlyList<string>> DiscoverRootsForHostsAsync(IEnumerable<string> hosts, CancellationToken cancellationToken)
    {
        return DiscoverSharesForHostsAsync(hosts, cancellationToken);
    }

#if !SIFT_NATIVE_AOT
    [SupportedOSPlatform("windows")]
    private IReadOnlyList<string> EnumerateDomainHosts(string? domainController, CliWindowsCredential? credential)
    {
        try
        {
            var hosts = new List<string>();
            using var rootDse = CreateDirectoryEntry(BuildLdapPath(domainController, "RootDSE"), credential);
            var namingContext = rootDse.Properties["defaultNamingContext"]?.Value?.ToString();
            if (string.IsNullOrWhiteSpace(namingContext))
            {
                throw new InvalidOperationException("Unable to determine the current Active Directory naming context.");
            }

            using var entry = CreateDirectoryEntry(BuildLdapPath(domainController, namingContext), credential);
            using var searcher = new DirectorySearcher(entry)
            {
                Filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                PageSize = 500,
                SearchScope = SearchScope.Subtree
            };

            searcher.PropertiesToLoad.Add("dNSHostName");
            searcher.PropertiesToLoad.Add("name");

            using var results = searcher.FindAll();
            foreach (SearchResult result in results)
            {
                var host = result.Properties["dNSHostName"].Count > 0
                    ? result.Properties["dNSHostName"][0]?.ToString()
                    : result.Properties["name"].Count > 0
                        ? result.Properties["name"][0]?.ToString()
                        : null;

                if (!string.IsNullOrWhiteSpace(host))
                {
                    hosts.Add(host);
                }
            }

            return hosts;
        }
        catch (Exception ex)
        {
            var targetDescription = string.IsNullOrWhiteSpace(domainController)
                ? "the current Active Directory domain"
                : $"Active Directory through domain controller '{domainController}'";
            throw new InvalidOperationException($"Unable to enumerate computers from {targetDescription}. Ensure the domain controller is reachable and the supplied user can query LDAP.", ex);
        }
    }

    [SupportedOSPlatform("windows")]
    private static DirectoryEntry CreateDirectoryEntry(string path, CliWindowsCredential? credential)
    {
        return credential is null
            ? new DirectoryEntry(path)
            : new DirectoryEntry(path, credential.DirectoryEntryUserName, credential.Password, AuthenticationTypes.Secure);
    }
#endif

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
