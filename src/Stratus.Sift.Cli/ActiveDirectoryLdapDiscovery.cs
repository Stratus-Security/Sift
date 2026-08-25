using System.ComponentModel;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Stratus.Sift.Cli;

internal sealed partial class ActiveDirectoryLdapDiscovery(CliDnsResolver dnsResolver)
{
    private const int LdapPort = 389;
    private const int PageSize = 500;
    private const int MaxPageCount = 2_000;
    private const int ErrorSuccess = 0;
    private const uint DsDirectoryServiceRequired = 0x00000010;
    private const uint DsIpRequired = 0x00000200;
    private const uint DsReturnDnsName = 0x40000000;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);

    internal const string EnabledComputerFilter =
        "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    [SupportedOSPlatform("windows")]
    internal async Task<IReadOnlyList<string>> EnumerateComputersAsync(
        string? requestedDomainController,
        CliWindowsCredential? credential,
        bool strictKerberos,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Active Directory discovery is currently supported only on Windows.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var domainController = ResolveDomainController(requestedDomainController, credential);

        try
        {
            var connectionTarget = domainController;
            var authenticationHostName = domainController;
            if (dnsServer != null && IPAddress.TryParse(domainController, out var controllerAddress))
            {
                if (strictKerberos)
                {
                    authenticationHostName = await dnsResolver.ResolveHostNameAsync(controllerAddress, dnsServer, cancellationToken).ConfigureAwait(false)
                        ?? domainController;
                }
            }
            else if (dnsServer != null)
            {
                var addresses = await dnsResolver.ResolveHostAddressesAsync(domainController, dnsServer, cancellationToken).ConfigureAwait(false);
                connectionTarget = addresses.FirstOrDefault(address => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString()
                    ?? addresses.First().ToString();
            }

            ValidateAuthenticationTarget(authenticationHostName, strictKerberos);
            using var connection = CreateConnection(connectionTarget, authenticationHostName, credential, strictKerberos);
            var rootDse = await SendSearchAsync(
                connection,
                new SearchRequest(
                    string.Empty,
                    "(objectClass=*)",
                    System.DirectoryServices.Protocols.SearchScope.Base,
                    "defaultNamingContext"),
                cancellationToken).ConfigureAwait(false);

            var namingContext = ReadFirstString(rootDse.Entries.Cast<SearchResultEntry>(), "defaultNamingContext");
            if (string.IsNullOrWhiteSpace(namingContext))
            {
                throw new InvalidOperationException("The LDAP server did not return a default naming context.");
            }

            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenCookies = new HashSet<string>(StringComparer.Ordinal);
            byte[] cookie = [];

            for (var pageNumber = 1; pageNumber <= MaxPageCount; pageNumber++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var request = new SearchRequest(
                    namingContext,
                    EnabledComputerFilter,
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    "dNSHostName",
                    "name");
                request.Controls.Add(new PageResultRequestControl(PageSize) { Cookie = cookie });

                var response = await SendSearchAsync(connection, request, cancellationToken).ConfigureAwait(false);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var host = ReadFirstString([entry], "dNSHostName")
                        ?? ReadFirstString([entry], "name");
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        hosts.Add(host.Trim().TrimEnd('.'));
                    }
                }

                cookie = ReadPageCookie(response);
                if (cookie.Length == 0)
                {
                    return hosts.OrderBy(host => host, StringComparer.OrdinalIgnoreCase).ToArray();
                }

                var cookieKey = Convert.ToBase64String(cookie);
                if (!seenCookies.Add(cookieKey))
                {
                    throw new InvalidOperationException("The LDAP server repeated a paging cookie, so discovery stopped to avoid an infinite loop.");
                }
            }

            throw new InvalidOperationException($"Active Directory discovery exceeded the safety limit of {MaxPageCount:N0} LDAP pages.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            var mode = strictKerberos ? "strict Kerberos" : "Negotiate authentication";
            throw new InvalidOperationException(
                $"Unable to enumerate Active Directory computers through '{domainController}' using {mode}. " +
                "Check DNS, LDAP access, credentials, and directory-query permissions.",
                ex);
        }
    }

    internal static AuthType GetAuthenticationType(bool strictKerberos) =>
        strictKerberos ? AuthType.Kerberos : AuthType.Negotiate;

    internal static void ValidateAuthenticationTarget(string domainController, bool strictKerberos)
    {
        if (strictKerberos && IPAddress.TryParse(domainController, out _))
        {
            throw new InvalidOperationException(
                "Strict Kerberos LDAP discovery requires a resolvable domain-controller hostname so Windows can build the LDAP service principal. " +
                "Use --domain-controller with the controller's DNS name, or remove --kerberos to allow Negotiate authentication.");
        }
    }

    internal static string? ReadFirstString(IEnumerable<SearchResultEntry> entries, string attributeName)
    {
        foreach (var entry in entries)
        {
            var attribute = entry.Attributes[attributeName];
            if (attribute is { Count: > 0 })
            {
                var value = attribute[0]?.ToString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }
        }

        return null;
    }

    internal static byte[] ReadPageCookie(SearchResponse response)
    {
        foreach (DirectoryControl control in response.Controls)
        {
            if (control is PageResultResponseControl pageControl)
            {
                return pageControl.Cookie ?? [];
            }
        }

        return [];
    }

    [SupportedOSPlatform("windows")]
    private static LdapConnection CreateConnection(
        string connectionTarget,
        string authenticationHostName,
        CliWindowsCredential? credential,
        bool strictKerberos)
    {
        var identifier = new LdapDirectoryIdentifier(connectionTarget, LdapPort, false, false);
        var authenticationType = GetAuthenticationType(strictKerberos);
        var connection = credential is null
            ? new LdapConnection(identifier) { AuthType = authenticationType }
            : new LdapConnection(identifier, credential.ToNetworkCredential(), authenticationType);

        connection.AutoBind = true;
        connection.Timeout = RequestTimeout;
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.HostName = authenticationHostName;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        connection.SessionOptions.Signing = true;
        connection.SessionOptions.Sealing = true;
        return connection;
    }

    private static async Task<SearchResponse> SendSearchAsync(
        LdapConnection connection,
        SearchRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var completion = new TaskCompletionSource<DirectoryResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var beginTask = Task.Run(() => connection.BeginSendRequest(
            request,
            RequestTimeout,
            PartialResultProcessing.NoPartialResultSupport,
            result =>
            {
                try
                {
                    completion.TrySetResult(connection.EndSendRequest(result));
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex);
                }
            },
            state: null));

        IAsyncResult pendingRequest;
        try
        {
            pendingRequest = await beginTask.WaitAsync(RequestTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            connection.Dispose();
            ObserveFault(beginTask);
            throw new TimeoutException($"LDAP request exceeded the {RequestTimeout.TotalSeconds:N0}-second timeout.", ex);
        }
        catch (OperationCanceledException)
        {
            connection.Dispose();
            ObserveFault(beginTask);
            throw;
        }

        DirectoryResponse response;
        try
        {
            response = await completion.Task.WaitAsync(RequestTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            TryAbort(connection, pendingRequest);
            throw new TimeoutException($"LDAP request exceeded the {RequestTimeout.TotalSeconds:N0}-second timeout.", ex);
        }
        catch (OperationCanceledException)
        {
            TryAbort(connection, pendingRequest);
            throw;
        }

        return response as SearchResponse
            ?? throw new InvalidOperationException($"LDAP returned an unexpected {response.GetType().Name} response.");
    }

    private static void TryAbort(LdapConnection connection, IAsyncResult pendingRequest)
    {
        try
        {
            connection.Abort(pendingRequest);
        }
        catch (Exception)
        {
            // The request may have completed between timeout/cancellation and Abort.
        }
    }

    private static void ObserveFault(Task task)
    {
        _ = task.ContinueWith(
            static completedTask => _ = completedTask.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    [SupportedOSPlatform("windows")]
    private static string ResolveDomainController(string? requestedDomainController, CliWindowsCredential? credential)
    {
        if (!string.IsNullOrWhiteSpace(requestedDomainController))
        {
            return requestedDomainController.Trim().TrimStart('\\').TrimEnd('.');
        }

        var domainHint = credential?.Domain;
        var separator = credential?.UserName.LastIndexOf('@') ?? -1;
        if (string.IsNullOrWhiteSpace(domainHint) && separator > 0)
        {
            domainHint = credential!.UserName[(separator + 1)..];
        }

        var result = DsGetDcName(
            computerName: null,
            domainName: string.IsNullOrWhiteSpace(domainHint) ? null : domainHint,
            domainGuid: IntPtr.Zero,
            siteName: null,
            flags: DsDirectoryServiceRequired | DsIpRequired | DsReturnDnsName,
            out var controllerInfoPointer);
        if (result != ErrorSuccess)
        {
            throw new Win32Exception(
                result,
                string.IsNullOrWhiteSpace(domainHint)
                    ? "Windows could not discover a domain controller for the current domain. Use --domain-controller to specify one."
                    : $"Windows could not discover a domain controller for '{domainHint}'. Use --domain-controller to specify one.");
        }

        try
        {
            var controllerInfo = Marshal.PtrToStructure<DomainControllerInfo>(controllerInfoPointer);
            var controllerName = Marshal.PtrToStringUni(controllerInfo.DomainControllerName)?.Trim().TrimStart('\\').TrimEnd('.');
            return !string.IsNullOrWhiteSpace(controllerName)
                ? controllerName
                : throw new InvalidOperationException("Windows domain-controller discovery returned no controller name.");
        }
        finally
        {
            NetApiBufferFree(controllerInfoPointer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DomainControllerInfo
    {
        public IntPtr DomainControllerName;
        public IntPtr DomainControllerAddress;
        public uint DomainControllerAddressType;
        public Guid DomainGuid;
        public IntPtr DomainName;
        public IntPtr DnsForestName;
        public uint Flags;
        public IntPtr DcSiteName;
        public IntPtr ClientSiteName;
    }

    [LibraryImport("Netapi32.dll", EntryPoint = "DsGetDcNameW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int DsGetDcName(
        string? computerName,
        string? domainName,
        IntPtr domainGuid,
        string? siteName,
        uint flags,
        out IntPtr domainControllerInfo);

    [LibraryImport("Netapi32.dll", EntryPoint = "NetApiBufferFree")]
    private static partial int NetApiBufferFree(IntPtr buffer);
}
