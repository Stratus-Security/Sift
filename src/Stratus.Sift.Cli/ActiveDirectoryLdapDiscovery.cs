using System.ComponentModel;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;

namespace Stratus.Sift.Cli;

internal sealed partial class ActiveDirectoryLdapDiscovery(CliDnsResolver dnsResolver, DomainControllerLocator controllerLocator)
{
    private const int LdapPort = 389;
    private const int ErrorSuccess = 0;
    private const uint DsDirectoryServiceRequired = 0x00000010;
    private const uint DsIpRequired = 0x00000200;
    private const uint DsReturnDnsName = 0x40000000;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan DomainControllerLookupTimeout = TimeSpan.FromSeconds(60);

    internal const string EnabledComputerFilter =
        "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    internal async Task<IReadOnlyList<string>> EnumerateComputersAsync(
        string? requestedDomainController,
        CliWindowsCredential? credential,
        bool strictKerberos,
        IPAddress? dnsServer,
        CancellationToken cancellationToken,
        CliDiscoveryProgress? progress = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows() && credential is not null && strictKerberos)
        {
            return await EnumerateWithExplicitKerberosAsync(
                requestedDomainController, credential, dnsServer, cancellationToken, progress).ConfigureAwait(false);
        }
        progress?.FindingDomainController();
        Task<string> lookup;
        if (OperatingSystem.IsWindows())
        {
            lookup = ResolveWindowsDomainControllerAsync(requestedDomainController, credential);
        }
        else
        {
            lookup = controllerLocator.LocateAsync(requestedDomainController, GetDnsDomain(credential), dnsServer, cancellationToken);
        }
        string domainController;
        try
        {
            domainController = await lookup.WaitAsync(DomainControllerLookupTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            ObserveFault(lookup);
            throw new TimeoutException(
                $"Domain-controller discovery exceeded {DomainControllerLookupTimeout.TotalSeconds:N0} seconds. Use --domain-controller to specify a known controller.", ex);
        }
        catch (OperationCanceledException)
        {
            ObserveFault(lookup);
            throw;
        }

        try
        {
            var connectionTarget = domainController;
            var authenticationHostName = domainController;
            if (IPAddress.TryParse(domainController, out var controllerAddress))
            {
                if (!OperatingSystem.IsWindows() || (dnsServer != null && strictKerberos))
                {
                    authenticationHostName = await dnsResolver.ResolveHostNameAsync(controllerAddress, dnsServer, cancellationToken)
                        .ConfigureAwait(false) ?? domainController;
                    if (!OperatingSystem.IsWindows() && IPAddress.TryParse(authenticationHostName, out _))
                    {
                        authenticationHostName = await controllerLocator.MatchControllerNameAsync(
                            controllerAddress, GetDnsDomain(credential), dnsServer, dnsResolver, cancellationToken)
                            .ConfigureAwait(false) ?? domainController;
                    }
                }
            }
            else if (dnsServer != null)
            {
                var addresses = await dnsResolver.ResolveHostAddressesAsync(domainController, dnsServer, cancellationToken).ConfigureAwait(false);
                connectionTarget = addresses.FirstOrDefault(address => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString()
                    ?? addresses.First().ToString();
            }

            ValidateAuthenticationTarget(authenticationHostName, strictKerberos);
            progress?.FindingComputers();
            if (!OperatingSystem.IsWindows() && credential is not null)
            {
                return await PortableLdapDiscovery.EnumerateComputersAsync(
                    connectionTarget, authenticationHostName, credential,
                    count => progress?.ComputersFound(count), cancellationToken).ConfigureAwait(false);
            }
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

            for (var pageNumber = 1; pageNumber <= ActiveDirectoryComputerSearchPolicy.MaxPageCount; pageNumber++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var request = new SearchRequest(
                    namingContext,
                    EnabledComputerFilter,
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    "dNSHostName",
                    "name");
                request.Controls.Add(new PageResultRequestControl(ActiveDirectoryComputerSearchPolicy.PageSize) { Cookie = cookie });

                var response = await SendSearchAsync(connection, request, cancellationToken).ConfigureAwait(false);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var dnsHostName = ReadFirstString([entry], "dNSHostName");
                    ActiveDirectoryComputerSearchPolicy.AddHost(
                        hosts, dnsHostName,
                        string.IsNullOrWhiteSpace(dnsHostName) ? ReadFirstString([entry], "name") : null);
                }
                progress?.ComputersFound(hosts.Count);

                cookie = ReadPageCookie(response);
                if (!ActiveDirectoryComputerSearchPolicy.HasMorePages(cookie, seenCookies))
                {
                    return ActiveDirectoryComputerSearchPolicy.OrderHosts(hosts);
                }
            }

            throw ActiveDirectoryComputerSearchPolicy.PageLimitExceeded();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            var mode = !OperatingSystem.IsWindows() && credential is not null
                ? "LDAPS password authentication"
                : strictKerberos ? "strict Kerberos" : "Negotiate authentication";
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
        if (OperatingSystem.IsWindows())
        {
            connection.SessionOptions.Signing = true;
            connection.SessionOptions.Sealing = true;
        }
        return connection;
    }

    private static string? GetDnsDomain(CliWindowsCredential? credential)
    {
        if (!string.IsNullOrWhiteSpace(credential?.Domain) && !credential.IsLocalMachineAccount)
        {
            return credential.Domain;
        }

        var userName = credential?.UserName;
        var separator = userName?.LastIndexOf('@') ?? -1;
        return separator > 0 ? userName![(separator + 1)..] : null;
    }

    [UnsupportedOSPlatform("windows")]
    private async Task<IReadOnlyList<string>> EnumerateWithExplicitKerberosAsync(
        string? requestedDomainController,
        CliWindowsCredential credential,
        IPAddress? dnsServer,
        CancellationToken cancellationToken,
        CliDiscoveryProgress? progress)
    {
        var realm = GetDnsDomain(credential) ?? throw new InvalidOperationException(
            "Kerberos LDAP discovery requires an AD DNS domain. Supply --domain or use user@domain.");
        if (Uri.CheckHostName(realm) != UriHostNameType.Dns || !realm.Contains('.'))
        {
            throw new InvalidOperationException("Kerberos LDAP discovery requires a valid AD DNS domain name.");
        }
        var controller = await controllerLocator.LocateAsync(
            requestedDomainController, realm, dnsServer, cancellationToken).ConfigureAwait(false);
        var kdcAddress = (await dnsResolver.ResolveHostAddressesAsync(controller, dnsServer, cancellationToken)
            .ConfigureAwait(false)).First().ToString();
        if (IPAddress.TryParse(controller, out var controllerAddress))
        {
            controller = await controllerLocator.MatchControllerNameAsync(
                controllerAddress, realm, dnsServer, dnsResolver, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException(
                    "The controller IP could not be matched to an AD DNS hostname for Kerberos LDAP authentication.");
        }
        var cachePath = Path.Combine(Path.GetTempPath(), $"sift-krb5cc-{Guid.NewGuid():N}");
        var configPath = Path.Combine(Path.GetTempPath(), $"sift-krb5-{Guid.NewGuid():N}.conf");
        try
        {
            using (var cacheFile = new FileStream(cachePath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            })) { }
            using (var configFile = new FileStream(configPath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            }))
            using (var writer = new StreamWriter(configFile))
            {
                await writer.WriteAsync($"[libdefaults]\n default_realm = {realm.ToUpperInvariant()}\n dns_lookup_kdc = false\n[realms]\n {realm.ToUpperInvariant()} = {{\n  kdc = {kdcAddress}\n }}\n")
                    .ConfigureAwait(false);
            }
            using var client = new KerberosClient { Cache = new Krb5TicketCache(cachePath) };
            client.PinKdc(realm, kdcAddress);
            await client.Authenticate(new KerberosPasswordCredential(credential.UserName, credential.Password!, realm))
                .ConfigureAwait(false);
            progress?.FindingDomainController();
            progress?.FindingComputers();
            var hosts = await RunLdapChildAsync(
                controller, dnsServer, cachePath, configPath, cancellationToken).ConfigureAwait(false);
            progress?.ComputersFound(hosts.Count);
            return hosts;
        }
        finally
        {
            try { File.Delete(cachePath); } catch (IOException) { }
            try { File.Delete(configPath); } catch (IOException) { }
        }
    }

    private static async Task<IReadOnlyList<string>> RunLdapChildAsync(
        string controller,
        IPAddress? dnsServer,
        string cachePath,
        string configPath,
        CancellationToken cancellationToken)
    {
        var processPath = Environment.ProcessPath ?? throw new InvalidOperationException("The scanner executable path is unavailable.");
        var start = new ProcessStartInfo(processPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        if (Path.GetFileNameWithoutExtension(processPath).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            start.ArgumentList.Add(Environment.GetCommandLineArgs()[0]);
        }
        start.ArgumentList.Add("--sift-internal-ldap");
        start.ArgumentList.Add(controller);
        start.ArgumentList.Add(dnsServer?.ToString() ?? string.Empty);
        start.Environment["KRB5CCNAME"] = $"FILE:{cachePath}";
        start.Environment["KRB5_CONFIG"] = configPath;

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start Kerberos LDAP discovery.");
        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            var output = await outputTask.ConfigureAwait(false);
            var error = await errorTask.ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"Kerberos LDAP discovery failed: {error.Trim()}");
            }
            return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(line => Encoding.UTF8.GetString(Convert.FromBase64String(line)))
                .ToArray();
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            throw;
        }
    }

    internal static async Task<int> RunLdapChildCommandAsync(string[] args, CancellationToken cancellationToken)
    {
        if (args.Length != 3 || !args[0].Equals("--sift-internal-ldap", StringComparison.Ordinal))
        {
            return 2;
        }
        try
        {
            var dnsServer = string.IsNullOrEmpty(args[2]) ? null : IPAddress.Parse(args[2]);
            var discovery = new ActiveDirectoryLdapDiscovery(new CliDnsResolver(), new DomainControllerLocator());
            var hosts = await discovery.EnumerateComputersAsync(
                args[1], null, strictKerberos: true, dnsServer, cancellationToken).ConfigureAwait(false);
            foreach (var host in hosts) Console.Out.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(host)));
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    [SupportedOSPlatform("windows")]
    private static Task<string> ResolveWindowsDomainControllerAsync(string? requestedDomainController, CliWindowsCredential? credential) =>
        Task.Run(() => ResolveDomainController(requestedDomainController, credential));

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
