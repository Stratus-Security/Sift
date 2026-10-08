using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using DnsClient;
using Kerberos.NET.Client;

namespace Stratus.Sift.Cli;

/// <summary>Locates an AD domain controller without relying on Windows Netlogon.</summary>
internal sealed class DomainControllerLocator
{
    internal async Task<string?> MatchControllerNameAsync(
        IPAddress address,
        string? domain,
        IPAddress? dnsServer,
        CliDnsResolver dnsResolver,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        await foreach (var host in EnumerateControllerNamesAsync(domain, dnsServer, cancellationToken))
        {
            try
            {
                var addresses = await dnsResolver.ResolveHostAddressesAsync(host, dnsServer, cancellationToken)
                    .ConfigureAwait(false);
                if (addresses.Contains(address))
                {
                    return host;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // A stale controller record must not hide a later matching record.
            }
        }
        return null;
    }

    internal async Task<string> LocateAsync(
        string? requestedController,
        string? domain,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(requestedController))
        {
            return requestedController.Trim().TrimStart('\\').TrimEnd('.');
        }

        var dnsDomain = domain?.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(dnsDomain) && !OperatingSystem.IsWindows())
        {
            try
            {
                var cachePath = PortableKerberosAuthenticationClient.ResolveCredentialCachePath();
                if (File.Exists(cachePath))
                {
                    dnsDomain = new Krb5TicketCache(cachePath).DefaultDomain;
                }
            }
            catch (IOException)
            {
                // No readable ticket cache; report the missing realm below.
            }
        }
        if (string.IsNullOrWhiteSpace(dnsDomain))
        {
            dnsDomain = IPGlobalProperties.GetIPGlobalProperties().DomainName?.Trim().TrimEnd('.');
        }

        if (string.IsNullOrWhiteSpace(dnsDomain))
        {
            throw new InvalidOperationException(
                "Unable to determine the AD DNS domain. Supply --domain with an AD DNS name or --domain-controller.");
        }

        await foreach (var controller in EnumerateControllerNamesAsync(dnsDomain, dnsServer, cancellationToken))
        {
            return controller;
        }

        throw new InvalidOperationException(
            $"No LDAP domain controller SRV record was found for '{dnsDomain}'. Supply --domain-controller.");
    }

    private static async IAsyncEnumerable<string> EnumerateControllerNamesAsync(
        string domain,
        IPAddress? dnsServer,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var client = dnsServer is null ? new LookupClient() : new LookupClient(dnsServer);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var queryName in new[] { $"_ldap._tcp.dc._msdcs.{domain}", $"_ldap._tcp.{domain}" })
        {
            var response = await client.QueryAsync(queryName, QueryType.SRV, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            foreach (var record in response.Answers.SrvRecords()
                .Where(record => record.Port == 389)
                .OrderBy(record => record.Priority)
                .ThenByDescending(record => record.Weight))
            {
                var host = record.Target.Value.TrimEnd('.');
                if (!string.IsNullOrWhiteSpace(host) && seen.Add(host))
                {
                    yield return host;
                }
            }
        }
    }
}
