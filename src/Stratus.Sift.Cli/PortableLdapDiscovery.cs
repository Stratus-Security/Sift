using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Novell.Directory.Ldap;
using Novell.Directory.Ldap.Controls;

namespace Stratus.Sift.Cli;

internal static class PortableLdapDiscovery
{
    internal static async Task<IReadOnlyList<string>> EnumerateComputersAsync(
        string connectionTarget,
        string certificateHostName,
        CliWindowsCredential credential,
        Action<int>? onComputersFound,
        CancellationToken cancellationToken)
    {
        var options = new LdapConnectionOptions()
            .UseSsl()
            .ConfigureRemoteCertificateValidationCallback((_, certificate, _, errors) =>
                VerifyControllerCertificate(certificate, certificateHostName, errors));
        using var connection = new Novell.Directory.Ldap.LdapConnection(options);
        await connection.ConnectAsync(connectionTarget, Novell.Directory.Ldap.LdapConnection.DefaultSslPort, cancellationToken)
            .ConfigureAwait(false);
        var principal = credential.UserName.Contains('@', StringComparison.Ordinal)
            ? credential.UserName
            : $"{credential.UserName}@{credential.Domain}";
        await connection.BindAsync(principal, credential.Password!, cancellationToken).ConfigureAwait(false);

        var root = await connection.SearchAsync(string.Empty, Novell.Directory.Ldap.LdapConnection.ScopeBase,
            "(objectClass=*)", ["defaultNamingContext"], false, cancellationToken).ConfigureAwait(false);
        var namingContext = string.Empty;
        while (await root.HasMoreAsync(cancellationToken).ConfigureAwait(false))
        {
            namingContext = (await root.NextAsync(cancellationToken).ConfigureAwait(false))
                .GetStringValueOrDefault("defaultNamingContext", string.Empty);
        }
        if (string.IsNullOrWhiteSpace(namingContext))
        {
            throw new InvalidOperationException("The LDAP server did not return a default naming context.");
        }

        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenCookies = new HashSet<string>(StringComparer.Ordinal);
        byte[] cookie = [];
        for (var pageNumber = 1; pageNumber <= ActiveDirectoryComputerSearchPolicy.MaxPageCount; pageNumber++)
        {
            var constraints = connection.SearchConstraints;
            constraints.ReferralFollowing = false;
            constraints.SetControls(new SimplePagedResultsControl(ActiveDirectoryComputerSearchPolicy.PageSize, cookie));
            var results = await connection.SearchAsync(namingContext, Novell.Directory.Ldap.LdapConnection.ScopeSub,
                ActiveDirectoryLdapDiscovery.EnabledComputerFilter, ["dNSHostName", "name"], false,
                constraints, cancellationToken).ConfigureAwait(false);
            while (await results.HasMoreAsync(cancellationToken).ConfigureAwait(false))
            {
                LdapEntry entry;
                try
                {
                    entry = await results.NextAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (LdapReferralException)
                {
                    // AD emits continuation references for other naming contexts.
                    continue;
                }
                var dnsHostName = entry.GetStringValueOrDefault("dNSHostName", string.Empty);
                ActiveDirectoryComputerSearchPolicy.AddHost(
                    hosts, dnsHostName,
                    string.IsNullOrWhiteSpace(dnsHostName) ? entry.GetStringValueOrDefault("name", string.Empty) : null);
            }
            onComputersFound?.Invoke(hosts.Count);
            cookie = results.ResponseControls?.OfType<SimplePagedResultsControl>().FirstOrDefault()?.Cookie ?? [];
            if (!ActiveDirectoryComputerSearchPolicy.HasMorePages(cookie, seenCookies))
            {
                return ActiveDirectoryComputerSearchPolicy.OrderHosts(hosts);
            }
        }
        throw ActiveDirectoryComputerSearchPolicy.PageLimitExceeded();
    }

    internal static bool VerifyControllerCertificate(X509Certificate? certificate, string hostName, SslPolicyErrors errors)
    {
        if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateNameMismatch) != SslPolicyErrors.None)
        {
            return false;
        }
        using var parsed = new X509Certificate2(certificate);
        return parsed.MatchesHostname(hostName);
    }
}
