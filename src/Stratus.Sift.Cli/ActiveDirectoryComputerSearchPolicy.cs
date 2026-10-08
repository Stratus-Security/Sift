namespace Stratus.Sift.Cli;

internal static class ActiveDirectoryComputerSearchPolicy
{
    internal const int PageSize = 500;
    internal const int MaxPageCount = 2_000;

    internal static void AddHost(HashSet<string> hosts, string? dnsHostName, string? name)
    {
        var host = string.IsNullOrWhiteSpace(dnsHostName) ? name : dnsHostName;
        if (!string.IsNullOrWhiteSpace(host))
        {
            hosts.Add(host.Trim().TrimEnd('.'));
        }
    }

    internal static bool HasMorePages(ReadOnlySpan<byte> cookie, HashSet<string> seenCookies)
    {
        if (cookie.IsEmpty)
        {
            return false;
        }

        if (!seenCookies.Add(Convert.ToBase64String(cookie)))
        {
            throw new InvalidOperationException("The LDAP server repeated a paging cookie, so discovery stopped to avoid an infinite loop.");
        }

        return true;
    }

    internal static IReadOnlyList<string> OrderHosts(HashSet<string> hosts) =>
        hosts.OrderBy(host => host, StringComparer.OrdinalIgnoreCase).ToArray();

    internal static InvalidOperationException PageLimitExceeded() =>
        new($"Active Directory discovery exceeded the safety limit of {MaxPageCount:N0} LDAP pages.");
}
