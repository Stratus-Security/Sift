using System.Net.NetworkInformation;
using System.Net;

namespace Stratus.Sift.Cli;

internal sealed record CliWindowsCredential(string UserName, string Password, string? Domain, bool IsLocalMachineAccount)
{
    internal string QualifiedUserName => string.IsNullOrWhiteSpace(Domain)
        ? UserName
        : $@"{Domain}\{UserName}";

    internal string DisplayName => string.IsNullOrWhiteSpace(Domain)
        ? UserName
        : $@"{Domain}\{UserName}";

    internal NetworkCredential ToNetworkCredential() => string.IsNullOrWhiteSpace(Domain)
        ? new NetworkCredential(UserName, Password)
        : new NetworkCredential(UserName, Password, Domain);

    internal static CliWindowsCredential? Create(
        string? userName,
        string? password,
        string? domain,
        bool useLocalMachine = false,
        bool preferDomainAccount = false)
    {
        var trimmedUserName = userName?.Trim();
        var trimmedDomain = domain?.Trim();
        var hasPassword = !string.IsNullOrWhiteSpace(password);

        if (string.IsNullOrWhiteSpace(trimmedUserName) && !hasPassword && string.IsNullOrWhiteSpace(trimmedDomain))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(trimmedUserName) || !hasPassword)
        {
            throw new ArgumentException("Both username and password are required when supplying SMB impersonation credentials.");
        }

        if (useLocalMachine && !string.IsNullOrWhiteSpace(trimmedDomain))
        {
            throw new ArgumentException("Use either --domain or --local, not both.");
        }

        if (!string.IsNullOrWhiteSpace(trimmedDomain) &&
            (trimmedUserName.Contains('\\', StringComparison.Ordinal) || trimmedUserName.Contains('@', StringComparison.Ordinal)))
        {
            throw new ArgumentException("Use either a qualified username or --domain, not both.");
        }

        var isLocalMachineAccount = false;

        if (trimmedUserName.Contains('\\', StringComparison.Ordinal))
        {
            var parts = trimmedUserName.Split('\\', 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[0]) && !string.IsNullOrWhiteSpace(parts[1]))
            {
                trimmedDomain = parts[0];
                trimmedUserName = parts[1];
                if (IsLocalMachineQualifier(trimmedDomain))
                {
                    trimmedDomain = Environment.MachineName;
                    isLocalMachineAccount = true;
                }
            }
        }

        if (trimmedUserName.Contains('@', StringComparison.Ordinal))
        {
            return new CliWindowsCredential(trimmedUserName, password!, null, false);
        }

        if (useLocalMachine)
        {
            trimmedDomain = Environment.MachineName;
            isLocalMachineAccount = true;
        }
        else if (string.IsNullOrWhiteSpace(trimmedDomain) && !preferDomainAccount)
        {
            trimmedDomain = ResolveDefaultDomainOrMachine();
            isLocalMachineAccount = string.Equals(trimmedDomain, Environment.MachineName, StringComparison.OrdinalIgnoreCase);
        }

        return new CliWindowsCredential(trimmedUserName, password!, string.IsNullOrWhiteSpace(trimmedDomain) ? null : trimmedDomain, isLocalMachineAccount);
    }

    private static bool IsLocalMachineQualifier(string value)
    {
        return string.Equals(value, ".", StringComparison.Ordinal)
            || string.Equals(value, "localhost", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Environment.MachineName, StringComparison.OrdinalIgnoreCase);
    }

    private static string ResolveDefaultDomainOrMachine()
    {
        var currentDomain = Environment.UserDomainName?.Trim();
        if (!string.IsNullOrWhiteSpace(currentDomain))
        {
            return currentDomain;
        }

        var dnsDomain = IPGlobalProperties.GetIPGlobalProperties().DomainName?.Trim();
        if (!string.IsNullOrWhiteSpace(dnsDomain))
        {
            return dnsDomain;
        }

        return Environment.MachineName;
    }
}
