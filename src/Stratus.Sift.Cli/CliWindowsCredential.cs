using System.Net.NetworkInformation;
using System.Net;
using System.Security.Cryptography;

namespace Stratus.Sift.Cli;

internal sealed record CliWindowsCredential(
    string UserName,
    string? Password,
    byte[]? NtHash,
    string? Domain,
    bool IsLocalMachineAccount) : IDisposable
{
    internal string QualifiedUserName => string.IsNullOrWhiteSpace(Domain)
        ? UserName
        : $@"{Domain}\{UserName}";

    internal string DisplayName => string.IsNullOrWhiteSpace(Domain)
        ? UserName
        : $@"{Domain}\{UserName}";

    internal bool UsesNtHash => NtHash is { Length: 16 };

    internal NetworkCredential ToNetworkCredential()
    {
        if (UsesNtHash)
        {
            throw new InvalidOperationException("An NT hash cannot be used with Windows password-based authentication.");
        }

        return string.IsNullOrWhiteSpace(Domain)
            ? new NetworkCredential(UserName, Password)
            : new NetworkCredential(UserName, Password, Domain);
    }

    internal static CliWindowsCredential? Create(
        string? userName,
        string? password,
        string? domain,
        bool useLocalMachine = false,
        bool preferDomainAccount = false,
        string? ntHash = null)
    {
        var trimmedUserName = userName?.Trim();
        var trimmedDomain = domain?.Trim();
        var hasPassword = !string.IsNullOrWhiteSpace(password);
        var hasNtHash = !string.IsNullOrWhiteSpace(ntHash);

        if (string.IsNullOrWhiteSpace(trimmedUserName) && !hasPassword && !hasNtHash && string.IsNullOrWhiteSpace(trimmedDomain))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(trimmedUserName) || hasPassword == hasNtHash)
        {
            throw new ArgumentException("Supply a username and exactly one of password or NT hash for SMB authentication.");
        }

        var parsedNtHash = hasNtHash ? ParseNtHash(ntHash!) : null;

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
            return new CliWindowsCredential(trimmedUserName, password, parsedNtHash, null, false);
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

        return new CliWindowsCredential(
            trimmedUserName,
            password,
            parsedNtHash,
            string.IsNullOrWhiteSpace(trimmedDomain) ? null : trimmedDomain,
            isLocalMachineAccount);
    }

    internal static bool IsValidNtHash(string? value)
    {
        if (value is null || value.Length != 32)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] ParseNtHash(string value)
    {
        var trimmed = value.Trim();
        if (!IsValidNtHash(trimmed))
        {
            throw new ArgumentException("The NT hash must be exactly 32 hexadecimal characters.", nameof(value));
        }

        return Convert.FromHexString(trimmed);
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

    public void Dispose()
    {
        if (NtHash is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(NtHash);
        }
    }
}
