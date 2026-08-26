using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Stratus.Sift.Cli;

[SupportedOSPlatform("windows")]
internal sealed partial class WindowsImpersonationSession : IDisposable
{
    private const int Logon32ProviderWinNt50 = 3;
    private const int Logon32LogonNewCredentials = 9;

    private readonly SafeAccessTokenHandle? _accessToken;

    private WindowsImpersonationSession(SafeAccessTokenHandle? accessToken)
    {
        _accessToken = accessToken;
    }

    internal static WindowsImpersonationSession Create(CliWindowsCredential? credential)
    {
        if (credential is null)
        {
            return new WindowsImpersonationSession(null);
        }

        if (credential.UsesNtHash)
        {
            throw new InvalidOperationException("Windows impersonation does not accept an NT hash. Use the managed SMB authentication path.");
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows impersonation is only supported on Windows.");
        }

        if (!LogonUser(
                credential.UserName,
                credential.Domain,
                credential.Password!,
                Logon32LogonNewCredentials,
                Logon32ProviderWinNt50,
                out var accessToken))
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            throw new InvalidOperationException($"Unable to impersonate '{credential.DisplayName}': {error.Message}", error);
        }

        return new WindowsImpersonationSession(accessToken);
    }

    internal Task RunAsync(Func<Task> action)
    {
        return _accessToken is null
            ? action()
            : WindowsIdentity.RunImpersonatedAsync(_accessToken, action);
    }

    internal Task<T> RunAsync<T>(Func<Task<T>> action)
    {
        return _accessToken is null
            ? action()
            : WindowsIdentity.RunImpersonatedAsync(_accessToken, action);
    }

    public void Dispose()
    {
        _accessToken?.Dispose();
    }

    [LibraryImport("advapi32.dll", EntryPoint = "LogonUserW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LogonUser(
        string lpszUsername,
        string? lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out SafeAccessTokenHandle phToken);
}
