using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SMBLibrary.Client.Authentication;

namespace Stratus.Sift.Cli;

/// <summary>
/// Bridges an explicitly selected Windows SSPI package into SMBLibrary. The
/// caller chooses Kerberos or NTLM directly so the negotiated protocol is
/// always known and Negotiate cannot perform an invisible fallback.
/// </summary>
internal sealed class SspiSmbAuthenticationClient : IAuthenticationClient, IDisposable
{
    private const int SecPkgCredOutbound = 2;
    private const int SecEOk = 0;
    private const int SecIContinueNeeded = 0x00090312;
    private const int SecICompleteNeeded = 0x00090313;
    private const int SecICompleteAndContinue = 0x00090314;
    private const int SecBufferVersion = 0;
    private const int SecBufferToken = 2;
    private const int SecurityNetworkDrep = 0;
    private const int SecPkgAttrSessionKey = 9;
    private const int SecWinntAuthIdentityUnicode = 2;

    private const uint IscReqReplayDetect = 0x00000004;
    private const uint IscReqSequenceDetect = 0x00000008;
    private const uint IscReqConfidentiality = 0x00000010;
    private const uint IscReqAllocateMemory = 0x00000100;
    private const uint IscReqConnection = 0x00000800;
    private const uint IscReqExtendedError = 0x00004000;
    private const uint IscReqIntegrity = 0x00010000;

    private const uint ContextRequirements =
        IscReqConnection |
        IscReqReplayDetect |
        IscReqSequenceDetect |
        IscReqConfidentiality |
        IscReqIntegrity |
        IscReqExtendedError |
        IscReqAllocateMemory;

    private string _targetName;
    private readonly string? _domain;
    private readonly string? _username;
    private readonly string? _password;
    private readonly string _securityPackage;
    private SecHandle _credentialHandle;
    private SecHandle _contextHandle;
    private bool _hasCredentials;
    private bool _hasContext;
    private bool _disposed;
    private byte[]? _sessionKey;

    internal SspiSmbAuthenticationClient(
        string hostName,
        string securityPackage,
        string? domain = null,
        string? username = null,
        string? password = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);
        _targetName = BuildTargetName(hostName);
        _securityPackage = NormalizeSecurityPackage(securityPackage);
        _domain = domain;
        _username = username;
        _password = password;
    }

    internal bool AuthenticationCompleted { get; private set; }
    internal int? LastSecurityStatus { get; private set; }
    internal string? LastSecurityError => LastSecurityStatus is int status
        ? $"0x{status:X8}: {new Win32Exception(status).Message}"
        : null;
    internal string TargetName => _targetName;
    internal string SecurityPackage => _securityPackage;

    public byte[]? InitializeSecurityContext(byte[]? securityBlob)
    {
        ThrowIfDisposed();
        EnsureCredentials();
        LastSecurityStatus = null;

        var input = securityBlob ?? [];
        var output = CreateOutputBufferDescriptor();
        try
        {
            int status;
            SecHandle newContext;
            if (!_hasContext)
            {
                status = InitializeSecurityContextW(
                    ref _credentialHandle,
                    IntPtr.Zero,
                    _targetName,
                    ContextRequirements,
                    0,
                    SecurityNetworkDrep,
                    IntPtr.Zero,
                    0,
                    out newContext,
                    ref output,
                    out _,
                    out _);
            }
            else
            {
                status = ContinueSecurityContext(input, ref output, out newContext);
            }

            if (IsContextStatus(status))
            {
                _contextHandle = newContext;
                _hasContext = true;
            }

            if (status is SecICompleteNeeded or SecICompleteAndContinue)
            {
                var completionStatus = CompleteAuthToken(ref _contextHandle, ref output);
                if (completionStatus != SecEOk)
                {
                    LastSecurityStatus = completionStatus;
                    return null;
                }
            }

            var token = ExtractOutputToken(output);
            if (status == SecEOk)
            {
                AuthenticationCompleted = true;
                _sessionKey ??= QuerySessionKey();
                return token ?? [];
            }

            if (status is SecIContinueNeeded or SecICompleteNeeded or SecICompleteAndContinue)
            {
                return token ?? [];
            }

            LastSecurityStatus = status;
            return null;
        }
        finally
        {
            FreeOutputBufferDescriptor(output);
        }
    }

    public byte[] GetSessionKey()
    {
        ThrowIfDisposed();
        _sessionKey ??= QuerySessionKey();
        return NormalizeSmbSessionKey(_sessionKey);
    }

    internal static byte[] NormalizeSmbSessionKey(byte[]? sessionKey)
    {
        if (sessionKey is not { Length: > 0 })
        {
            return [];
        }

        // Kerberos AES contexts commonly expose a 32-byte SSPI session key.
        // SMB 2/3 uses the first 16 bytes as Session.SessionKey for signing and
        // encryption key derivation; passing the full key makes the server
        // reject the first signed request after SESSION_SETUP.
        return sessionKey.AsSpan(0, Math.Min(16, sessionKey.Length)).ToArray();
    }

    public void ResetSecurityContext(string serverName)
    {
        ThrowIfDisposed();
        DeleteExistingContext();
        AuthenticationCompleted = false;
        LastSecurityStatus = null;
        _targetName = BuildTargetName(serverName);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        DeleteExistingContext();
        if (_hasCredentials)
        {
            FreeCredentialsHandle(ref _credentialHandle);
            _hasCredentials = false;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private int ContinueSecurityContext(byte[] input, ref SecBufferDesc output, out SecHandle newContext)
    {
        var inputToken = IntPtr.Zero;
        var inputBufferPointer = IntPtr.Zero;
        try
        {
            inputToken = Marshal.AllocHGlobal(input.Length);
            if (input.Length > 0)
            {
                Marshal.Copy(input, 0, inputToken, input.Length);
            }

            var inputBuffer = new SecBuffer
            {
                BufferLength = input.Length,
                BufferType = SecBufferToken,
                Buffer = inputToken
            };
            inputBufferPointer = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>());
            Marshal.StructureToPtr(inputBuffer, inputBufferPointer, false);
            var inputDescriptor = new SecBufferDesc
            {
                Version = SecBufferVersion,
                BufferCount = 1,
                Buffers = inputBufferPointer
            };

            return InitializeSecurityContextW(
                ref _credentialHandle,
                ref _contextHandle,
                _targetName,
                ContextRequirements,
                0,
                SecurityNetworkDrep,
                ref inputDescriptor,
                0,
                out newContext,
                ref output,
                out _,
                out _);
        }
        finally
        {
            if (inputBufferPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(inputBufferPointer);
            }

            if (inputToken != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(inputToken);
            }
        }
    }

    private void EnsureCredentials()
    {
        if (_hasCredentials)
        {
            return;
        }

        var authData = IntPtr.Zero;
        var userPointer = IntPtr.Zero;
        var domainPointer = IntPtr.Zero;
        var passwordPointer = IntPtr.Zero;
        try
        {
            if (!string.IsNullOrWhiteSpace(_username))
            {
                userPointer = Marshal.StringToHGlobalUni(_username);
                domainPointer = Marshal.StringToHGlobalUni(_domain ?? string.Empty);
                passwordPointer = Marshal.StringToHGlobalUni(_password ?? string.Empty);
                var identity = new SecWinntAuthIdentity
                {
                    User = userPointer,
                    UserLength = _username.Length,
                    Domain = domainPointer,
                    DomainLength = (_domain ?? string.Empty).Length,
                    Password = passwordPointer,
                    PasswordLength = (_password ?? string.Empty).Length,
                    Flags = SecWinntAuthIdentityUnicode
                };
                authData = Marshal.AllocHGlobal(Marshal.SizeOf<SecWinntAuthIdentity>());
                Marshal.StructureToPtr(identity, authData, false);
            }

            var status = AcquireCredentialsHandleW(
                null,
                _securityPackage,
                SecPkgCredOutbound,
                IntPtr.Zero,
                authData,
                IntPtr.Zero,
                IntPtr.Zero,
                out _credentialHandle,
                out _);
            if (status != SecEOk)
            {
                throw new InvalidOperationException($"AcquireCredentialsHandleW({_securityPackage}) failed with 0x{status:X8}: {new Win32Exception(status).Message}");
            }

            _hasCredentials = true;
        }
        finally
        {
            if (authData != IntPtr.Zero) Marshal.FreeHGlobal(authData);
            if (userPointer != IntPtr.Zero) Marshal.FreeHGlobal(userPointer);
            if (domainPointer != IntPtr.Zero) Marshal.FreeHGlobal(domainPointer);
            if (passwordPointer != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(passwordPointer);
        }
    }

    private byte[]? QuerySessionKey()
    {
        if (!_hasContext)
        {
            return null;
        }

        var status = QueryContextAttributesW(ref _contextHandle, SecPkgAttrSessionKey, out var sessionKey);
        if (status != SecEOk || sessionKey.SessionKey == IntPtr.Zero || sessionKey.SessionKeyLength <= 0)
        {
            return null;
        }

        try
        {
            var result = new byte[sessionKey.SessionKeyLength];
            Marshal.Copy(sessionKey.SessionKey, result, 0, result.Length);
            return result;
        }
        finally
        {
            FreeContextBuffer(sessionKey.SessionKey);
        }
    }

    private void DeleteExistingContext()
    {
        if (_hasContext)
        {
            DeleteSecurityContext(ref _contextHandle);
            _contextHandle = default;
            _hasContext = false;
        }

        if (_sessionKey != null)
        {
            CryptographicOperations.ZeroMemory(_sessionKey);
            _sessionKey = null;
        }
    }

    private static string BuildTargetName(string serverName)
    {
        var target = string.IsNullOrWhiteSpace(serverName)
            ? "unknown"
            : serverName.Trim().TrimStart('\\').TrimEnd('.');
        return target.StartsWith("cifs/", StringComparison.OrdinalIgnoreCase) ? target : $"cifs/{target}";
    }

    private static string NormalizeSecurityPackage(string securityPackage)
    {
        if (securityPackage.Equals("Kerberos", StringComparison.OrdinalIgnoreCase)) return "Kerberos";
        if (securityPackage.Equals("NTLM", StringComparison.OrdinalIgnoreCase)) return "NTLM";
        throw new ArgumentException("The SMB SSPI package must be Kerberos or NTLM.", nameof(securityPackage));
    }

    private static SecBufferDesc CreateOutputBufferDescriptor()
    {
        var bufferPointer = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>());
        Marshal.StructureToPtr(new SecBuffer { BufferType = SecBufferToken }, bufferPointer, false);
        return new SecBufferDesc
        {
            Version = SecBufferVersion,
            BufferCount = 1,
            Buffers = bufferPointer
        };
    }

    private static byte[]? ExtractOutputToken(SecBufferDesc descriptor)
    {
        if (descriptor.Buffers == IntPtr.Zero)
        {
            return null;
        }

        var buffer = Marshal.PtrToStructure<SecBuffer>(descriptor.Buffers);
        if (buffer.BufferLength <= 0 || buffer.Buffer == IntPtr.Zero)
        {
            return null;
        }

        var token = new byte[buffer.BufferLength];
        Marshal.Copy(buffer.Buffer, token, 0, token.Length);
        return token;
    }

    private static void FreeOutputBufferDescriptor(SecBufferDesc descriptor)
    {
        if (descriptor.Buffers == IntPtr.Zero)
        {
            return;
        }

        var buffer = Marshal.PtrToStructure<SecBuffer>(descriptor.Buffers);
        if (buffer.Buffer != IntPtr.Zero)
        {
            FreeContextBuffer(buffer.Buffer);
        }

        Marshal.FreeHGlobal(descriptor.Buffers);
    }

    private static bool IsContextStatus(int status) =>
        status is SecEOk or SecIContinueNeeded or SecICompleteNeeded or SecICompleteAndContinue;

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecHandle
    {
        public IntPtr Lower;
        public IntPtr Upper;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityInteger
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecBuffer
    {
        public int BufferLength;
        public int BufferType;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecBufferDesc
    {
        public int Version;
        public int BufferCount;
        public IntPtr Buffers;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecPkgContextSessionKey
    {
        public int SessionKeyLength;
        public IntPtr SessionKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecWinntAuthIdentity
    {
        public IntPtr User;
        public int UserLength;
        public IntPtr Domain;
        public int DomainLength;
        public IntPtr Password;
        public int PasswordLength;
        public int Flags;
    }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern int AcquireCredentialsHandleW(
        string? principal,
        string package,
        int credentialUse,
        IntPtr logonId,
        IntPtr authData,
        IntPtr getKeyFunction,
        IntPtr getKeyArgument,
        out SecHandle credential,
        out SecurityInteger expiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern int InitializeSecurityContextW(
        ref SecHandle credential,
        IntPtr context,
        string targetName,
        uint contextRequirements,
        uint reserved1,
        int targetDataRepresentation,
        IntPtr input,
        uint reserved2,
        out SecHandle newContext,
        ref SecBufferDesc output,
        out uint contextAttributes,
        out SecurityInteger expiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern int InitializeSecurityContextW(
        ref SecHandle credential,
        ref SecHandle context,
        string targetName,
        uint contextRequirements,
        uint reserved1,
        int targetDataRepresentation,
        ref SecBufferDesc input,
        uint reserved2,
        out SecHandle newContext,
        ref SecBufferDesc output,
        out uint contextAttributes,
        out SecurityInteger expiry);

    [DllImport("secur32.dll")]
    private static extern int QueryContextAttributesW(
        ref SecHandle context,
        int attribute,
        out SecPkgContextSessionKey buffer);

    [DllImport("secur32.dll")]
    private static extern int DeleteSecurityContext(ref SecHandle context);

    [DllImport("secur32.dll")]
    private static extern int FreeCredentialsHandle(ref SecHandle credential);

    [DllImport("secur32.dll")]
    private static extern int FreeContextBuffer(IntPtr contextBuffer);

    [DllImport("secur32.dll")]
    private static extern int CompleteAuthToken(ref SecHandle context, ref SecBufferDesc token);
}
