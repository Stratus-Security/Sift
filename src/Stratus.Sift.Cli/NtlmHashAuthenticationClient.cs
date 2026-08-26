using System.Security.Cryptography;
using System.Text;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.Authentication.NTLM;
using SMBLibrary.Client;
using SMBLibrary.Client.Authentication;
using Utilities;

namespace Stratus.Sift.Cli;

/// <summary>
/// Performs an NTLMv2 SMB client exchange from an NT hash. The supplied hash
/// is used only as the NTOWFv1 key and is never converted to password text.
/// </summary>
internal sealed class NtlmHashAuthenticationClient : NTLMAuthenticationClient, IDisposable
{
    private readonly string _domain;
    private readonly string _userName;
    private readonly bool _useServerTargetAsDomain;
    private readonly byte[] _ntHash;
    private string _spn;
    private byte[]? _negotiateMessage;
    private byte[]? _sessionKey;
    private bool _disposed;

    internal NtlmHashAuthenticationClient(
        string? domain,
        string userName,
        ReadOnlySpan<byte> ntHash,
        string spn,
        bool useServerTargetAsDomain)
        : base(domain ?? string.Empty, userName, string.Empty, spn, AuthenticationMethod.NTLMv2)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentException.ThrowIfNullOrWhiteSpace(spn);
        if (ntHash.Length != 16)
        {
            throw new ArgumentException("An NT hash must contain exactly 16 bytes.", nameof(ntHash));
        }

        _domain = domain ?? string.Empty;
        _userName = userName;
        _spn = spn;
        _useServerTargetAsDomain = useServerTargetAsDomain;
        _ntHash = ntHash.ToArray();
    }

    protected override byte[] CreateNegotiateMessage()
    {
        ThrowIfDisposed();
        _negotiateMessage = NTLMAuthenticationHelper.GetNegotiateMessage(
            isAnonymous: false,
            AuthenticationMethod.NTLMv2,
            requestSeal: false);
        return _negotiateMessage;
    }

    protected override byte[] GetAuthenticateMessage(byte[] securityBlob)
    {
        ThrowIfDisposed();
        if (_negotiateMessage is null)
        {
            throw new InvalidOperationException("The NTLM negotiate message has not been created.");
        }

        var useSpnego = false;
        var challengeBytes = securityBlob;
        try
        {
            if (SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, false) is SimpleProtectedNegotiationTokenResponse token &&
                token.ResponseToken is { Length: > 0 })
            {
                challengeBytes = token.ResponseToken;
                useSpnego = true;
            }
        }
        catch (Exception)
        {
            // A raw NTLM challenge is valid when SPNEGO is not in use.
        }

        if (!AuthenticationMessageUtils.IsSignatureValid(challengeBytes) ||
            AuthenticationMessageUtils.GetMessageType(challengeBytes) != MessageTypeName.Challenge)
        {
            throw new InvalidOperationException("The SMB server did not return a valid NTLM challenge.");
        }

        var challenge = new ChallengeMessage(challengeBytes);
        var domain = _useServerTargetAsDomain && !string.IsNullOrWhiteSpace(challenge.TargetName)
            ? challenge.TargetName
            : _domain;
        var clientChallenge = RandomNumberGenerator.GetBytes(8);
        var challengeStructure = new NTLMv2ClientChallenge(
            DateTime.UtcNow,
            clientChallenge,
            challenge.TargetInfo,
            _spn);
        var challengeBlob = challengeStructure.GetBytesPadded();
        var responseKeyNt = ComputeResponseKeyNt(_ntHash, _userName, domain);
        var responseKeyLm = ComputeResponseKeyNt(
            _ntHash,
            _userName,
            string.IsNullOrWhiteSpace(challenge.TargetName) ? domain : challenge.TargetName);
        var serverAndBlob = ByteUtils.Concatenate(challenge.ServerChallenge, challengeBlob);
        var serverAndClientChallenge = ByteUtils.Concatenate(challenge.ServerChallenge, clientChallenge);
        var ntProof = HMACMD5.HashData(responseKeyNt, serverAndBlob);
        var lmProof = HMACMD5.HashData(responseKeyLm, serverAndClientChallenge);
        var sessionBaseKey = HMACMD5.HashData(responseKeyNt, ntProof);

        try
        {
            var message = new AuthenticateMessage
            {
                NegotiateFlags = CreateAuthenticateFlags(challenge.NegotiateFlags),
                UserName = _userName,
                DomainName = domain,
                WorkStation = Environment.MachineName,
                LmChallengeResponse = ByteUtils.Concatenate(lmProof, clientChallenge),
                NtChallengeResponse = ByteUtils.Concatenate(ntProof, challengeBlob),
                Version = NTLMVersion.Server2003
            };

            ClearSessionKey();
            _sessionKey = sessionBaseKey.ToArray();
            if ((challenge.NegotiateFlags & NegotiateFlags.KeyExchange) != 0)
            {
                RandomNumberGenerator.Fill(_sessionKey);
                message.EncryptedRandomSessionKey = RC4.Encrypt(sessionBaseKey, _sessionKey);
            }

            message.CalculateMIC(_sessionKey, _negotiateMessage, challengeBytes);
            var authenticateBytes = message.GetBytes();
            if (!useSpnego)
            {
                return authenticateBytes;
            }

            var mechanisms = new List<byte[]> { GSSProvider.NTLMSSPIdentifier };
            var mechanismList = SimpleProtectedNegotiationTokenInit.GetMechanismTypeListBytes(mechanisms);
            return new SimpleProtectedNegotiationTokenResponse
            {
                ResponseToken = authenticateBytes,
                MechanismListMIC = NTLMCryptography.ComputeMechListMIC(_sessionKey, mechanismList)
            }.GetBytes();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(responseKeyNt);
            CryptographicOperations.ZeroMemory(responseKeyLm);
            CryptographicOperations.ZeroMemory(sessionBaseKey);
        }
    }

    public override byte[] GetSessionKey()
    {
        ThrowIfDisposed();
        return _sessionKey ?? [];
    }

    public override void ResetSecurityContext(string spn)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(spn);
        base.ResetSecurityContext(spn);
        _spn = spn;
        ClearSessionKey();
        _negotiateMessage = null;
    }

    internal static byte[] ComputeResponseKeyNt(ReadOnlySpan<byte> ntHash, string userName, string domain)
    {
        if (ntHash.Length != 16)
        {
            throw new ArgumentException("An NT hash must contain exactly 16 bytes.", nameof(ntHash));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        var identity = Encoding.Unicode.GetBytes(userName.ToUpperInvariant() + (domain ?? string.Empty));
        return HMACMD5.HashData(ntHash, identity);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        ClearSessionKey();
        if (_negotiateMessage is not null)
        {
            CryptographicOperations.ZeroMemory(_negotiateMessage);
            _negotiateMessage = null;
        }

        CryptographicOperations.ZeroMemory(_ntHash);
        _disposed = true;
    }

    private static NegotiateFlags CreateAuthenticateFlags(NegotiateFlags serverFlags)
    {
        var flags = NegotiateFlags.Sign |
                    NegotiateFlags.NTLMSessionSecurity |
                    NegotiateFlags.AlwaysSign |
                    NegotiateFlags.Version |
                    NegotiateFlags.Use128BitEncryption |
                    NegotiateFlags.Use56BitEncryption |
                    NegotiateFlags.ExtendedSessionSecurity;
        flags |= (serverFlags & NegotiateFlags.UnicodeEncoding) != 0
            ? NegotiateFlags.UnicodeEncoding
            : NegotiateFlags.OEMEncoding;

        if ((serverFlags & NegotiateFlags.Seal) != 0)
        {
            flags |= NegotiateFlags.Seal;
        }

        if ((serverFlags & NegotiateFlags.KeyExchange) != 0)
        {
            flags |= NegotiateFlags.KeyExchange;
        }

        return flags;
    }

    private void ClearSessionKey()
    {
        if (_sessionKey is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_sessionKey);
        _sessionKey = null;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
