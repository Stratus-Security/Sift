using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using SMBLibrary.Client.Authentication;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace Stratus.Sift.Cli;

/// <summary>Supplies SMBLibrary with Kerberos tokens and the SMB signing session key on Unix.</summary>
internal sealed class PortableKerberosAuthenticationClient : IAuthenticationClient, IDisposable
{
    private readonly KerberosClient _client;
    private string _spn;
    private byte[]? _sessionKey;

    static PortableKerberosAuthenticationClient() => PreserveAotCollections();

    [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(List<PaDataType>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(List<EncryptionType>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(List<string>))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(List<SpakePreAuthGroupType>))]
    internal PortableKerberosAuthenticationClient(
        string hostName,
        string? realm,
        string? kdcHost,
        string? userName,
        string? password)
    {
        _spn = $"cifs/{hostName}";
        _client = new KerberosClient();
        if (userName is null)
        {
            var cachePath = ResolveCredentialCachePath();
            if (!File.Exists(cachePath))
            {
                throw new InvalidOperationException($"No Kerberos FILE ticket cache was found at '{cachePath}'. Obtain a ticket first or supply a password.");
            }
            _client.Cache = new Krb5TicketCache(cachePath) { PersistChanges = false };
        }
        if (!string.IsNullOrWhiteSpace(realm) && !string.IsNullOrWhiteSpace(kdcHost))
        {
            _client.PinKdc(realm, kdcHost);
        }

        if (userName is not null)
        {
            if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(realm))
            {
                throw new InvalidOperationException("Kerberos requires a password and AD DNS domain for the supplied account.");
            }

            _client.Authenticate(new KerberosPasswordCredential(userName, password, realm))
                .GetAwaiter().GetResult();
        }
    }

    public byte[]? InitializeSecurityContext(byte[]? securityBlob)
    {
        var ticket = _client.GetServiceTicket(_spn).GetAwaiter().GetResult();
        var cacheEntry = (KerberosClientCacheEntry)_client.Cache.GetCacheItem(_spn);
        _sessionKey = cacheEntry.SessionKey.KeyValue.ToArray();
        return ticket.EncodeGssApi().ToArray();
    }

    public byte[] GetSessionKey() => _sessionKey is null
        ? throw new InvalidOperationException("The Kerberos service ticket has not been acquired.")
        : SspiSmbAuthenticationClient.NormalizeSmbSessionKey(_sessionKey);

    public void ResetSecurityContext(string serverName)
    {
        _spn = serverName.StartsWith("cifs/", StringComparison.OrdinalIgnoreCase)
            ? serverName
            : $"cifs/{serverName}";
        _sessionKey = null;
    }

    public void Dispose()
    {
        if (_sessionKey is not null)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(_sessionKey);
        }
        _client.Dispose();
    }

    internal static string ResolveCredentialCachePath()
    {
        var configured = Environment.GetEnvironmentVariable("KRB5CCNAME");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            if (configured.StartsWith("FILE:", StringComparison.OrdinalIgnoreCase))
            {
                return configured[5..];
            }
            if (!configured.Contains(':', StringComparison.Ordinal))
            {
                return configured;
            }
            throw new InvalidOperationException(
                $"Kerberos ticket cache '{configured.Split(':')[0]}' is not supported. Set KRB5CCNAME to a FILE cache.");
        }

        return $"/tmp/krb5cc_{GetEffectiveUserId()}";
    }

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    private static void PreserveAotCollections()
    {
        // Kerberos.NET creates these configuration collections by reflection;
        // explicit construction keeps their constructors in native AOT builds.
        _ = Activator.CreateInstance(typeof(List<PaDataType>));
        _ = Activator.CreateInstance(typeof(List<EncryptionType>));
        _ = Activator.CreateInstance(typeof(List<string>));
        _ = Activator.CreateInstance(typeof(List<SpakePreAuthGroupType>));
        _ = Activator.CreateInstance(typeof(Dictionary<string, Krb5RealmConfig>));
        _ = Activator.CreateInstance(typeof(Dictionary<string, string>));
        _ = Activator.CreateInstance(typeof(Dictionary<string, IDictionary<string, string>>));
    }
}
