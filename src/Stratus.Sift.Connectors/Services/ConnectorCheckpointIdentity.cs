using System.Security.Cryptography;
using System.Text;

namespace Stratus.Sift.Connectors.Services;

internal static class ConnectorCheckpointIdentity
{
    internal static string Create(params string?[] values)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var value in values)
        {
            var bytes = Encoding.UTF8.GetBytes(value?.Trim() ?? string.Empty);
            try
            {
                hash.AppendData(bytes);
                hash.AppendData([0]);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }

        return Convert.ToHexString(hash.GetHashAndReset().AsSpan(0, 16)).ToLowerInvariant();
    }
}
