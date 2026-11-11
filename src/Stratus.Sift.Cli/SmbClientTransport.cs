using System.Net.Sockets;
using System.Runtime.CompilerServices;
using SMBLibrary.Client;

namespace Stratus.Sift.Cli;

internal static class SmbClientTransport
{
    internal static void Abort(SMB2Client client)
    {
        // SMBLibrary's Disconnect checks IsConnected and takes the receive-buffer
        // lock before closing the socket. Neither is safe for interrupting a
        // stalled connect/read or cleaning up a client marked disconnected by a
        // send failure. Close the owned socket without waiting on that lock.
        try { GetSocket(client)?.Dispose(); }
        catch (ObjectDisposedException) { }
    }

    // Deliberately tied to the pinned SMBLibrary version. The loopback transport
    // tests verify the field contract; UnsafeAccessor also works in Native AOT.
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "m_clientSocket")]
    private static extern ref Socket? GetSocket(SMB2Client client);
}
