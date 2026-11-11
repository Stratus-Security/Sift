using System.Net;
using System.Net.Sockets;
using SMBLibrary;
using SMBLibrary.Client;
using Stratus.Sift.Cli;

namespace Stratus.Sift.Cli.Tests;

public sealed class SmbClientTransportTests
{
    [Fact]
    public async Task AbortClosesRealSocket_BeforeNegotiationSetsConnectedFlag()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var client = new TestClient();
        var connecting = Task.Run(() => client.ConnectTo(((IPEndPoint)listener.LocalEndpoint).Port));
        try
        {
            using var peer = await listener.AcceptSocketAsync().WaitAsync(TimeSpan.FromSeconds(10));
            var request = new byte[4096];
            Assert.True(await peer.ReceiveAsync(request.AsMemory(), SocketFlags.None).AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10)) > 0);
            // The TCP connection exists, but SMB negotiation has no response.
            // Public Disconnect is a no-op while the SDK flag is still false.
            Assert.False(client.IsConnected);
            client.Disconnect();
            Assert.False(connecting.IsCompleted);
            SmbClientTransport.Abort(client);
            Assert.False(await connecting.WaitAsync(TimeSpan.FromSeconds(2)));
            SmbClientTransport.Abort(client); // Repeated cleanup is safe.
        }
        finally { SmbClientTransport.Abort(client); }
    }

    [Fact]
    public void AbortBeforeConnect_IsSafe()
    {
        SmbClientTransport.Abort(new SMB2Client());
    }

    private sealed class TestClient() : SMB2Client(60_000)
    {
        internal bool ConnectTo(int port) => Connect(IPAddress.Loopback, SMBTransportType.DirectTCPTransport, port);
    }
}
