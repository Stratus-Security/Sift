using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Stratus.Sift.Cli.Tests;

public sealed class CliDnsResolverTests
{
    [Theory]
    [InlineData("192.168.10.10", true)]
    [InlineData("2001:db8::53", true)]
    [InlineData("dns.example.test", false)]
    [InlineData("192.168.10.10:53", false)]
    [InlineData("udp://192.168.10.10", false)]
    [InlineData("", false)]
    public void IsValidServer_RequiresLiteralIpAddress(string value, bool expected)
    {
        Assert.Equal(expected, CliDnsResolver.IsValidServer(value));
    }

    [Fact]
    public void CreateReverseLookupName_FormatsIpv4()
    {
        Assert.Equal("10.10.168.192.in-addr.arpa", CliDnsResolver.CreateReverseLookupName(IPAddress.Parse("192.168.10.10")));
    }

    [Fact]
    public void CreateReverseLookupName_FormatsIpv6Nibbles()
    {
        var name = CliDnsResolver.CreateReverseLookupName(IPAddress.Parse("2001:db8::1"));

        Assert.EndsWith(".ip6.arpa", name, StringComparison.Ordinal);
        Assert.StartsWith("1.0.0.0.", name, StringComparison.Ordinal);
        Assert.Equal(32, name.Split(".ip6.arpa", StringSplitOptions.None)[0].Split('.').Length);
    }

    [Theory]
    [InlineData("192.0.2.42", "192.0.2.42")]
    [InlineData("2001:db8::42", "2001-db8--42.ipv6-literal.net")]
    public void FormatUncHost_UsesDnsFreeLiteralForm(string address, string expected)
    {
        Assert.Equal(expected, SmbDiscoveryService.FormatUncHost(IPAddress.Parse(address)));
    }

    [Fact]
    public void ExplicitUncTarget_IsRewrittenBeforeWindowsReceivesIt()
    {
        var roots = SmbDiscoveryService.CreateExplicitShareRoots(
            @"\\only-on-test-dns.example\Finance",
            [IPAddress.Parse("192.0.2.42"), IPAddress.Parse("2001:db8::42")]);

        Assert.Contains(@"\\192.0.2.42\Finance", roots);
        Assert.Contains(@"\\2001-db8--42.ipv6-literal.net\Finance", roots);
    }

    [Fact]
    public async Task ExplicitServer_ResolvesAAndAaaaWithoutSystemDns()
    {
        await using var server = await TestDnsServer.StartAsync();
        var resolver = new CliDnsResolver();

        var addresses = await resolver.ResolveHostAddressesAsync("only-on-test-dns.example", server.Endpoint, CancellationToken.None);

        Assert.Equal([IPAddress.Parse("192.0.2.42"), IPAddress.Parse("2001:db8::42")], addresses);
        Assert.Contains(server.Queries, query => query is ("only-on-test-dns.example", CliDnsResolver.DnsRecordType.A, "udp"));
        Assert.Contains(server.Queries, query => query is ("only-on-test-dns.example", CliDnsResolver.DnsRecordType.Aaaa, "udp"));
    }

    [Fact]
    public async Task ExplicitServer_NxdomainDoesNotFallBackToResolvableLocalName()
    {
        await using var server = await TestDnsServer.StartAsync(returnNxDomain: true);
        var resolver = new CliDnsResolver();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            resolver.ResolveHostAddressesAsync("localhost", server.Endpoint, CancellationToken.None));

        Assert.Contains("Local DNS was not consulted", exception.Message, StringComparison.Ordinal);
        Assert.Contains(server.Queries, query => query.Name == "localhost");
    }

    [Fact]
    public async Task ExplicitServer_ResolvesPtrWithoutSystemDns()
    {
        await using var server = await TestDnsServer.StartAsync();
        var resolver = new CliDnsResolver();

        var hostName = await resolver.ResolveHostNameAsync(IPAddress.Parse("192.0.2.42"), server.Endpoint, CancellationToken.None);

        Assert.Equal("host42.example.test", hostName);
        Assert.Contains(server.Queries, query => query.Type == CliDnsResolver.DnsRecordType.Ptr);
    }

    [Fact]
    public async Task ExplicitServer_RetriesTruncatedUdpOverTcp()
    {
        await using var server = await TestDnsServer.StartAsync(truncateUdp: true);
        var resolver = new CliDnsResolver();

        var addresses = await resolver.ResolveHostAddressesAsync("tcp-fallback.example", server.Endpoint, CancellationToken.None);

        Assert.Equal(2, addresses.Count);
        Assert.Contains(server.Queries, query => query.Transport == "udp");
        Assert.Contains(server.Queries, query => query.Transport == "tcp");
    }

    [Fact]
    public async Task ExplicitServer_HonoursCancellationWhileWaitingForReply()
    {
        await using var server = await TestDnsServer.StartAsync(ignoreQueries: true);
        var resolver = new CliDnsResolver();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            resolver.ResolveHostAddressesAsync("never-answers.example", server.Endpoint, cancellation.Token));
    }

    [Fact]
    public void ParseResponse_RejectsWrongTransactionIdAndMalformedCompression()
    {
        var query = CliDnsResolver.CreateQuery(123, "invalid.example", CliDnsResolver.DnsRecordType.A);
        var response = TestDnsServer.BuildResponse(query, truncate: false, returnNxDomain: false);

        Assert.Throws<InvalidDataException>(() =>
            CliDnsResolver.ParseResponse(response, 124, "invalid.example", CliDnsResolver.DnsRecordType.A));

        var mismatchedQuestion = TestDnsServer.BuildResponse(query, truncate: false, returnNxDomain: false);
        mismatchedQuestion[13] = (byte)'x';
        Assert.Throws<InvalidDataException>(() =>
            CliDnsResolver.ParseResponse(mismatchedQuestion, 123, "invalid.example", CliDnsResolver.DnsRecordType.A));

        response[query.Length] = 0xC0;
        response[query.Length + 1] = 0xFF;
        Assert.Throws<InvalidDataException>(() =>
            CliDnsResolver.ParseResponse(response, 123, "invalid.example", CliDnsResolver.DnsRecordType.A));
    }

    [Fact]
    public void Commands_AcceptLiteralDnsServerAndRejectNamesOrPorts()
    {
        var root = Program.BuildRootCommand();

        Assert.Empty(root.Parse(["domain", "--domain-controller", "192.168.10.10", "--dns-server", "192.168.10.10"]).Errors);
        Assert.Empty(root.Parse(["network", "--device", "server.example", "--dns-server", "2001:db8::53"]).Errors);
        Assert.Contains(
            root.Parse(["domain", "--dns-server", "192.168.10.10"]).Errors,
            error => error.Message.Contains("requires --domain-controller", StringComparison.Ordinal));
        Assert.NotEmpty(root.Parse(["domain", "--dns-server", "dns.example"]).Errors);
        Assert.NotEmpty(root.Parse(["network", "--device", "server.example", "--dns-server", "192.168.10.10:53"]).Errors);
        Assert.NotEmpty(root.Parse(["local", "--path", ".", "--dns-server", "192.168.10.10"]).Errors);
    }

    [Fact]
    public void ResumeIdentity_SeparatesSystemAndExplicitDnsScopes()
    {
        var target = new FileSystemScanTarget(FileSystemScanMode.Device, "server.example");
        var root = Path.GetFullPath(".");
        var systemDns = CliResumeIdentity.CreateFilesystemScope(target, root, "rules", false, null, null, false, null);
        var firstServer = CliResumeIdentity.CreateFilesystemScope(target, root, "rules", false, null, null, false, IPAddress.Parse("192.0.2.53"));
        var secondServer = CliResumeIdentity.CreateFilesystemScope(target, root, "rules", false, null, null, false, IPAddress.Parse("192.0.2.54"));

        Assert.NotEqual(systemDns, firstServer);
        Assert.NotEqual(firstServer, secondServer);
    }

    private sealed class TestDnsServer : IAsyncDisposable
    {
        private readonly UdpClient _udp;
        private readonly TcpListener _tcp;
        private readonly CancellationTokenSource _shutdown = new();
        private readonly Task _udpLoop;
        private readonly Task _tcpLoop;
        private readonly bool _truncateUdp;
        private readonly bool _returnNxDomain;
        private readonly bool _ignoreQueries;

        private TestDnsServer(bool truncateUdp, bool returnNxDomain, bool ignoreQueries)
        {
            _tcp = new TcpListener(IPAddress.Loopback, 0);
            _tcp.Start();
            var port = ((IPEndPoint)_tcp.LocalEndpoint).Port;
            _udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
            Endpoint = new IPEndPoint(IPAddress.Loopback, port);
            _truncateUdp = truncateUdp;
            _returnNxDomain = returnNxDomain;
            _ignoreQueries = ignoreQueries;
            _udpLoop = RunUdpAsync();
            _tcpLoop = RunTcpAsync();
        }

        internal IPEndPoint Endpoint { get; }
        internal ConcurrentBag<(string Name, CliDnsResolver.DnsRecordType Type, string Transport)> Queries { get; } = [];

        internal static Task<TestDnsServer> StartAsync(
            bool truncateUdp = false,
            bool returnNxDomain = false,
            bool ignoreQueries = false) =>
            Task.FromResult(new TestDnsServer(truncateUdp, returnNxDomain, ignoreQueries));

        private async Task RunUdpAsync()
        {
            try
            {
                while (!_shutdown.IsCancellationRequested)
                {
                    var request = await _udp.ReceiveAsync(_shutdown.Token);
                    RecordQuery(request.Buffer, "udp");
                    if (_ignoreQueries)
                    {
                        continue;
                    }

                    var response = BuildResponse(request.Buffer, _truncateUdp, _returnNxDomain);
                    await _udp.SendAsync(response, request.RemoteEndPoint, _shutdown.Token);
                }
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
            }
            catch (ObjectDisposedException) when (_shutdown.IsCancellationRequested)
            {
            }
        }

        private async Task RunTcpAsync()
        {
            try
            {
                while (!_shutdown.IsCancellationRequested)
                {
                    using var client = await _tcp.AcceptTcpClientAsync(_shutdown.Token);
                    await using var stream = client.GetStream();
                    var lengthPrefix = new byte[2];
                    await stream.ReadExactlyAsync(lengthPrefix, _shutdown.Token);
                    var request = new byte[BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix)];
                    await stream.ReadExactlyAsync(request, _shutdown.Token);
                    RecordQuery(request, "tcp");
                    var response = BuildResponse(request, truncate: false, _returnNxDomain);
                    BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, checked((ushort)response.Length));
                    await stream.WriteAsync(lengthPrefix, _shutdown.Token);
                    await stream.WriteAsync(response, _shutdown.Token);
                }
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
            }
            catch (ObjectDisposedException) when (_shutdown.IsCancellationRequested)
            {
            }
        }

        private void RecordQuery(byte[] query, string transport)
        {
            var offset = 12;
            var labels = new List<string>();
            while (query[offset] != 0)
            {
                var length = query[offset++];
                labels.Add(Encoding.ASCII.GetString(query, offset, length));
                offset += length;
            }

            offset++;
            var type = (CliDnsResolver.DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(offset, 2));
            Queries.Add((string.Join('.', labels), type, transport));
        }

        internal static byte[] BuildResponse(byte[] query, bool truncate, bool returnNxDomain)
        {
            var queryType = (CliDnsResolver.DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(query.Length - 4, 2));
            var responseData = queryType switch
            {
                CliDnsResolver.DnsRecordType.A => IPAddress.Parse("192.0.2.42").GetAddressBytes(),
                CliDnsResolver.DnsRecordType.Aaaa => IPAddress.Parse("2001:db8::42").GetAddressBytes(),
                CliDnsResolver.DnsRecordType.Ptr => EncodeName("host42.example.test"),
                _ => []
            };
            var answerCount = truncate || returnNxDomain ? 0 : 1;
            var response = new byte[query.Length + (answerCount == 0 ? 0 : 12 + responseData.Length)];
            query.CopyTo(response, 0);
            var flags = returnNxDomain ? 0x8183 : truncate ? 0x8380 : 0x8180;
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), checked((ushort)flags));
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), checked((ushort)answerCount));

            if (answerCount == 0)
            {
                return response;
            }

            var offset = query.Length;
            response[offset++] = 0xC0;
            response[offset++] = 0x0C;
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), (ushort)queryType);
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 2, 2), 1);
            BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset + 4, 4), 60);
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset + 8, 2), checked((ushort)responseData.Length));
            responseData.CopyTo(response, offset + 10);
            return response;
        }

        private static byte[] EncodeName(string name)
        {
            using var stream = new MemoryStream();
            foreach (var label in name.Split('.'))
            {
                stream.WriteByte(checked((byte)label.Length));
                stream.Write(Encoding.ASCII.GetBytes(label));
            }

            stream.WriteByte(0);
            return stream.ToArray();
        }

        public async ValueTask DisposeAsync()
        {
            await _shutdown.CancelAsync();
            _udp.Dispose();
            _tcp.Stop();
            await Task.WhenAll(_udpLoop, _tcpLoop);
            _shutdown.Dispose();
        }
    }
}
