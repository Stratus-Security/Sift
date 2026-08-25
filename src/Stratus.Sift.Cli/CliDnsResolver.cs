using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Stratus.Sift.Cli;

internal sealed class CliDnsResolver
{
    internal const int DefaultDnsPort = 53;
    private const int HeaderLength = 12;
    private const int MaximumNameJumps = 128;
    private const int MaximumAttempts = 2;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(3);

    internal async Task<IReadOnlyList<IPAddress>> ResolveHostAddressesAsync(
        string host,
        IPAddress? explicitDnsServer,
        CancellationToken cancellationToken)
    {
        var normalizedHost = NormalizeHost(host);
        if (IPAddress.TryParse(normalizedHost, out var address))
        {
            return [address];
        }

        if (explicitDnsServer is null)
        {
            return await Dns.GetHostAddressesAsync(normalizedHost, cancellationToken).ConfigureAwait(false);
        }

        return await ResolveHostAddressesAsync(
            normalizedHost,
            new IPEndPoint(explicitDnsServer, DefaultDnsPort),
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task<IReadOnlyList<IPAddress>> ResolveHostAddressesAsync(
        string host,
        IPEndPoint explicitDnsServer,
        CancellationToken cancellationToken)
    {
        var normalizedHost = NormalizeHost(host);
        if (IPAddress.TryParse(normalizedHost, out var address))
        {
            return [address];
        }

        cancellationToken.ThrowIfCancellationRequested();
        var ipv4Task = QueryAsync(normalizedHost, DnsRecordType.A, explicitDnsServer, cancellationToken);
        var ipv6Task = QueryAsync(normalizedHost, DnsRecordType.Aaaa, explicitDnsServer, cancellationToken);
        var results = await AwaitAddressQueriesAsync(ipv4Task, ipv6Task).ConfigureAwait(false);
        var addresses = results
            .SelectMany(result => result.Addresses)
            .Distinct()
            .OrderBy(candidate => candidate.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ToArray();

        return addresses.Length > 0
            ? addresses
            : throw new InvalidOperationException(
                $"DNS server {FormatEndpoint(explicitDnsServer)} returned no A or AAAA records for '{normalizedHost}'. " +
                "Local DNS was not consulted because --dns-server was supplied.");
    }

    internal async Task<string?> ResolveHostNameAsync(
        IPAddress address,
        IPAddress? explicitDnsServer,
        CancellationToken cancellationToken)
    {
        if (explicitDnsServer is null)
        {
            try
            {
                var entry = await Dns.GetHostEntryAsync(address).WaitAsync(cancellationToken).ConfigureAwait(false);
                return string.IsNullOrWhiteSpace(entry.HostName) ? null : entry.HostName.TrimEnd('.');
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                return null;
            }
        }

        return await ResolveHostNameAsync(
            address,
            new IPEndPoint(explicitDnsServer, DefaultDnsPort),
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task<string?> ResolveHostNameAsync(
        IPAddress address,
        IPEndPoint explicitDnsServer,
        CancellationToken cancellationToken)
    {
        var queryName = CreateReverseLookupName(address);
        var result = await QueryAsync(queryName, DnsRecordType.Ptr, explicitDnsServer, cancellationToken).ConfigureAwait(false);
        return result.Names.FirstOrDefault()?.TrimEnd('.');
    }

    internal static bool IsValidServer(string? value) =>
        !string.IsNullOrWhiteSpace(value) && IPAddress.TryParse(value.Trim(), out _);

    internal static string CreateReverseLookupName(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            Array.Reverse(bytes);
            return $"{string.Join('.', bytes)}.in-addr.arpa";
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            throw new ArgumentException($"Unsupported address family '{address.AddressFamily}'.", nameof(address));
        }

        var builder = new StringBuilder((bytes.Length * 4) + 8);
        for (var index = bytes.Length - 1; index >= 0; index--)
        {
            builder.Append((bytes[index] & 0x0F).ToString("x", CultureInfo.InvariantCulture));
            builder.Append('.');
            builder.Append((bytes[index] >> 4).ToString("x", CultureInfo.InvariantCulture));
            builder.Append('.');
        }

        builder.Append("ip6.arpa");
        return builder.ToString();
    }

    private static async Task<IReadOnlyList<DnsQueryResult>> AwaitAddressQueriesAsync(
        Task<DnsQueryResult> ipv4Task,
        Task<DnsQueryResult> ipv6Task)
    {
        var results = new List<DnsQueryResult>(2);
        Exception? failure = null;
        foreach (var task in new[] { ipv4Task, ipv6Task })
        {
            try
            {
                results.Add(await task.ConfigureAwait(false));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                failure ??= ex;
            }
        }

        if (results.Any(result => result.Addresses.Count > 0) || failure is null)
        {
            return results;
        }

        throw failure;
    }

    private static async Task<DnsQueryResult> QueryAsync(
        string queryName,
        DnsRecordType recordType,
        IPEndPoint dnsServer,
        CancellationToken cancellationToken)
    {
        Exception? lastFailure = null;
        for (var attempt = 1; attempt <= MaximumAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var transactionId = checked((ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1));
            var request = CreateQuery(transactionId, queryName, recordType);

            try
            {
                var response = await SendUdpAsync(request, dnsServer, cancellationToken).ConfigureAwait(false);
                var header = ReadHeader(response, transactionId);
                if (header.IsTruncated)
                {
                    response = await SendTcpAsync(request, dnsServer, cancellationToken).ConfigureAwait(false);
                }

                return ParseResponse(response, transactionId, queryName, recordType);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (attempt < MaximumAttempts)
            {
                lastFailure = ex;
            }
            catch (Exception ex)
            {
                lastFailure = ex;
            }
        }

        throw new InvalidOperationException(
            $"DNS query for '{queryName}' through {FormatEndpoint(dnsServer)} failed after {MaximumAttempts} attempts. " +
            "Local DNS was not consulted because --dns-server was supplied.",
            lastFailure);
    }

    internal static byte[] CreateQuery(ushort transactionId, string queryName, DnsRecordType recordType)
    {
        var normalizedName = NormalizeHost(queryName);
        var idn = new IdnMapping();
        var labels = normalizedName
            .Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(label => idn.GetAscii(label))
            .ToArray();
        if (labels.Length == 0 || labels.Any(label => label.Length is 0 or > 63))
        {
            throw new ArgumentException($"'{queryName}' is not a valid DNS name.", nameof(queryName));
        }

        var queryLength = HeaderLength + labels.Sum(label => label.Length + 1) + 1 + 4;
        var encodedNameLength = labels.Sum(label => label.Length + 1) + 1;
        if (encodedNameLength > 255 || queryLength > 512)
        {
            throw new ArgumentException($"'{queryName}' is too long for a DNS query.", nameof(queryName));
        }

        var query = new byte[queryLength];
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(0, 2), transactionId);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(2, 2), 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(4, 2), 1);
        var offset = HeaderLength;
        foreach (var label in labels)
        {
            query[offset++] = checked((byte)label.Length);
            offset += Encoding.ASCII.GetBytes(label, query.AsSpan(offset));
        }

        query[offset++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset, 2), (ushort)recordType);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset + 2, 2), 1);
        return query;
    }

    internal static DnsQueryResult ParseResponse(
        ReadOnlySpan<byte> response,
        ushort expectedTransactionId,
        string queryName,
        DnsRecordType requestedType)
    {
        var header = ReadHeader(response, expectedTransactionId);
        if (header.IsTruncated)
        {
            throw new InvalidDataException("DNS response remained truncated after TCP fallback.");
        }
        if (header.ResponseCode == 3)
        {
            return new DnsQueryResult([], []);
        }

        if (header.ResponseCode != 0)
        {
            throw new InvalidDataException($"DNS server returned response code {header.ResponseCode}.");
        }

        if (header.QuestionCount != 1)
        {
            throw new InvalidDataException($"DNS response contained {header.QuestionCount} questions instead of one.");
        }

        var offset = HeaderLength;
        var responseQuestionName = ReadName(response, ref offset);
        EnsureAvailable(response, offset, 4);
        var responseQuestionType = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset, 2));
        var responseQuestionClass = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset + 2, 2));
        offset += 4;
        if (!responseQuestionName.Equals(NormalizeHost(queryName), StringComparison.OrdinalIgnoreCase) ||
            responseQuestionType != requestedType ||
            responseQuestionClass != 1)
        {
            throw new InvalidDataException("DNS response question did not match the request.");
        }

        var records = new List<DnsResourceRecord>(header.AnswerCount + header.AdditionalCount);
        var totalRecords = header.AnswerCount + header.AuthorityCount + header.AdditionalCount;
        for (var recordIndex = 0; recordIndex < totalRecords; recordIndex++)
        {
            var owner = ReadName(response, ref offset);
            EnsureAvailable(response, offset, 10);
            var type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset, 2));
            var recordClass = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset + 2, 2));
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(offset + 8, 2));
            offset += 10;
            EnsureAvailable(response, offset, dataLength);

            if (recordClass == 1)
            {
                if (type == DnsRecordType.A && dataLength == 4)
                {
                    records.Add(new DnsResourceRecord(owner, type, new IPAddress(response.Slice(offset, 4)), null));
                }
                else if (type == DnsRecordType.Aaaa && dataLength == 16)
                {
                    records.Add(new DnsResourceRecord(owner, type, new IPAddress(response.Slice(offset, 16)), null));
                }
                else if (type is DnsRecordType.Cname or DnsRecordType.Ptr)
                {
                    var nameOffset = offset;
                    var recordName = ReadName(response, ref nameOffset);
                    if (nameOffset != offset + dataLength)
                    {
                        throw new InvalidDataException("DNS name record length did not match its encoded data.");
                    }

                    records.Add(new DnsResourceRecord(owner, type, null, recordName));
                }
            }

            offset += dataLength;
        }

        var acceptedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { NormalizeHost(queryName) };
        for (var depth = 0; depth < 16; depth++)
        {
            var added = false;
            foreach (var record in records.Where(record => record.Type == DnsRecordType.Cname && acceptedNames.Contains(record.Owner)))
            {
                added |= acceptedNames.Add(record.Name!);
            }

            if (!added)
            {
                break;
            }
        }

        var addresses = records
            .Where(record => record.Address != null && acceptedNames.Contains(record.Owner) && record.Type == requestedType)
            .Select(record => record.Address!)
            .Distinct()
            .ToArray();
        var names = records
            .Where(record => record.Type == DnsRecordType.Ptr && acceptedNames.Contains(record.Owner) && !string.IsNullOrWhiteSpace(record.Name))
            .Select(record => record.Name!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new DnsQueryResult(addresses, names);
    }

    private static async Task<byte[]> SendUdpAsync(
        byte[] request,
        IPEndPoint dnsServer,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        using var client = new UdpClient(dnsServer.AddressFamily);
        client.Connect(dnsServer);

        try
        {
            await client.SendAsync(request, timeout.Token).ConfigureAwait(false);
            var response = await client.ReceiveAsync(timeout.Token).ConfigureAwait(false);
            return response.Buffer;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"DNS server {FormatEndpoint(dnsServer)} did not answer within {RequestTimeout.TotalSeconds:N0} seconds.");
        }
    }

    private static async Task<byte[]> SendTcpAsync(
        byte[] request,
        IPEndPoint dnsServer,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        using var client = new TcpClient(dnsServer.AddressFamily);

        try
        {
            await client.ConnectAsync(dnsServer.Address, dnsServer.Port, timeout.Token).ConfigureAwait(false);
            await using var stream = client.GetStream();
            var lengthPrefix = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, checked((ushort)request.Length));
            await stream.WriteAsync(lengthPrefix, timeout.Token).ConfigureAwait(false);
            await stream.WriteAsync(request, timeout.Token).ConfigureAwait(false);
            await stream.ReadExactlyAsync(lengthPrefix, timeout.Token).ConfigureAwait(false);
            var responseLength = BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix);
            if (responseLength < HeaderLength)
            {
                throw new InvalidDataException($"DNS server returned an invalid TCP response length of {responseLength} bytes.");
            }

            var response = new byte[responseLength];
            await stream.ReadExactlyAsync(response, timeout.Token).ConfigureAwait(false);
            return response;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"DNS server {FormatEndpoint(dnsServer)} did not complete its TCP response within {RequestTimeout.TotalSeconds:N0} seconds.");
        }
    }

    private static DnsHeader ReadHeader(ReadOnlySpan<byte> response, ushort expectedTransactionId)
    {
        EnsureAvailable(response, 0, HeaderLength);
        var transactionId = BinaryPrimitives.ReadUInt16BigEndian(response[..2]);
        if (transactionId != expectedTransactionId)
        {
            throw new InvalidDataException("DNS response transaction ID did not match the request.");
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(response.Slice(2, 2));
        if ((flags & 0x8000) == 0)
        {
            throw new InvalidDataException("DNS packet was not marked as a response.");
        }

        if ((flags & 0x7800) != 0)
        {
            throw new InvalidDataException("DNS response used an unsupported operation code.");
        }

        return new DnsHeader(
            IsTruncated: (flags & 0x0200) != 0,
            ResponseCode: flags & 0x000F,
            QuestionCount: BinaryPrimitives.ReadUInt16BigEndian(response.Slice(4, 2)),
            AnswerCount: BinaryPrimitives.ReadUInt16BigEndian(response.Slice(6, 2)),
            AuthorityCount: BinaryPrimitives.ReadUInt16BigEndian(response.Slice(8, 2)),
            AdditionalCount: BinaryPrimitives.ReadUInt16BigEndian(response.Slice(10, 2)));
    }

    private static string ReadName(ReadOnlySpan<byte> message, ref int offset)
    {
        var cursor = offset;
        var resumeOffset = -1;
        var jumpCount = 0;
        var builder = new StringBuilder();

        while (true)
        {
            EnsureAvailable(message, cursor, 1);
            var length = message[cursor++];
            if (length == 0)
            {
                offset = resumeOffset >= 0 ? resumeOffset : cursor;
                return builder.ToString();
            }

            if ((length & 0xC0) == 0xC0)
            {
                EnsureAvailable(message, cursor, 1);
                var pointer = ((length & 0x3F) << 8) | message[cursor++];
                if (pointer >= message.Length || ++jumpCount > MaximumNameJumps)
                {
                    throw new InvalidDataException("DNS response contained an invalid compression pointer.");
                }

                resumeOffset = resumeOffset >= 0 ? resumeOffset : cursor;
                cursor = pointer;
                continue;
            }

            if ((length & 0xC0) != 0 || length > 63)
            {
                throw new InvalidDataException("DNS response contained an invalid label length.");
            }

            EnsureAvailable(message, cursor, length);
            if (builder.Length > 0)
            {
                builder.Append('.');
            }

            builder.Append(Encoding.ASCII.GetString(message.Slice(cursor, length)));
            cursor += length;
            if (builder.Length > 255)
            {
                throw new InvalidDataException("DNS response contained a name longer than 255 characters.");
            }
        }
    }

    private static void EnsureAvailable(ReadOnlySpan<byte> value, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset > value.Length - length)
        {
            throw new InvalidDataException("DNS response was truncated or malformed.");
        }
    }

    private static string NormalizeHost(string host)
    {
        var normalized = host.Trim().TrimStart('\\').TrimEnd('.');
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new ArgumentException("A DNS name is required.", nameof(host));
        }

        return normalized;
    }

    private static string FormatEndpoint(IPEndPoint endpoint) =>
        endpoint.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{endpoint.Address}]:{endpoint.Port}"
            : $"{endpoint.Address}:{endpoint.Port}";

    internal enum DnsRecordType : ushort
    {
        A = 1,
        Cname = 5,
        Ptr = 12,
        Aaaa = 28
    }

    internal sealed record DnsQueryResult(
        IReadOnlyList<IPAddress> Addresses,
        IReadOnlyList<string> Names);

    private sealed record DnsResourceRecord(
        string Owner,
        DnsRecordType Type,
        IPAddress? Address,
        string? Name);

    private sealed record DnsHeader(
        bool IsTruncated,
        int ResponseCode,
        int QuestionCount,
        int AnswerCount,
        int AuthorityCount,
        int AdditionalCount);
}
