using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;

namespace Stratus.Sift.Cli;

internal sealed record NetworkTargetFile(string SourcePath, IReadOnlyList<string> Hosts)
{
    internal const int MaxTargets = 65_536;
    internal const int MaxFileBytes = 8 * 1024 * 1024;
    private const int MaxLines = 200_000;
    private const int MaxLineLength = 4096;
    private sealed record AddressRange(AddressFamily Family, BigInteger Start, BigInteger End, int Line);

    internal static NetworkTargetFile Load(string path)
    {
        var fullPath = Path.GetFullPath(path);
        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxFileBytes)
            throw new ArgumentException($"Target file '{path}' exceeds the 8 MiB size limit.");
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: true);
        IEnumerable<string> Lines()
        {
            while (reader.ReadLine() is { } line) yield return line;
        }
        return Parse(Lines(), fullPath);
    }

    internal static NetworkTargetFile Parse(IEnumerable<string> lines, string sourcePath = "targets")
    {
        var namedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ranges = new List<AddressRange>();
        var lineNumber = 0;
        foreach (var line in lines)
        {
            if (++lineNumber > MaxLines) throw Error(sourcePath, lineNumber, "The target file exceeds 200,000 lines.");
            if (line.Length > MaxLineLength) throw Error(sourcePath, lineNumber, "The line exceeds 4,096 characters.");
            var value = StripComments(line).Trim();
            if (value.Length == 0) continue;
            if (value[0] is '\'' or '"')
            {
                if (value.Length < 2 || value[^1] != value[0]) throw Error(sourcePath, lineNumber, "Unclosed target quote.");
                value = value[1..^1].Trim();
            }
            try
            {
                if (value.Contains('/'))
                {
                    var parts = value.Split('/', StringSplitOptions.TrimEntries);
                    if (parts.Length != 2 || !TryParseAddress(parts[0], out var address)
                        || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix)
                        || prefix < 0 || prefix > address.GetAddressBytes().Length * 8)
                        throw new ArgumentException("Use an IP address and CIDR prefix, for example 192.0.2.0/24 or 2001:db8::/120.");
                    if (address.AddressFamily == AddressFamily.InterNetworkV6 && parts[0].Contains('%'))
                        throw new ArgumentException("IPv6 CIDRs cannot contain an interface scope; specify scoped IPv6 hosts individually.");
                    var bits = address.GetAddressBytes().Length * 8;
                    var hostBits = bits - prefix;
                    var start = new BigInteger(address.GetAddressBytes(), isUnsigned: true, isBigEndian: true) >> hostBits << hostBits;
                    var end = start + (BigInteger.One << hostBits) - 1;
                    // IPv4 /31 and /32 retain every address. IPv6 has no broadcast address.
                    if (address.AddressFamily == AddressFamily.InterNetwork && prefix < 31) { start++; end--; }
                    if (end - start + 1 > MaxTargets) throw new ArgumentException($"CIDR expands beyond the {MaxTargets:N0}-target limit. Use a smaller range.");
                    ranges.Add(new(address.AddressFamily, start, end, lineNumber));
                }
                else if (TryParseAddress(value, out var address))
                {
                    if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
                        namedHosts.Add(address.ToString());
                    else
                    {
                        var number = new BigInteger(address.GetAddressBytes(), isUnsigned: true, isBigEndian: true);
                        ranges.Add(new(address.AddressFamily, number, number, lineNumber));
                    }
                }
                else
                {
                    var host = value.TrimEnd('.');
                    if (host.Length == 0 || host.Any(char.IsWhiteSpace) || host.IndexOfAny(['/', '\\', ':', '[', ']', '#', ';', '\'', '"']) >= 0
                        || host.All(character => char.IsAsciiDigit(character) || character == '.') || IPAddress.TryParse(host, out _))
                        throw new ArgumentException("Expected an IP address, hostname, or CIDR; ports, URLs, and share paths are not supported in target files.");
                    host = new IdnMapping().GetAscii(host);
                    if (host.Length > 253 || host.Split('.').Any(label => label.Length is 0 or > 63 || label.StartsWith('-') || label.EndsWith('-'))
                        || Uri.CheckHostName(host) != UriHostNameType.Dns)
                        throw new ArgumentException("The hostname is invalid.");
                    namedHosts.Add(host.ToLowerInvariant());
                }
                if (namedHosts.Count > MaxTargets) throw new ArgumentException($"The list exceeds the {MaxTargets:N0}-target limit.");
            }
            catch (ArgumentException ex) { throw Error(sourcePath, lineNumber, ex.Message); }
        }

        // Merge ranges before expansion. Repeated or heavily overlapping CIDRs
        // cost only a sort, and never multiply discovery work or allocations.
        var merged = new List<AddressRange>();
        foreach (var range in ranges.OrderBy(range => range.Family).ThenBy(range => range.Start).ThenBy(range => range.End))
        {
            if (merged.Count > 0 && merged[^1].Family == range.Family && range.Start <= merged[^1].End + 1)
                merged[^1] = merged[^1] with { End = BigInteger.Max(merged[^1].End, range.End) };
            else merged.Add(range);
        }
        var count = new BigInteger(namedHosts.Count);
        foreach (var range in merged)
        {
            count += range.End - range.Start + 1;
            if (count > MaxTargets) throw Error(sourcePath, range.Line, $"The list expands beyond the {MaxTargets:N0}-target limit. Use smaller ranges or split the file.");
        }
        if (count == 0) throw new ArgumentException($"Target file '{sourcePath}' contains no IP addresses, hostnames, or CIDRs.");
        foreach (var range in merged)
        {
            var bytes = new byte[range.Family == AddressFamily.InterNetwork ? 4 : 16];
            for (var number = range.Start; number <= range.End; number++)
            {
                Array.Clear(bytes);
                var addressBytes = number.ToByteArray(isUnsigned: true, isBigEndian: true);
                addressBytes.CopyTo(bytes, bytes.Length - addressBytes.Length);
                namedHosts.Add(new IPAddress(bytes).ToString());
            }
        }
        return new(sourcePath, Array.AsReadOnly(namedHosts.Order(StringComparer.OrdinalIgnoreCase).ToArray()));
    }

    private static bool TryParseAddress(string value, out IPAddress address)
    {
        var text = value.Trim();
        if (text.StartsWith('[') && text.EndsWith(']')) text = text[1..^1];
        if (text.Contains(':')) return IPAddress.TryParse(text, out address!);
        // Avoid IPAddress.TryParse's shortened, hexadecimal, and octal IPv4 forms:
        // a typo such as 10.1 must not silently become 10.0.0.1.
        var octets = text.Split('.');
        var bytes = new byte[4];
        if (octets.Length == 4)
        {
            var valid = true;
            for (var index = 0; index < 4; index++)
                valid &= octets[index].Length is > 0 and <= 3 && byte.TryParse(octets[index], NumberStyles.None, CultureInfo.InvariantCulture, out bytes[index]);
            if (valid) { address = new(bytes); return true; }
        }
        address = null!;
        return false;
    }

    private static string StripComments(string line)
    {
        var quote = '\0';
        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (character is '\'' or '"')
            {
                if (quote == '\0') quote = character;
                else if (quote == character) quote = '\0';
            }
            if (quote == '\0' && (index == 0 || char.IsWhiteSpace(line[index - 1]))
                && (character is '#' or ';' || character == '/' && index + 1 < line.Length && line[index + 1] == '/'))
                return line[..index];
        }
        return line;
    }

    private static ArgumentException Error(string source, int line, string message) => new($"{source}: line {line}: {message}");
}
