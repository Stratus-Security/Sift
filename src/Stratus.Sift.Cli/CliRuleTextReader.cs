using System.Text;

namespace Stratus.Sift.Cli;

internal static class CliRuleTextReader
{
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly Encoding Utf16Le = new UnicodeEncoding(false, false, true);
    private static readonly Encoding Utf16Be = new UnicodeEncoding(true, false, true);
    private static readonly Encoding Utf32Le = new UTF32Encoding(false, false, true);
    private static readonly Encoding Utf32Be = new UTF32Encoding(true, false, true);

    internal static async Task<string> ReadAsync(string path, CancellationToken cancellationToken)
        => Decode(await File.ReadAllBytesAsync(path, cancellationToken), path);

    internal static async Task<string> ReadAsync(Stream stream, string source, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, cancellationToken);
        return Decode(buffer.GetBuffer().AsSpan(0, checked((int)buffer.Length)), source);
    }

    private static string Decode(ReadOnlySpan<byte> bytes, string source)
    {
        var encoding = Utf8;
        var preamble = 0;
        if (bytes.StartsWith<byte>([0xff, 0xfe, 0x00, 0x00])) { encoding = Utf32Le; preamble = 4; }
        else if (bytes.StartsWith<byte>([0x00, 0x00, 0xfe, 0xff])) { encoding = Utf32Be; preamble = 4; }
        else if (bytes.StartsWith<byte>([0xef, 0xbb, 0xbf])) { preamble = 3; }
        else if (bytes.StartsWith<byte>([0xff, 0xfe])) { encoding = Utf16Le; preamble = 2; }
        else if (bytes.StartsWith<byte>([0xfe, 0xff])) { encoding = Utf16Be; preamble = 2; }
        if (preamble == 0 && bytes.Contains((byte)0))
            throw new InvalidDataException($"Rule file '{source}' contains NUL bytes without a Unicode BOM. "
                + "Save it as UTF-8, or include a BOM for UTF-16/UTF-32.");
        try
        {
            return encoding.GetString(bytes[preamble..]);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException(
                $"Rule file '{source}' is not valid {encoding.WebName}. Save it as UTF-8 "
                + "(or UTF-16/UTF-32 with a BOM). Legacy ANSI/Shift-JIS encodings are not guessed.", exception);
        }
    }
}
