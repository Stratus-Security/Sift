using System.Buffers.Binary;
using System.Text;
using OpenMcdf;

namespace Stratus.Sift.Scanner.Services;

public partial class ContentExtractor
{
    // MS-PPT 2.1.2: resolve the latest document through CurrentUser/UserEdit and
    // the incremental persist directory. Reading every stored record would also
    // expose deleted slide text from previous quick saves.
    internal static bool AppendLegacySlideListText(Stream source, StringBuilder text)
    {
        source.Position = 0;
        using var storage = RootStorage.Open(source, StorageModeFlags.LeaveOpen);
        using var documentStream = storage.OpenStream("PowerPoint Document");
        using var userStream = storage.OpenStream("Current User");
        var data = ReadCompoundStream(documentStream);
        var currentUser = ReadCompoundStream(userStream);
        var user = PptRecord(currentUser, 0);
        if (user.Type != 4086 || user.Length < 20) throw new InvalidDataException("Invalid PowerPoint current-user record.");
        var editOffset = PptOffset(currentUser, user.Body + 8);
        var directory = new Dictionary<uint, int>();
        var visitedEdits = new HashSet<int>();
        uint? documentId = null;
        while (editOffset != 0)
        {
            if (visitedEdits.Count >= 4096 || !visitedEdits.Add(editOffset))
                throw new InvalidDataException("PowerPoint edit chain repeats or exceeds its traversal limit.");
            var edit = PptRecord(data, editOffset);
            if (edit.Type != 4085 || edit.Length < 28) throw new InvalidDataException("Invalid PowerPoint edit record.");
            documentId ??= BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(edit.Body + 16, 4));
            var persist = PptRecord(data, PptOffset(data, edit.Body + 12));
            if (persist.Type is not (6001 or 6002)) throw new InvalidDataException("Invalid PowerPoint persist directory.");
            var position = persist.Body;
            while (position < persist.End)
            {
                if (persist.End - position < 4) throw new InvalidDataException("Truncated PowerPoint persist directory.");
                var entry = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position, 4));
                position += 4;
                var id = entry & 0xFFFFF;
                var count = (int)(entry >> 20);
                if (count == 0 || count > (persist.End - position) / 4 || id + count > 0x100000)
                    throw new InvalidDataException("Invalid PowerPoint persist entry.");
                for (var index = 0; index < count; index++, position += 4)
                {
                    directory.TryAdd(id + (uint)index, PptOffset(data, position));
                    if (directory.Count > 100_000) throw new InvalidDataException("PowerPoint persist directory exceeds its entry limit.");
                }
            }
            editOffset = PptOffset(data, edit.Body + 8);
        }
        if (documentId == null || !directory.TryGetValue(documentId.Value, out var rootOffset))
            throw new InvalidDataException("PowerPoint has no current document record.");
        var root = PptRecord(data, rootOffset);
        if (root.Type != 1000 || !root.Container) throw new InvalidDataException("Invalid PowerPoint document container.");
        var recordCount = 0;
        return Walk(root.Body, root.End, 0, false);

        bool Walk(int start, int end, int depth, bool inSlideList)
        {
            if (depth > 64) throw new InvalidDataException("PowerPoint record depth limit exceeded.");
            for (var offset = start; offset < end;)
            {
                if (++recordCount > 100_000) throw new InvalidDataException("PowerPoint record count limit exceeded.");
                var record = PptRecord(data, offset);
                if (record.End > end) throw new InvalidDataException("PowerPoint record exceeds its parent container.");
                if (record.Container)
                {
                    if (!Walk(record.Body, record.End, depth + 1, inSlideList || record.Type == 4080)) return false;
                }
                else if (inSlideList && record.Type is 4000 or 4008)
                {
                    if (record.Type == 4000 && record.Length % 2 != 0)
                        throw new InvalidDataException("PowerPoint Unicode text record has an odd byte count.");
                    var value = (record.Type == 4000 ? new UnicodeEncoding(false, false, true) : Encoding.Latin1)
                        .GetString(data, record.Body, record.Length).Replace('\r', '\n');
                    if (!AppendBounded(text, value, true)) return false;
                }
                offset = record.End;
            }
            return true;
        }
    }

    private static byte[] ReadCompoundStream(Stream stream)
    {
        if (stream.Length > MaxFileSize) throw new InvalidDataException("PowerPoint compound stream exceeds its size limit.");
        var data = new byte[checked((int)stream.Length)];
        stream.ReadExactly(data);
        return data;
    }

    private static int PptOffset(byte[] data, int position)
        => checked((int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position, 4)));

    private static (ushort Type, int Body, int Length, int End, bool Container) PptRecord(byte[] data, int offset)
    {
        if (offset < 0 || offset > data.Length - 8) throw new InvalidDataException("Truncated PowerPoint record header.");
        var header = data.AsSpan(offset, 8);
        var length = BinaryPrimitives.ReadUInt32LittleEndian(header[4..]);
        if (length > data.Length - offset - 8) throw new InvalidDataException("Truncated PowerPoint record body.");
        var body = offset + 8;
        return (BinaryPrimitives.ReadUInt16LittleEndian(header[2..]), body, (int)length, body + (int)length,
            (BinaryPrimitives.ReadUInt16LittleEndian(header) & 0xF) == 0xF);
    }
}
