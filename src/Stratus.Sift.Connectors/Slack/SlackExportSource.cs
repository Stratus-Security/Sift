using System.IO.Compression;
using System.Text.Json;

namespace Stratus.Sift.Connectors.Slack;

internal abstract class SlackExportSource : IDisposable
{
    private static readonly HashSet<string> RootMarkers = new(StringComparer.OrdinalIgnoreCase)
    {
        "channels.json", "groups.json", "dms.json", "mpims.json", "users.json", "org_users.json"
    };

    protected SlackExportSource(string displayName, IEnumerable<string> rawEntries)
    {
        DisplayName = displayName;
        var normalized = rawEntries
            .Select(NormalizeRelativePath)
            .Where(path => path != null)
            .Select(path => path!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        RootPrefix = FindRootPrefix(normalized);
        Entries = normalized
            .Where(path => path.StartsWith(RootPrefix, StringComparison.OrdinalIgnoreCase))
            .Select(path => path[RootPrefix.Length..])
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public string DisplayName { get; }
    public IReadOnlyList<string> Entries { get; }
    protected string RootPrefix { get; }

    public abstract Task<Stream> OpenReadAsync(string relativePath, CancellationToken cancellationToken);

    public async Task<JsonDocument> ReadJsonAsync(string relativePath, CancellationToken cancellationToken)
    {
        await using var stream = await OpenReadAsync(relativePath, cancellationToken);
        return await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
    }

    public async Task<string> ReadTextAsync(string relativePath, CancellationToken cancellationToken)
    {
        await using var stream = await OpenReadAsync(relativePath, cancellationToken);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(cancellationToken);
    }

    public static SlackExportSource Open(string inputPath)
    {
        var fullPath = Path.GetFullPath(inputPath);
        if (Directory.Exists(fullPath)) return new DirectorySlackExportSource(fullPath);
        if (File.Exists(fullPath) && Path.GetExtension(fullPath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            return new ZipSlackExportSource(fullPath);
        }

        throw new ArgumentException($"Slack export input '{inputPath}' must be an existing ZIP file or directory.");
    }

    public virtual void Dispose()
    {
    }

    private static string FindRootPrefix(IReadOnlyCollection<string> entries)
    {
        var marker = entries
            .Where(path => RootMarkers.Contains(Path.GetFileName(path)))
            .OrderBy(path => path.Count(ch => ch == '/'))
            .ThenBy(path => path.Length)
            .FirstOrDefault();
        if (marker == null) return string.Empty;
        var index = marker.LastIndexOf('/');
        return index < 0 ? string.Empty : marker[..(index + 1)];
    }

    private static string? NormalizeRelativePath(string path)
    {
        var normalized = path.Replace('\\', '/').Trim('/');
        if (string.IsNullOrWhiteSpace(normalized)) return null;
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Any(segment => segment is "." or "..") ? null : string.Join('/', segments);
    }

    private sealed class DirectorySlackExportSource : SlackExportSource
    {
        private readonly string _root;

        internal DirectorySlackExportSource(string root)
            : base(Path.GetFileName(root.TrimEnd(Path.DirectorySeparatorChar)), Directory.EnumerateFiles(root, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
                IgnoreInaccessible = true
            }).Select(path => Path.GetRelativePath(root, path)))
        {
            _root = root;
        }

        public override Task<Stream> OpenReadAsync(string relativePath, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var combined = Path.GetFullPath(Path.Combine(_root, RootPrefix.Replace('/', Path.DirectorySeparatorChar), relativePath.Replace('/', Path.DirectorySeparatorChar)));
            var allowedRoot = Path.GetFullPath(_root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!combined.StartsWith(allowedRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Slack export entry resolved outside the export directory.");
            }

            return Task.FromResult<Stream>(new FileStream(combined, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan));
        }
    }

    private sealed class ZipSlackExportSource : SlackExportSource
    {
        private readonly FileStream _stream;
        private readonly ZipArchive _archive;
        private readonly Dictionary<string, ZipArchiveEntry> _entries;

        internal ZipSlackExportSource(string zipPath)
            : this(zipPath, new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
        }

        private ZipSlackExportSource(string zipPath, FileStream stream)
            : this(zipPath, stream, new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true))
        {
        }

        private ZipSlackExportSource(string zipPath, FileStream stream, ZipArchive archive)
            : base(Path.GetFileNameWithoutExtension(zipPath), archive.Entries.Where(entry => !string.IsNullOrEmpty(entry.Name)).Select(entry => entry.FullName))
        {
            _stream = stream;
            _archive = archive;
            _entries = archive.Entries
                .Where(entry => !string.IsNullOrEmpty(entry.Name))
                .ToDictionary(entry => entry.FullName.Replace('\\', '/').Trim('/'), StringComparer.OrdinalIgnoreCase);
        }

        public override Task<Stream> OpenReadAsync(string relativePath, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var key = RootPrefix + relativePath;
            if (!_entries.TryGetValue(key, out var entry)) throw new FileNotFoundException("Slack export entry was not found.", relativePath);
            return Task.FromResult(entry.Open());
        }

        public override void Dispose()
        {
            _archive.Dispose();
            _stream.Dispose();
        }
    }
}
