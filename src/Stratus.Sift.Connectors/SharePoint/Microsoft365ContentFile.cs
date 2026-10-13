using System.Security.Cryptography;
using System.Text;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed class Microsoft365ContentFile : IRemoteFile, IRemoteFileInspection
{
    private readonly Func<string?, CancellationToken, Task<Stream?>> _content;
    private Func<CancellationToken, Task<Microsoft365Access>>? _inspect;
    private string _sharingVersion = "";
    private readonly string? _version;
    internal Microsoft365ContentFile(string id, string name, string url, string? version, long? size,
        Func<string?, CancellationToken, Task<Stream?>> content, bool complete = true,
        string exposure = "Unknown", string owner = "Unknown", IReadOnlyList<AclEntry>? acls = null)
    {
        Id = id; Name = name; ContentName = name; WebUrl = url; _version = version; Size = size; _content = content;
        IsContentComplete = complete; Exposure = exposure; Owner = owner; AclEntries = acls ?? [];
    }
    internal static Microsoft365ContentFile Text(string id, string name, string url, string text,
        bool complete = true, string exposure = "Unknown", string owner = "Unknown", IReadOnlyList<AclEntry>? acls = null)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        return new(id, name, url, Convert.ToHexString(SHA256.HashData(bytes)), bytes.Length,
            (_, _) => Task.FromResult<Stream?>(new MemoryStream(bytes, writable: false)), complete, exposure, owner, acls)
        { SampleLargeContent = false };
    }
    public string Id { get; }
    public string ResumeIdentity => Id;
    public string Name { get; }
    public string ContentName { get; init; }
    public string Path => WebUrl;
    public string WebUrl { get; }
    public long? Size { get; }
    public string? Version => _version == null ? null : _version + _sharingVersion;
    public DateTimeOffset? LastEditedAtUtc => DateTimeOffset.TryParse(_version, out var modified)
        ? modified.ToUniversalTime() : null;
    public string? ContentType => null;
    public bool IsDeleted => false;
    public bool IsDirectory => false;
    public bool IsLink => false;
    public bool IsExternal => Exposure is "External" or "Public";
    public bool IsContentComplete { get; private set; }
    public bool SampleLargeContent { get; private init; } = true;
    public string Exposure { get; private set; }
    public string Owner { get; private set; }
    public IReadOnlyList<AclEntry> AclEntries { get; private set; }
    internal Microsoft365ContentFile WithInspection(Func<CancellationToken, Task<Microsoft365Access>>? inspect)
    { _inspect = inspect; return this; }
    public async Task PrepareAsync(CancellationToken cancellationToken)
    {
        if (_inspect == null) return;
        try
        {
            var access = await _inspect(cancellationToken);
            Exposure = access.Exposure; Owner = access.Owner; AclEntries = access.Acls;
            _sharingVersion = ":sharing:" + access.Fingerprint;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        { IsContentComplete = false; Exposure = "Unknown"; throw; }
    }
    public Task<Stream?> GetContentAsync(CancellationToken cancellationToken = default) => _content(null, cancellationToken);
    public Task<Stream?> GetContentRangeAsync(long start, long end, CancellationToken cancellationToken = default)
        => _content($"bytes={start}-{end}", cancellationToken);
}
