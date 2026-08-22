using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.FileSystem;

/// <summary>
/// Enumerates local filesystem metadata without requiring the managed-agent runtime.
/// </summary>
public sealed class StandardFileSystemEnumerator
{
    private static readonly EnumerationOptions EnumerationOptions = new()
    {
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.System | FileAttributes.ReparsePoint,
        RecurseSubdirectories = false,
        ReturnSpecialDirectories = false,
    };

    private readonly ILogger<StandardFileSystemEnumerator> _logger;

    public StandardFileSystemEnumerator(ILogger<StandardFileSystemEnumerator> logger)
    {
        _logger = logger;
    }

    public IEnumerable<FileSystemEntryInfo> EnumeratePath(string path, bool includeAcls = true)
        => EnumeratePath(path, directoryFilter: null, includeAcls);

    public FileSystemEntryInfo? GetSingleEntry(string path, bool includeAcls = true)
    {
        if (File.Exists(path))
        {
            return GetEntryInfo(new FileInfo(path), includeAcls);
        }

        if (Directory.Exists(path))
        {
            return GetEntryInfo(new DirectoryInfo(path), includeAcls);
        }

        return null;
    }

    public IEnumerable<FileSystemEntryInfo> EnumeratePath(
        string path,
        PathFilter? directoryFilter,
        bool includeAcls = true)
    {
        if (directoryFilter?.Invoke(path.AsSpan()) == true)
        {
            yield break;
        }

        var pendingDirectories = new Stack<string>();
        pendingDirectories.Push(path);

        while (pendingDirectories.Count > 0)
        {
            var currentDirectory = pendingDirectories.Pop();
            var directoryEntry = GetEntryInfo(new DirectoryInfo(currentDirectory), includeAcls);
            if (directoryEntry.HasValue)
            {
                yield return directoryEntry.Value;
            }

            IEnumerable<FileSystemInfo> entries;
            try
            {
                entries = new DirectoryInfo(currentDirectory)
                    .EnumerateFileSystemInfos("*", EnumerationOptions);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }
            catch (Exception exception)
            {
                _logger.LogDebug(exception, "Could not enumerate {Path}", currentDirectory);
                continue;
            }

            foreach (var entry in entries)
            {
                if (entry.Attributes.HasFlag(FileAttributes.Directory))
                {
                    if (directoryFilter?.Invoke(entry.FullName.AsSpan()) != true)
                    {
                        pendingDirectories.Push(entry.FullName);
                    }

                    continue;
                }

                var fileEntry = GetEntryInfo(entry, includeAcls);
                if (fileEntry.HasValue)
                {
                    yield return fileEntry.Value;
                }
            }
        }
    }

    private static FileSystemEntryInfo? GetEntryInfo(FileSystemInfo entry, bool includeAcls)
    {
        try
        {
            var isDirectory = entry.Attributes.HasFlag(FileAttributes.Directory);
            List<AclEntry>? accessEntries = null;
            var owner = "Unknown";
            var exposure = "Unknown";

            if (includeAcls && OperatingSystem.IsWindows())
            {
                (accessEntries, owner, exposure) = ReadWindowsSecurity(entry);
            }

            return new FileSystemEntryInfo(
                entry.FullName,
                entry.Name,
                Path.GetDirectoryName(entry.FullName) ?? string.Empty,
                isDirectory,
                isDirectory ? 0 : ((FileInfo)entry).Length,
                entry.CreationTimeUtc,
                entry.LastWriteTimeUtc,
                entry.LastAccessTimeUtc,
                entry.Attributes,
                accessEntries,
                owner,
                exposure);
        }
        catch
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static (List<AclEntry> AccessEntries, string Owner, string Exposure) ReadWindowsSecurity(
        FileSystemInfo entry)
    {
        var accessEntries = new List<AclEntry>();
        var owner = "Unknown";
        var exposure = "Unknown";

        try
        {
            FileSystemSecurity security = entry switch
            {
                FileInfo file => file.GetAccessControl(),
                DirectoryInfo directory => directory.GetAccessControl(),
                _ => throw new NotSupportedException(),
            };

            if (security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier ownerSid)
            {
                try
                {
                    owner = ((NTAccount)ownerSid.Translate(typeof(NTAccount))).Value;
                }
                catch
                {
                    owner = ownerSid.Value;
                }
            }

            var everyone = false;
            var domainUsers = false;
            var authenticatedUsers = false;

            foreach (FileSystemAccessRule rule in security.GetAccessRules(
                         includeExplicit: true,
                         includeInherited: true,
                         targetType: typeof(SecurityIdentifier)))
            {
                accessEntries.Add(new AclEntry
                {
                    Identity = rule.IdentityReference.Value,
                    Permissions = rule.FileSystemRights.ToString(),
                    AccessControlType = rule.AccessControlType.ToString(),
                    IsInherited = rule.IsInherited,
                });

                if (rule.AccessControlType != AccessControlType.Allow
                    || rule.IdentityReference is not SecurityIdentifier sid)
                {
                    continue;
                }

                everyone |= sid.IsWellKnown(WellKnownSidType.WorldSid)
                    || sid.IsWellKnown(WellKnownSidType.AnonymousSid);
                authenticatedUsers |= sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid);
                domainUsers |= sid.Value.EndsWith("-513", StringComparison.Ordinal);
            }

            exposure = everyone
                ? "Everyone"
                : domainUsers
                    ? "Domain users"
                    : authenticatedUsers
                        ? "Authenticated users"
                        : "Restricted";
        }
        catch
        {
            // ACL metadata is optional. A scan must still proceed when it is unavailable.
        }

        return (accessEntries, owner, exposure);
    }
}
