using System.Security.Principal;
using Stratus.Sift.Core.Models;

namespace Stratus.Sift.Cli;

internal static class CliAccessSummary
{
    internal static string ForReadableRoot(List<AclEntry>? aclEntries)
    {
        var identities = GetCurrentIdentitySet();
        var canWrite = HasPermission(acls: aclEntries, identities, PermissionKind.Write);
        var canModify = HasPermission(acls: aclEntries, identities, PermissionKind.Modify);

        return string.Concat(
            "R",
            canWrite ? "W" : string.Empty,
            canModify ? "M" : string.Empty);
    }

    internal static string ForReadableRoot(List<AclEntry>? aclEntries, IReadOnlySet<string> identities)
    {
        var canWrite = HasPermission(acls: aclEntries, identities, PermissionKind.Write);
        var canModify = HasPermission(acls: aclEntries, identities, PermissionKind.Modify);

        return string.Concat(
            "R",
            canWrite ? "W" : string.Empty,
            canModify ? "M" : string.Empty);
    }

    private static bool HasPermission(List<AclEntry>? acls, IReadOnlySet<string> identities, PermissionKind permissionKind)
    {
        if (acls is null || acls.Count == 0 || identities.Count == 0)
        {
            return false;
        }

        var denied = false;
        var allowed = false;

        foreach (var acl in acls)
        {
            if (string.IsNullOrWhiteSpace(acl.Identity) || !identities.Contains(acl.Identity))
            {
                continue;
            }

            if (!MatchesPermission(acl.Permissions, permissionKind))
            {
                continue;
            }

            if (string.Equals(acl.AccessControlType, "Deny", StringComparison.OrdinalIgnoreCase))
            {
                denied = true;
            }
            else if (string.Equals(acl.AccessControlType, "Allow", StringComparison.OrdinalIgnoreCase))
            {
                allowed = true;
            }
        }

        return allowed && !denied;
    }

    private static bool MatchesPermission(string permissions, PermissionKind permissionKind)
    {
        if (string.IsNullOrWhiteSpace(permissions))
        {
            return false;
        }

        return permissionKind switch
        {
            PermissionKind.Write =>
                permissions.Contains("FullControl", StringComparison.OrdinalIgnoreCase) ||
                permissions.Contains("Modify", StringComparison.OrdinalIgnoreCase) ||
                permissions.Contains("Write", StringComparison.OrdinalIgnoreCase) ||
                permissions.Contains("AppendData", StringComparison.OrdinalIgnoreCase) ||
                permissions.Contains("CreateFiles", StringComparison.OrdinalIgnoreCase) ||
                permissions.Contains("CreateDirectories", StringComparison.OrdinalIgnoreCase),
            PermissionKind.Modify =>
                permissions.Contains("FullControl", StringComparison.OrdinalIgnoreCase) ||
                permissions.Contains("Modify", StringComparison.OrdinalIgnoreCase) ||
                permissions.Contains("Delete", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static HashSet<string> GetCurrentIdentitySet()
    {
        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows())
        {
            return identities;
        }

        try
        {
            var identity = WindowsIdentity.GetCurrent();
            if (!string.IsNullOrWhiteSpace(identity.User?.Value))
            {
                identities.Add(identity.User.Value);
            }

            if (identity.Groups != null)
            {
                foreach (var group in identity.Groups)
                {
                    if (!string.IsNullOrWhiteSpace(group?.Value))
                    {
                        identities.Add(group.Value);
                    }
                }
            }
        }
        catch
        {
        }

        return identities;
    }

    private enum PermissionKind
    {
        Write,
        Modify
    }
}
