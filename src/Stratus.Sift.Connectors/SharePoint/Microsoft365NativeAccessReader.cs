using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Net;
using Stratus.Sift.Core.Models;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed record Microsoft365Access(string Exposure, string Owner, IReadOnlyList<AclEntry> Acls, string Fingerprint);

internal static class Microsoft365NativeAccessReader
{
    private sealed record GroupAccess(bool Guest, string Fingerprint);
    private static readonly ConditionalWeakTable<SharePointRestClient, ConcurrentDictionary<string, Lazy<Task<GroupAccess>>>> Groups = new();
    internal static void Reset(SharePointRestClient client) => Groups.Remove(client);
    private static async Task<GroupAccess> GroupAsync(SharePointRestClient client, Uri site, string id,
        Microsoft365CoverageOptions options, CancellationToken ct)
    {
        var cache = Groups.GetValue(client, _ => new(StringComparer.Ordinal));
        var key = site.GetLeftPart(UriPartial.Authority) + site.AbsolutePath + ":" + id;
        async Task<GroupAccess> Read()
        {
            var hashes = new List<string>(); var guest = false;
            await foreach (var user in client.EnumerateJsonAsync(SharePointRestClient.Api(site,
                $"web/sitegroups/GetById({ValidatedNumber(id)})/users?$top=200"), ct))
            {
                if (hashes.Count >= 100_000) throw new InvalidDataException("SharePoint group exceeds the member limit.");
                hashes.Add(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(user.GetRawText()))));
                guest |= await IsGuestAsync(user, options, ct);
            }
            return new(guest, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', hashes.Order(StringComparer.Ordinal))))));
        }
        var task = new Lazy<Task<GroupAccess>>(Read);
        if (cache.Count < 10_000) task = cache.GetOrAdd(key, task);
        try { return await task.Value.WaitAsync(ct); }
        catch { cache.TryRemove(new KeyValuePair<string, Lazy<Task<GroupAccess>>>(key, task)); throw; }
    }
    internal static async Task<Microsoft365Access> ReadAsync(SharePointRestClient client, Uri site, string resource,
        Microsoft365CoverageOptions options, CancellationToken ct)
    {
        var acls = new List<AclEntry>();
        var versions = new List<string>();
        var external = false; var publicAccess = false; var organization = false;
        using var metadata = await ReadMetadataAsync(client, site, resource, ct);
        var metadataRoot = metadata.RootElement;
        if (metadataRoot.TryGetProperty("d", out var wrappedMetadata)) metadataRoot = wrappedMetadata;
        var owner = "Cloud";
        if (metadataRoot.TryGetProperty("Author", out var author))
        {
            // A list's person lookup uses EMail; SP.User responses use Email.
            var email = String(author, "EMail") ?? String(author, "Email");
            var title = String(author, "Title");
            owner = !string.IsNullOrWhiteSpace(email) ? email : !string.IsNullOrWhiteSpace(title) ? title : "Cloud";
        }
        if (!metadataRoot.TryGetProperty("HasUniqueRoleAssignments", out var unique)
            || unique.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new InvalidDataException("SharePoint permission inheritance metadata is missing.");
        var inherited = !unique.GetBoolean();
        versions.Add(metadataRoot.GetRawText());
        await foreach (var assignment in client.EnumerateJsonAsync(SharePointRestClient.Api(site,
            resource + "/RoleAssignments?$expand=Member,RoleDefinitionBindings&$top=200"), ct))
        {
            if (acls.Count >= 10_000) throw new InvalidDataException("Role assignments exceed the inspection limit.");
            versions.Add(assignment.GetRawText());
            if (!assignment.TryGetProperty("Member", out var member)) throw new InvalidDataException("Role assignment has no principal.");
            var label = String(member, "LoginName") ?? String(member, "Title") ?? "Unknown";
            var roles = "Unknown";
            if (assignment.TryGetProperty("RoleDefinitionBindings", out var bindings))
            {
                if (bindings.ValueKind == JsonValueKind.Object && bindings.TryGetProperty("results", out var results)) bindings = results;
                if (bindings.ValueKind == JsonValueKind.Array) roles = string.Join(',', bindings.EnumerateArray().Select(role => String(role, "Name")));
            }
            acls.Add(new() { Identity = label, Permissions = roles, AccessControlType = "Allow", IsInherited = inherited });
            if (label.Contains("SharingLinks.", StringComparison.OrdinalIgnoreCase))
            {
                if (label.Contains("Anonymous", StringComparison.OrdinalIgnoreCase)) publicAccess = true;
                else if (label.Contains("Organization", StringComparison.OrdinalIgnoreCase)) organization = true;
                // Specific-people links are classified by their group membership below.
            }
            if (label.Contains("spo-grid-all-users", StringComparison.OrdinalIgnoreCase)) { organization = true; continue; }
            if (label.Contains("c:0(.s|true", StringComparison.OrdinalIgnoreCase)) { external = true; continue; }
            var type = String(member, "PrincipalType");
            if (type == "8")
            {
                var groupId = String(member, "Id") ?? throw new InvalidDataException("SharePoint group has no ID.");
                var group = await GroupAsync(client, site, groupId, options, ct);
                versions.Add(group.Fingerprint);
                external |= group.Guest;
            }
            else if (type == "1" && String(member, "Id") is { } userId)
            {
                using var user = await client.ReadJsonAsync(SharePointRestClient.Api(site,
                    $"web/siteusers/GetById({ValidatedNumber(userId)})"), ct);
                var root = user.RootElement;
                if (root.TryGetProperty("d", out var wrapped)) root = wrapped;
                versions.Add(root.GetRawText());
                external |= await IsGuestAsync(root, options, ct);
            }
            else external |= await IsGuestAsync(member, options, ct);
        }
        return new(publicAccess ? "Public" : external ? "External" : organization ? "Organization" : "Restricted", owner, acls,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', versions.Order(StringComparer.Ordinal))))));
    }

    private static async Task<JsonDocument> ReadMetadataAsync(SharePointRestClient client, Uri site, string resource,
        CancellationToken ct)
    {
        try
        {
            return await client.ReadJsonAsync(SharePointRestClient.Api(site,
                resource + "?$select=Author/Title,Author/EMail,HasUniqueRoleAssignments&$expand=Author"), ct);
        }
        catch (HttpRequestException ex) when (!ct.IsCancellationRequested && ex.StatusCode == HttpStatusCode.BadRequest
            && ((ex.Message.Contains("The query to field 'Author/", StringComparison.OrdinalIgnoreCase)
                && ex.Message.Contains("' is not valid.", StringComparison.OrdinalIgnoreCase))
                || ex.Message.Contains("The $expand query is not valid for field 'Author'.", StringComparison.OrdinalIgnoreCase)))
        {
            // Author fields vary on system lists. Their absence must not block ACL
            // inspection. Other failures (including access denied) still propagate.
            return await client.ReadJsonAsync(SharePointRestClient.Api(site,
                resource + "?$select=HasUniqueRoleAssignments"), ct);
        }
    }

    internal static async Task<bool> IsSitePrincipalGuestAsync(SharePointRestClient client, Uri site, string kind,
        string id, Microsoft365CoverageOptions options, CancellationToken ct)
    {
        if (kind == "siteUser")
        {
            using var user = await client.ReadJsonAsync(SharePointRestClient.Api(site, $"web/siteusers/GetById({ValidatedNumber(id)})"), ct);
            var root = user.RootElement;
            if (root.TryGetProperty("d", out var wrapped)) root = wrapped;
            return await IsGuestAsync(root, options, ct);
        }
        return (await GroupAsync(client, site, id, options, ct)).Guest;
    }

    internal static async Task<bool> IsGuestAsync(JsonElement user, Microsoft365CoverageOptions options, CancellationToken ct)
    {
        var login = String(user, "LoginName") ?? String(user, "loginName") ?? "";
        if (login.Contains("#ext#", StringComparison.OrdinalIgnoreCase)) return true;
        if (login.Contains("spo-grid-all-users", StringComparison.OrdinalIgnoreCase)) return false;
        if (login.Contains("c:0(.s|true", StringComparison.OrdinalIgnoreCase)) return true;
        if (String(user, "PrincipalType") is "4" or "2")
        {
            var id = login.Split('|').Last();
            var ownerGroup = id.EndsWith("_o", StringComparison.OrdinalIgnoreCase);
            if (ownerGroup) id = id[..^2];
            if (!Guid.TryParse(id, out _))
                throw new InvalidDataException("Directory sharing group has no valid Entra object ID.");
            if (options.GraphClient != null)
                return await Microsoft365PrincipalReader.IsGuestAsync(options.GraphClient, ownerGroup ? "groupOwners" : "group", id, ct);
            throw new InvalidDataException("Directory sharing group cannot be classified without Graph access.");
        }
        var known = false;
        foreach (var field in new[] { "IsEmailAuthenticationGuestUser", "IsShareByEmailGuestUser" })
            if (user.TryGetProperty(field, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False)
            { known = true; if (value.GetBoolean()) return true; }
        if (known) return false;
        // RoleAssignment.Member has fewer fields than the site-user endpoint.
        throw new InvalidDataException("SharePoint user guest status could not be established.");
    }
    internal static long ValidatedNumber(string value) => long.TryParse(value, out var number) && number > 0
        ? number : throw new InvalidDataException("SharePoint principal or list item ID is invalid.");
}
