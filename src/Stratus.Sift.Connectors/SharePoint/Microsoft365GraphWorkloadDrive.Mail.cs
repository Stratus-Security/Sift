using System.Text.Json;
using Microsoft.Kiota.Abstractions;
using Stratus.Sift.Connectors.Interfaces;
using static Stratus.Sift.Connectors.SharePoint.Microsoft365GraphReader;

namespace Stratus.Sift.Connectors.SharePoint;

internal sealed partial class Microsoft365GraphWorkloadDrive
{
    private async Task ReadSharedMail(Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        if (options.SharedMailboxes.Count == 0)
            throw new InvalidDataException("Shared-mail scanning requires explicit SharedMailbox addresses or IDs. Personal mailboxes are never auto-discovered.");
        string? self = null;
        if (!appOnly)
        {
            // Resolve both sides to directory IDs: comparing email strings misses aliases.
            using var me = await graph.GetAsync("me?$select=id", ct);
            self = Id(me.RootElement);
        }
        foreach (var target in options.SharedMailboxes)
            await Attempt("Shared mailbox " + target, async () =>
            {
                if (target.Equals("me", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("The signed-in user's personal mailbox cannot be scanned.");
                var id = await MailboxIdentity(target, ct);
                if (self != null && id.Equals(self, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("The shared-mailbox target resolves to the signed-in user's own mailbox; it was excluded.");
                if (!_roots.Add("mailbox:" + id)) return;
                if (appOnly)
                {
                    using var settings = await graph.GetAsync("users/" + Segment(id) + "/mailboxSettings/userPurpose", ct);
                    if (String(settings.RootElement, "value") != "shared")
                        throw new InvalidDataException("Mailbox is not classified as shared; its messages were excluded.");
                }
                await MailFolders("users/" + Segment(id), id, emit, ct);
            }, ct);
    }

    private async Task<string> MailboxIdentity(string target, CancellationToken ct)
    {
        try
        {
            using var user = await graph.GetAsync("users/" + Segment(target) + "?$select=id,mail,userPrincipalName", ct);
            return Id(user.RootElement);
        }
        catch (ApiException ex) when (ex.ResponseStatusCode == 404 && target.Contains('@'))
        {
            // Graph's user path accepts a UPN or ID, which can differ from a shared
            // mailbox's primary SMTP address or aliases. Resolve those without
            // opening messages, then compare the directory ID with our own ID.
            var escaped = target.Replace("'", "''");
            var filter = Segment("mail eq '" + escaped + "' or userPrincipalName eq '" + escaped
                + "' or proxyAddresses/any(p:p eq 'smtp:" + escaped + "') or proxyAddresses/any(p:p eq 'SMTP:" + escaped + "')");
            var matches = new List<string>();
            await foreach (var user in graph.EnumerateAsync("users?$filter=" + filter + "&$select=id,mail,userPrincipalName&$top=2&$count=true", ct, eventualConsistency: true))
            {
                matches.Add(Id(user));
                if (matches.Count > 1) throw new InvalidDataException("Mailbox address resolved to multiple directory users; use its directory ID.");
            }
            return matches.Count == 1 ? matches[0]
                : throw new InvalidDataException("Mailbox address did not resolve to a directory user. Use its user principal name or directory ID.");
        }
    }

    private async Task MailFolders(string mailbox, string mailboxId, Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        var pending = new Stack<(string Path, int Depth)>();
        var visited = new HashSet<string>(StringComparer.Ordinal);
        pending.Push((mailbox + "/mailFolders?includeHiddenFolders=true&$top=100", 0));
        while (pending.TryPop(out var cursor))
        {
            ct.ThrowIfCancellationRequested();
            if (cursor.Depth > 128) throw new InvalidDataException("Shared mailbox folder tree exceeded its depth limit.");
            await Attempt(cursor.Path, async () =>
            {
                await foreach (var folder in graph.EnumerateAsync(cursor.Path, ct))
                {
                    var id = Id(folder);
                    if (!visited.Add(id)) continue;
                    if (visited.Count > 100_000) throw new InvalidDataException("Shared mailbox exceeded its folder limit.");
                    var prefix = mailbox + "/mailFolders/" + Segment(id);
                    pending.Push((prefix + "/childFolders?includeHiddenFolders=true&$top=100", cursor.Depth + 1));
                    await Attempt(prefix + "/messages", async () =>
                    {
                        const string select = "id,subject,body,from,toRecipients,ccRecipients,bccRecipients,replyTo,sender,sentDateTime,receivedDateTime,lastModifiedDateTime,hasAttachments,webLink";
                        await foreach (var message in graph.EnumerateAsync(prefix + "/messages?$select=" + select + "&$top=50", ct))
                        {
                            var messageId = Id(message);
                            var key = mailboxId + ":" + messageId;
                            await Json(key, messageId + ".mail", message, emit, ct, String(message, "webLink"));
                            if (message.TryGetProperty("hasAttachments", out var flag) && flag.ValueKind == JsonValueKind.True
                                || message.TryGetProperty("body", out var body) && (String(body, "content") ?? "").Contains("cid:", StringComparison.OrdinalIgnoreCase))
                                await Attempt(mailbox + "/messages/" + messageId + "/attachments",
                                    () => Attachments(mailbox + "/messages/" + Segment(messageId), key, true, emit, ct), ct);
                        }
                    }, ct);
                }
            }, ct);
        }
    }

    private async Task Attachments(string parentPath, string parentId, bool mail, Func<IRemoteFile, Task> emit, CancellationToken ct)
    {
        await foreach (var attachment in graph.EnumerateAsync(parentPath + "/attachments", ct))
        {
            var id = Id(attachment);
            var path = parentPath + "/attachments/" + Segment(id);
            var kind = String(attachment, "@odata.type") ?? "";
            await Attempt(path, async () =>
            {
                var key = parentId + ":attachment:" + id;
                var name = String(attachment, "name") ?? "attachment.bin";
                if (kind is "#microsoft.graph.fileAttachment" or "#microsoft.graph.taskFileAttachment")
                {
                    long? size = attachment.TryGetProperty("size", out var bytes) && bytes.TryGetInt64(out var n) ? n : null;
                    var version = String(attachment, "lastModifiedDateTime");
                    if (version == null && attachment.TryGetProperty("contentBytes", out var content) && content.ValueKind == JsonValueKind.String)
                        version = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(content.GetString()!)));
                    await Emit(new Microsoft365ContentFile(Workload + ":" + key, name, Link(WebUrl, key), version, size,
                        async (_, token) => await graph.OpenAsync(graph.Url(path + "/$value"), token)), emit, ct);
                }
                else if (mail && kind == "#microsoft.graph.itemAttachment")
                {
                    using var item = await graph.GetAsync(path + "?$expand=microsoft.graph.itemAttachment/item", ct);
                    var text = SearchableText(item.RootElement);
                    var incomplete = ContainsEmbeddedAttachment(item.RootElement);
                    await Emit(Microsoft365ContentFile.Text(Workload + ":" + key, name + ".attached-item.json", Link(WebUrl, key), text, !incomplete), emit, ct);
                }
                else
                {
                    await Json(key, name + ".attachment-reference", attachment, emit, ct, complete: false);
                    Record(path, new InvalidDataException("Attachment payload is a reference or an unsupported attachment type; metadata was retained."));
                }
            }, ct);
        }
    }
    private static bool ContainsEmbeddedAttachment(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Array) return node.EnumerateArray().Any(ContainsEmbeddedAttachment);
        return node.ValueKind == JsonValueKind.Object && node.EnumerateObject().Any(property =>
            property.Name == "attachments" && property.Value.ValueKind == JsonValueKind.Array && property.Value.GetArrayLength() > 0
            || ContainsEmbeddedAttachment(property.Value));
    }
}
