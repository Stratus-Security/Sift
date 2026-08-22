using System.Text.RegularExpressions;

namespace Stratus.Sift.Cli;

internal static partial class CliCloudResourceLinkNormalizer
{
    internal static string Normalize(string resourcePath, IReadOnlyList<CliOutputEventRecord>? events)
    {
        if (string.IsNullOrWhiteSpace(resourcePath)
            || IsWebUrl(resourcePath))
        {
            return resourcePath;
        }

        var discoveries = ParseDiscoveries(events);
        if (resourcePath.StartsWith("atlassian://", StringComparison.OrdinalIgnoreCase))
        {
            return NormalizeAtlassian(resourcePath) ?? resourcePath;
        }

        if (resourcePath.StartsWith("slack://", StringComparison.OrdinalIgnoreCase)
            || resourcePath.StartsWith("slack-browser://", StringComparison.OrdinalIgnoreCase))
        {
            return NormalizeSlack(resourcePath, discoveries) ?? resourcePath;
        }

        if (resourcePath.StartsWith("sharepoint://", StringComparison.OrdinalIgnoreCase))
        {
            return NormalizeSharePoint(resourcePath, discoveries) ?? resourcePath;
        }

        return NormalizeAzureBlob(resourcePath, discoveries) ?? resourcePath;
    }

    internal static List<CliOutputEventRecord> ExtractDiscoveryEvents(IEnumerable<string> lines)
    {
        var events = new List<CliOutputEventRecord>();
        foreach (var line in lines)
        {
            var markerIndex = line.IndexOf("Discovered drive:", StringComparison.OrdinalIgnoreCase);
            if (markerIndex < 0)
            {
                continue;
            }

            var message = line[markerIndex..].Trim();
            if (!DiscoveryRegex().IsMatch(message))
            {
                continue;
            }

            events.Add(new CliOutputEventRecord
            {
                Kind = "discovery",
                Message = message,
                TimestampUtc = DateTimeOffset.UtcNow
            });
        }

        return events;
    }

    private static string? NormalizeAtlassian(string resourcePath)
    {
        var segments = GetCustomUriSegments(resourcePath, "atlassian://");
        if (segments.Count < 4 || !IsValidHost(segments[0]))
        {
            return null;
        }

        var host = segments[0];
        if (segments[1].Equals("jira", StringComparison.OrdinalIgnoreCase))
        {
            var issueKey = TrimTextExtension(segments[3]);
            return string.IsNullOrWhiteSpace(issueKey)
                ? null
                : $"https://{host}/browse/{EscapeSegment(issueKey)}";
        }

        if (!segments[1].Equals("confluence", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var spaceKey = segments[2];
        if (segments.Count < 5)
        {
            return $"https://{host}/wiki/spaces/{EscapeSegment(spaceKey)}";
        }

        var collection = segments[3];
        var contentId = TrimTextExtension(segments[4]);
        if (collection.Equals("pages", StringComparison.OrdinalIgnoreCase))
        {
            return $"https://{host}/wiki/spaces/{EscapeSegment(spaceKey)}/pages/{EscapeSegment(contentId)}";
        }

        if (collection.Equals("blogposts", StringComparison.OrdinalIgnoreCase))
        {
            return $"https://{host}/wiki/spaces/{EscapeSegment(spaceKey)}/blog/{EscapeSegment(contentId)}";
        }

        return $"https://{host}/wiki/spaces/{EscapeSegment(spaceKey)}";
    }

    private static string? NormalizeSlack(string resourcePath, IReadOnlyList<DriveDiscovery> discoveries)
    {
        var prefix = resourcePath.StartsWith("slack-browser://", StringComparison.OrdinalIgnoreCase)
            ? "slack-browser://"
            : "slack://";
        var segments = GetCustomUriSegments(resourcePath, prefix);
        if (segments.Count < 2)
        {
            return null;
        }

        var channelName = segments[1];
        var discovery = discoveries.FirstOrDefault(candidate =>
            candidate.DriveType.Equals("Slack", StringComparison.OrdinalIgnoreCase)
            && candidate.Name.Equals(channelName, StringComparison.OrdinalIgnoreCase)
            && IsWebUrl(candidate.WebUrl));
        if (discovery == null)
        {
            return null;
        }

        var channelUrl = discovery.WebUrl.TrimEnd('/');
        var messageName = segments.LastOrDefault(segment => segment.StartsWith("message-", StringComparison.OrdinalIgnoreCase));
        var match = messageName == null ? Match.Empty : SlackMessageRegex().Match(messageName);
        if (match.Success && channelUrl.Contains(".slack.com/archives/", StringComparison.OrdinalIgnoreCase))
        {
            return $"{channelUrl}/p{match.Groups["seconds"].Value}{match.Groups["fraction"].Value}";
        }

        return channelUrl;
    }

    private static string? NormalizeSharePoint(string resourcePath, IReadOnlyList<DriveDiscovery> discoveries)
    {
        var segments = GetCustomUriSegments(resourcePath, "sharepoint://");
        if (segments.Count < 2)
        {
            return null;
        }

        return discoveries.FirstOrDefault(candidate =>
            candidate.Id.Equals(segments[1], StringComparison.OrdinalIgnoreCase)
            && IsWebUrl(candidate.WebUrl))?.WebUrl;
    }

    private static string? NormalizeAzureBlob(string resourcePath, IReadOnlyList<DriveDiscovery> discoveries)
    {
        if (Path.IsPathRooted(resourcePath) || resourcePath.Contains("://", StringComparison.Ordinal))
        {
            return null;
        }

        var containers = discoveries
            .Where(candidate => candidate.DriveType.Equals("AzureBlob", StringComparison.OrdinalIgnoreCase)
                                && IsWebUrl(candidate.WebUrl))
            .Select(candidate => candidate.WebUrl.TrimEnd('/'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (containers.Count != 1)
        {
            return null;
        }

        var relativePath = string.Join('/', resourcePath
            .Replace('\\', '/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Select(EscapeSegment));
        return string.IsNullOrWhiteSpace(relativePath) ? containers[0] : $"{containers[0]}/{relativePath}";
    }

    private static List<DriveDiscovery> ParseDiscoveries(IReadOnlyList<CliOutputEventRecord>? events)
    {
        var discoveries = new List<DriveDiscovery>();
        if (events == null)
        {
            return discoveries;
        }

        foreach (var outputEvent in events)
        {
            var markerIndex = outputEvent.Message.IndexOf("Discovered drive:", StringComparison.OrdinalIgnoreCase);
            if (markerIndex < 0)
            {
                continue;
            }

            var match = DiscoveryRegex().Match(outputEvent.Message[markerIndex..].Trim());
            if (match.Success)
            {
                discoveries.Add(new DriveDiscovery(
                    match.Groups["name"].Value.Trim(),
                    match.Groups["id"].Value.Trim(),
                    match.Groups["type"].Value.Trim(),
                    match.Groups["url"].Value.Trim()));
            }
        }

        return discoveries;
    }

    private static List<string> GetCustomUriSegments(string value, string prefix)
        => value[prefix.Length..]
            .Replace('\\', '/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Select(Uri.UnescapeDataString)
            .ToList();

    private static bool IsWebUrl(string? value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri)
           && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);

    private static bool IsValidHost(string host)
        => !string.IsNullOrWhiteSpace(host) && Uri.CheckHostName(host) != UriHostNameType.Unknown;

    private static string EscapeSegment(string value) => Uri.EscapeDataString(Uri.UnescapeDataString(value));

    private static string TrimTextExtension(string value)
        => value.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ? value[..^4] : value;

    [GeneratedRegex(@"^Discovered drive:\s+(?<name>.+)\s+\((?<id>[^()]*)\)\s+\[(?<type>[^\]]+)\](?:\s+-\s+(?<url>https?://\S+))?\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex DiscoveryRegex();

    [GeneratedRegex(@"^message-(?<seconds>\d+)-(?<fraction>\d+)\.txt$", RegexOptions.IgnoreCase)]
    private static partial Regex SlackMessageRegex();

    private sealed record DriveDiscovery(string Name, string Id, string DriveType, string WebUrl);
}
