using System.Collections.Concurrent;

namespace Stratus.Sift.Connectors.Slack;

/// <summary>
/// Keeps handled Slack throttling visible without flooding interactive output or logs.
/// </summary>
internal sealed class SlackRateLimitNoticeLimiter
{
    private readonly ConcurrentDictionary<string, byte> _reportedMethods = new(StringComparer.OrdinalIgnoreCase);

    internal bool ShouldReport(string method)
        => _reportedMethods.TryAdd(string.IsNullOrWhiteSpace(method) ? "unknown" : method, 0);
}
