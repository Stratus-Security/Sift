namespace Stratus.Sift.Cli;

internal sealed record SmbDeviceTarget(string Host, string? Share, string RootDirectory = "")
{
    internal string? UncPath => Share is null
        ? null
        : $@"\\{Host}\{Share}" + (RootDirectory.Length == 0 ? string.Empty : $@"\{RootDirectory}");

    internal static SmbDeviceTarget Parse(string value)
    {
        var normalized = value.Trim();
        if (!normalized.StartsWith(@"\\", StringComparison.Ordinal))
        {
            if (normalized.Length == 0 || normalized.IndexOfAny(['\\', '/', '*', '?']) >= 0)
                throw new ArgumentException("Specify a hostname, IP address, or UNC path such as \\\\server\\share\\folder.");
            return new SmbDeviceTarget(normalized, null);
        }

        var parts = normalized.TrimStart('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Any(part => part is "." or ".." || part.IndexOfAny(['/', '*', '?']) >= 0))
            throw new ArgumentException("UNC targets must name a host and optional share/folders, without wildcards or . and .. segments.");

        return new SmbDeviceTarget(
            parts[0],
            parts.Length >= 2 ? parts[1] : null,
            string.Join('\\', parts.Skip(2)));
    }
}
