namespace Stratus.Sift.Connectors.SharePoint;

internal sealed record Microsoft365CoverageOptions
{
    internal SharePointRestClient? NativeClient { get; init; }
    internal Microsoft.Graph.GraphServiceClient? GraphClient { get; init; }
    internal Uri? NativeSiteUrl { get; init; }
    internal bool GraphPermissionsAreComplete { get; init; } = true;
    internal bool RecurseSubsites { get; init; } = true;
    internal bool DiscoverPersonalDrives { get; init; } = true;
    internal bool DiscoverSharedFiles { get; init; } = true;
    internal bool ScanListsAndPages { get; init; } = true;
    internal bool ScanLibraryFields { get; init; } = true;
    internal bool ScanVersions { get; init; } = true;
    internal bool ScanRecycleBin { get; init; } = true;
    internal bool ReadSharing { get; init; } = true;
    internal int MaxVersionsPerFile { get; init; } = 1000;
    internal const int MaxPages = 100_000;
    internal const int MaxSites = 100_000;
    internal const int MaxSiteDepth = 64;

    internal static Microsoft365CoverageOptions Disabled { get; } = new()
    {
        RecurseSubsites = false,
        DiscoverPersonalDrives = false,
        DiscoverSharedFiles = false,
        ScanListsAndPages = false,
        ScanLibraryFields = false,
        ScanVersions = false,
        ScanRecycleBin = false,
        ReadSharing = false
    };

    internal static Microsoft365CoverageOptions FromConfiguration(IReadOnlyDictionary<string, string> config)
        => new()
        {
            RecurseSubsites = Boolean(config, "RecurseSubsites"),
            DiscoverPersonalDrives = Boolean(config, "DiscoverPersonalDrives"),
            DiscoverSharedFiles = Boolean(config, "DiscoverSharedFiles"),
            ScanListsAndPages = Boolean(config, "ScanListsAndPages"),
            ScanLibraryFields = Boolean(config, "ScanLibraryFields"),
            ScanVersions = Boolean(config, "ScanVersions"),
            ScanRecycleBin = Boolean(config, "ScanRecycleBin"),
            ReadSharing = Boolean(config, "ReadSharing"),
            MaxVersionsPerFile = config.TryGetValue("MaxVersionsPerFile", out var raw)
                ? int.TryParse(raw, out var number) && number is > 0 and <= 100_000 ? number
                    : throw new ArgumentException("MaxVersionsPerFile must be between 1 and 100000.") : 1000
        };

    private static bool Boolean(IReadOnlyDictionary<string, string> config, string key)
        => !config.TryGetValue(key, out var raw) ? true : bool.TryParse(raw, out var value) ? value
            : throw new ArgumentException($"{key} must be true or false.");
}
