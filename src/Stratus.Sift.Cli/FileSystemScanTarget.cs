namespace Stratus.Sift.Cli;

internal enum FileSystemScanMode
{
    Folder,
    Domain,
    Subnet,
    Device,
    TargetsFile
}

internal sealed record FileSystemScanTarget(FileSystemScanMode Mode, string Value)
{
    public NetworkTargetFile? TargetList { get; init; }
    public string DisplayName => Mode switch
    {
        FileSystemScanMode.Folder => "Local filesystem",
        FileSystemScanMode.Domain => "Domain",
        FileSystemScanMode.Subnet => $"Subnet {Value}",
        FileSystemScanMode.Device => $"Device {Value}",
        FileSystemScanMode.TargetsFile => $"Network targets ({TargetList?.Hosts.Count ?? 0:N0} hosts)",
        _ => "Filesystem"
    };

    public static FileSystemScanTarget Parse(string? path, bool domain, string? subnet, string? device, NetworkTargetFile? targetsFile = null)
    {
        var specifiedModes = 0;
        if (!string.IsNullOrWhiteSpace(path))
        {
            specifiedModes++;
        }

        if (domain)
        {
            specifiedModes++;
        }

        if (!string.IsNullOrWhiteSpace(subnet))
        {
            specifiedModes++;
        }

        if (!string.IsNullOrWhiteSpace(device))
        {
            specifiedModes++;
        }
        if (targetsFile != null) specifiedModes++;

        if (specifiedModes != 1)
        {
            throw new ArgumentException("Specify exactly one scan target: local --path, domain, network --subnet, network --device, or network --targets-file.");
        }

        if (!string.IsNullOrWhiteSpace(path))
        {
            return new FileSystemScanTarget(FileSystemScanMode.Folder, path.Trim());
        }

        if (domain)
        {
            return new FileSystemScanTarget(FileSystemScanMode.Domain, "current domain");
        }

        if (!string.IsNullOrWhiteSpace(subnet))
        {
            return new FileSystemScanTarget(FileSystemScanMode.Subnet, subnet.Trim());
        }

        return targetsFile != null
            ? new FileSystemScanTarget(FileSystemScanMode.TargetsFile, targetsFile.SourcePath) { TargetList = targetsFile }
            : new FileSystemScanTarget(FileSystemScanMode.Device, device!.Trim());
    }
}
