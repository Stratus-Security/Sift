namespace Stratus.Sift.Cli;

internal enum FileSystemScanMode
{
    Folder,
    Domain,
    Subnet,
    Device
}

internal sealed record FileSystemScanTarget(FileSystemScanMode Mode, string Value)
{
    public string DisplayName => Mode switch
    {
        FileSystemScanMode.Folder => "Local filesystem",
        FileSystemScanMode.Domain => "Domain",
        FileSystemScanMode.Subnet => $"Subnet {Value}",
        FileSystemScanMode.Device => $"Device {Value}",
        _ => "Filesystem"
    };

    public static FileSystemScanTarget Parse(string? path, bool domain, string? subnet, string? device)
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

        if (specifiedModes != 1)
        {
            throw new ArgumentException("Specify exactly one scan target: local --path, domain, network --subnet, or network --device.");
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

        return new FileSystemScanTarget(FileSystemScanMode.Device, device!.Trim());
    }
}
