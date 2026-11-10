using System.Net;
using SMBLibrary;
using Stratus.Sift.Connectors.Interfaces;
using FileAttributes = SMBLibrary.FileAttributes;

namespace Stratus.Sift.Cli.Tests;

public sealed class SmbNestedTargetTests
{
    [Fact]
    public void DeviceOption_PreservesNestedJapanesePathWithSpaces()
    {
        const string path = @"\\server\Data\Parent\資料 2026\ child \";
        Assert.Empty(Program.BuildRootCommand().Parse(["network", "-d", path]).Errors);
        var target = Assert.Single(SmbKerberosService.GetNetworkHostTargets(
            new FileSystemScanTarget(FileSystemScanMode.Device, path)));

        Assert.Equal("server", target.Host);
        Assert.Equal("Data", target.Share);
        Assert.Equal(@"Parent\資料 2026\ child ", target.RootDirectory);
        Assert.Equal(path.TrimEnd('\\'), target.UncPath);
    }

    [Theory]
    [InlineData("server", null)]
    [InlineData(@"\\server", null)]
    [InlineData(@"\\server\Data", "Data")]
    public void DeviceOption_PreservesHostAndShareTargets(string value, string? share)
    {
        var target = SmbDeviceTarget.Parse(value);
        Assert.Equal("server", target.Host);
        Assert.Equal(share, target.Share);
        Assert.Empty(target.RootDirectory);
    }

    [Theory]
    [InlineData(@"\\server\Data\Parent\..\Other")]
    [InlineData(@"\\server\Data\Parent\.\Child")]
    [InlineData(@"\\server\Data\Parent*")]
    [InlineData(@"server\Data\Parent")]
    public void DeviceOption_RejectsAmbiguousFolderTargets(string value)
    {
        Assert.Contains(Program.BuildRootCommand().Parse(["network", "-d", value]).Errors,
            error => error.Message.Contains("--device:", StringComparison.Ordinal));
    }

    [Fact]
    public void WindowsDiscoveryAndDnsRewrite_PreserveNestedTarget()
    {
        const string path = @"\\server\Data\Parent\資料 2026";
        Assert.True(SmbDiscoveryService.TryExtractExplicitShareRoot(path, out var root));
        Assert.Equal(path, root);
        var rewritten = SmbDiscoveryService.CreateExplicitShareRoots(path,
            [IPAddress.Parse("192.0.2.42"), IPAddress.Parse("2001:db8::42")]);
        Assert.Contains(@"\\192.0.2.42\Data\Parent\資料 2026", rewritten);
        Assert.Contains(@"\\2001-db8--42.ipv6-literal.net\Data\Parent\資料 2026", rewritten);
    }

    [Fact]
    public async Task NestedTarget_ListsOnlyRequestedFolderAndItsDescendants()
    {
        const string root = @"Parent\資料 2026";
        var target = Assert.Single(SmbKerberosService.GetNetworkHostTargets(
            new FileSystemScanTarget(FileSystemScanMode.Device, @"\\server\Data\" + root)));
        using var drive = CreateDrive(target.RootDirectory);
        var attempts = new List<string>();
        var items = new List<IRemoteFile>();
        await drive.ProcessDirectoriesAsync(path =>
        {
            attempts.Add(path);
            return path switch
            {
                root => [Entry("included.txt"), Entry("Child", directory: true)],
                root + @"\Child" => [Entry("nested.txt")],
                _ => throw new InvalidOperationException("The scan escaped its target: " + path)
            };
        }, null, item => { items.Add(item); return Task.CompletedTask; });

        Assert.Equal([root, root + @"\Child"], attempts);
        Assert.Contains(items, item => item.Path == @"\\server\Data\Parent\資料 2026\included.txt");
        Assert.Contains(items, item => item.Path == @"\\server\Data\Parent\資料 2026\Child\nested.txt");
        Assert.Equal(@"\\server\Data\Parent\資料 2026", drive.WebUrl);
    }

    [Fact]
    public async Task NestedTarget_ResumesFromItsPendingDescendant()
    {
        using var drive = CreateDrive(@"Parent\資料");
        var checkpoint = SmbKerberosDrive.CreateCheckpoint(new Stack<string>([@"Parent\資料\Child"]));
        var attempts = new List<string>();
        await drive.ProcessDirectoriesAsync(path => { attempts.Add(path); return []; },
            checkpoint, _ => Task.CompletedTask);
        Assert.Equal([@"Parent\資料\Child"], attempts);
    }

    [Theory]
    [InlineData("")]
    [InlineData(@"Parent\資料-backup")]
    [InlineData(@"Parent\資料\..\Other")]
    public async Task NestedTarget_RejectsCheckpointOutsideItsRoot(string pending)
    {
        using var drive = CreateDrive(@"Parent\資料");
        var checkpoint = SmbKerberosDrive.CreateCheckpoint(new Stack<string>([pending]));
        var attempts = new List<string>();
        await drive.ProcessDirectoriesAsync(path => { attempts.Add(path); return []; },
            checkpoint, _ => Task.CompletedTask);
        Assert.Equal([@"Parent\資料"], attempts);
    }

    [Fact]
    public async Task UnreadableNestedRoot_DoesNotFallBackToShare()
    {
        using var drive = CreateDrive(@"Parent\資料");
        var attempts = new List<string>();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => drive.ProcessDirectoriesAsync(path =>
        {
            attempts.Add(path);
            throw new UnauthorizedAccessException();
        }, null, _ => Task.CompletedTask));
        Assert.Equal([@"Parent\資料"], attempts);
    }

    [Fact]
    public void NestedTargets_HaveSeparateResumeIdentities()
    {
        using var share = CreateDrive("");
        using var first = CreateDrive(@"Parent\資料");
        using var second = CreateDrive(@"Parent\Other");
        Assert.NotEqual(share.ConnectionId, first.ConnectionId);
        Assert.NotEqual(first.ConnectionId, second.ConnectionId);
    }

    private static SmbKerberosDrive CreateDrive(string root) => new(
        new SmbKerberosConnection(IPAddress.Loopback, "server", null, null, SmbAuthenticationProtocol.Ntlm, false),
        "Data", null, null, root);

    private static FileDirectoryInformation Entry(string name, bool directory = false) => new()
    {
        FileName = name,
        FileAttributes = directory ? FileAttributes.Directory : FileAttributes.Normal
    };
}
