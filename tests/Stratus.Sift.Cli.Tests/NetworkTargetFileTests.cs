using System.CommandLine;
using System.Text;

namespace Stratus.Sift.Cli.Tests;

public sealed class NetworkTargetFileTests
{
    [Fact]
    public void MixedTargets_NormalizeAndMergeOverlapsWithoutDuplicatingHosts()
    {
        var targets = NetworkTargetFile.Parse([
            "# Inventory", "", "  SERVER01  ", "server01.", "\"server02\" ; owner comment",
            "192.0.2.1", "192.0.2.0/30", "192.0.2.1/30 # same range", "192.000.002.002",
            "[2001:db8::1]", "2001:db8::/126", " // comment", "; comment"]);
        Assert.Equal(8, targets.Hosts.Count);
        Assert.Contains("server01", targets.Hosts);
        Assert.Contains("server02", targets.Hosts);
        Assert.Contains("192.0.2.1", targets.Hosts);
        Assert.Contains("192.0.2.2", targets.Hosts);
        Assert.Contains("2001:db8::", targets.Hosts);
        Assert.DoesNotContain("192.0.2.0", targets.Hosts);
        Assert.DoesNotContain("192.0.2.3", targets.Hosts);
    }

    [Theory]
    [InlineData("192.0.2.1/30", "192.0.2.1", "192.0.2.2")]
    [InlineData("192.0.2.0/31", "192.0.2.0", "192.0.2.1")]
    [InlineData("255.255.255.254/31", "255.255.255.254", "255.255.255.255")]
    [InlineData("2001:db8::1/127", "2001:db8::", "2001:db8::1")]
    public void SmallSubnets_KeepCorrectBoundaryAddresses(string input, string first, string second)
        => Assert.Equal(new[] { first, second }, NetworkTargetFile.Parse([input]).Hosts);

    [Theory]
    [InlineData("255.255.255.255/32", "255.255.255.255")]
    [InlineData("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("0.0.0.0/32", "0.0.0.0")]
    [InlineData("::/128", "::")]
    [InlineData("[fe80::1%12]", "fe80::1%12")]
    [InlineData("SERVER_01", "server_01")]
    [InlineData("bücher.example", "xn--bcher-kva.example")]
    [InlineData("'server.example.' # note", "server.example")]
    public void SingleTargets_AcceptCommonAddressAndHostnameForms(string input, string expected)
        => Assert.Equal(expected, Assert.Single(NetworkTargetFile.Parse([input]).Hosts));

    [Theory]
    [InlineData("192.0.2.0/33")]
    [InlineData("192.0.2.0/-1")]
    [InlineData("192.0.2.0/24/1")]
    [InlineData("host.example/24")]
    [InlineData("2001:db8::/129")]
    [InlineData("fe80::1%12/128")]
    [InlineData("fe80::1%0/128")]
    [InlineData("192.0.2.999")]
    [InlineData("10.1")]
    [InlineData("2130706433")]
    [InlineData("0x7f000001")]
    [InlineData("server.example:445")]
    [InlineData("https://server.example")]
    [InlineData("server..example")]
    [InlineData("-server.example")]
    [InlineData("server-.example")]
    [InlineData("host1 host2")]
    [InlineData("\"server.example")]
    [InlineData("\"\"")]
    [InlineData("192.0.2.1,192.0.2.2")]
    public void InvalidLines_ReportSourceAndPhysicalLineNumber(string input)
    {
        var exception = Assert.Throws<ArgumentException>(() => NetworkTargetFile.Parse(["# note", "server01", input], "hosts.txt"));
        Assert.Contains("hosts.txt: line 3:", exception.Message);
    }

    [Fact]
    public void EmptyOrOversizedLists_FailBeforeDiscovery()
    {
        Assert.Contains("contains no", Assert.Throws<ArgumentException>(() => NetworkTargetFile.Parse(["", "# comment", "; comment"])).Message);
        Assert.Contains("line 1", Assert.Throws<ArgumentException>(() => NetworkTargetFile.Parse([new string('a', 4097)])).Message);
        Assert.Throws<ArgumentException>(() => NetworkTargetFile.Parse(Enumerable.Repeat("", 200_001)));
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("192.0.0.0/15")]
    [InlineData("::/0")]
    [InlineData("2001:db8::/64")]
    public void HugeCidrs_FailBeforeExpansion(string range)
        => Assert.Contains("target limit", Assert.Throws<ArgumentException>(() => NetworkTargetFile.Parse([range])).Message);

    [Fact]
    public void AggregateLimit_CountsMergedRangesAndHostnames()
    {
        var repeated = Enumerable.Repeat("192.0.0.0/16", 100).Append("192.0.2.0/24").Append("192.0.2.1");
        Assert.Equal(65_534, NetworkTargetFile.Parse(repeated).Hosts.Count);
        Assert.Contains("line 2", Assert.Throws<ArgumentException>(() => NetworkTargetFile.Parse(["192.0.0.0/16", "198.18.0.0/16"])).Message);
        Assert.Throws<ArgumentException>(() => NetworkTargetFile.Parse(["2001:db8::/112", "server01"]));
    }

    [Theory]
    [InlineData("utf8")]
    [InlineData("utf8-bom")]
    [InlineData("utf16")]
    public void Load_SupportsCommonTextEncodingsAndWindowsOrUnixNewlines(string encodingName)
    {
        var path = Path.GetTempFileName();
        try
        {
            Encoding encoding = encodingName switch { "utf16" => Encoding.Unicode, "utf8-bom" => new UTF8Encoding(true), _ => new UTF8Encoding(false) };
            File.WriteAllText(path, "# inventory\r\nserver01\n192.0.2.1\r\n", encoding);
            var targets = NetworkTargetFile.Load(path);
            Assert.Equal(Path.GetFullPath(path), targets.SourcePath);
            Assert.Equal(2, targets.Hosts.Count);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Load_RejectsLargeFilesAndInvalidEncoding()
    {
        var path = Path.GetTempFileName();
        try
        {
            using (var stream = File.OpenWrite(path)) stream.SetLength(NetworkTargetFile.MaxFileBytes + 1L);
            Assert.Contains("8 MiB", Assert.Throws<ArgumentException>(() => NetworkTargetFile.Load(path)).Message);
            File.WriteAllBytes(path, [0xff, 0xff]);
            Assert.Throws<DecoderFallbackException>(() => NetworkTargetFile.Load(path));
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("--targets-file")]
    [InlineData("--target-file")]
    [InlineData("-t")]
    public void CliOption_LoadsAnImmutableSnapshotAndPassesItToNetworkDiscovery(string optionName)
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "192.0.2.0/30\nSERVER01\n");
            var root = Program.BuildRootCommand();
            var result = root.Parse(["network", optionName, path, "--dns-server", "192.0.2.53", "--enum-only"]);
            Assert.Empty(result.Errors);
            var option = (Option<NetworkTargetFile?>)root.Subcommands.Single(command => command.Name == "network").Options.Single(option => option.Name == "--targets-file");
            File.Delete(path);
            var targets = result.GetValue(option)!;
            Assert.Equal(3, targets.Hosts.Count);
            var target = FileSystemScanTarget.Parse(null, false, null, null, targets);
            Assert.Equal(FileSystemScanMode.TargetsFile, target.Mode);
            Assert.Contains("3 hosts", target.DisplayName);
            var hostTargets = SmbKerberosService.GetNetworkHostTargets(target);
            Assert.Equal(targets.Hosts, hostTargets.Select(host => host.Host));
            Assert.All(hostTargets, host => Assert.Null(host.Share));
            Assert.Throws<NotSupportedException>(() => ((IList<string>)targets.Hosts).Add("other"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void CliOption_RejectsConflictingTargetsAndInvalidFiles()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "server01\n");
            var root = Program.BuildRootCommand();
            Assert.NotEmpty(root.Parse(["network", "--targets-file", path, "--device", "server02"]).Errors);
            Assert.NotEmpty(root.Parse(["network", "--targets-file", path, "--subnet", "192.0.2.0/30"]).Errors);
            Assert.NotEmpty(root.Parse(["network", "--targets-file", path, "--targets-file", path]).Errors);
            File.WriteAllText(path, "server01\n# note\nnot a host\n");
            Assert.Contains(root.Parse(["network", "--targets-file", path]).Errors, error => error.Message.Contains("line 3:"));
            File.Delete(path);
            Assert.Contains(root.Parse(["network", "--targets-file", path]).Errors, error => error.Message.Contains("--targets-file:"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ExistingSubnetExpansion_IsAlsoBounded()
        => Assert.Throws<ArgumentException>(() => SmbDiscoveryService.EnumerateSubnetHosts("0.0.0.0/0"));
}
