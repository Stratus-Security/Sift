namespace Stratus.Sift.Cli.Tests;

public sealed class NtHashFormatTests
{
    private const string Nt = "8846f7eaee8fb117ad06bdd830b7586c";
    private const string Lm = "aad3b435b51404eeaad3b435b51404ee";

    public static TheoryData<string> AcceptedFormats => new()
    {
        Nt, Nt.ToUpperInvariant(), " \t" + Nt + "\r\n", ":" + Nt, Lm + ":" + Nt,
        "  " + Lm + " : " + Nt + "  ", "' :" + Nt + " '", "\"" + Lm + ":" + Nt + "\"",
        "$NT$" + Nt, "NT:" + Nt, " ntlm : " + Nt,
        "Administrator:500:" + Lm + ":" + Nt + ":::",
        @"CONTOSO\alice:1105:" + Lm + ":" + Nt,
        "alice:::" + Nt + ":::",
        "alice:1105::" + Nt + ":comment:home:metadata"
    };

    [Theory]
    [MemberData(nameof(AcceptedFormats))]
    public void CommonHashFormats_ReachCredentialCreationAndCliValidation(string value)
    {
        Assert.True(CliWindowsCredential.IsValidNtHash(value));
        using var credential = CliWindowsCredential.Create("Administrator", null, null,
            useLocalMachine: true, ntHash: value);
        Assert.Equal(Convert.FromHexString(Nt), credential!.NtHash);
        Assert.Null(credential.Password);
        Assert.Empty(Program.BuildRootCommand().Parse(
            ["network", "-d", "server", "--username", "Administrator", "--local", "-H", value]).Errors);
    }

    [Theory]
    [InlineData("")]
    [InlineData(":")]
    [InlineData(Lm + ":")]
    [InlineData("not-an-lm-hash:" + Nt)]
    [InlineData(Nt + ":" + Nt + ":" + Nt)]
    [InlineData("alice:not-a-rid:" + Lm + ":" + Nt + ":::")]
    [InlineData("alice:500:bad-lm:" + Nt + ":::")]
    [InlineData("alice:500:" + Lm + ":short:::")]
    [InlineData(Nt + "\n" + Nt)]
    [InlineData("alice::CONTOSO:1122334455667788:" + Nt + ":0101000000000000")]
    [InlineData("alice::CONTOSO:" + Nt + ":" + Nt + ":1122334455667788")]
    public void AmbiguousOrUnusableValues_AreRejected(string value)
    {
        Assert.False(CliWindowsCredential.IsValidNtHash(value));
        Assert.NotEmpty(Program.BuildRootCommand().Parse(
            ["network", "-d", "server", "--username", "Administrator", "--local", "-H", value]).Errors);
    }

    [Fact]
    public void EnvironmentVariable_AcceptsFullPwdumpRecord()
    {
        var variable = "SIFT_TEST_FORMATTED_HASH_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(variable, "Administrator:500:" + Lm + ":" + Nt + ":::");
        try
        {
            Assert.Empty(Program.BuildRootCommand().Parse(
                ["network", "-d", "server", "--username", "Administrator", "--local", "--nt-hash-env", variable]).Errors);
        }
        finally { Environment.SetEnvironmentVariable(variable, null); }
    }

    [Theory]
    [InlineData(":" + Nt)]
    [InlineData(Lm + ":" + Nt)]
    [InlineData("Administrator:500:" + Lm + ":" + Nt + ":::")]
    public void FormattedHashes_StillRejectKerberosAuthentication(string value)
    {
        Assert.Contains(Program.BuildRootCommand().Parse(
                ["network", "-d", "server", "--username", @"CONTOSO\alice", "-H", value, "--kerberos"]).Errors,
            error => error.Message.Contains("pass-the-hash uses NTLMv2", StringComparison.Ordinal));
    }

    [Fact]
    public void EquivalentHashFormats_PreserveResumeIdentity()
    {
        using var raw = CliWindowsCredential.Create("alice", null, "CONTOSO", ntHash: Nt);
        using var pair = CliWindowsCredential.Create("alice", null, "CONTOSO", ntHash: Lm + ":" + Nt);
        var target = new FileSystemScanTarget(FileSystemScanMode.Device, "server");
        Assert.Equal(
            CliResumeIdentity.CreateFilesystemScope(target, @"\\server\Data", "rules", false, null, raw, false, null),
            CliResumeIdentity.CreateFilesystemScope(target, @"\\server\Data", "rules", false, null, pair, false, null));
    }

    [Fact]
    public void InvalidHashErrors_DoNotEchoSuppliedSecret()
    {
        const string value = "not-a-valid-secret";
        var error = Assert.Throws<ArgumentException>(() => CliWindowsCredential.Create("alice", null, "CONTOSO", ntHash: value));
        Assert.DoesNotContain(value, error.Message);
    }
}
