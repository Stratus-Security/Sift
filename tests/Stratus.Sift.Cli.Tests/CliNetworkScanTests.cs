using Stratus.Sift.Cli;
using Microsoft.Extensions.DependencyInjection;
using Stratus.Sift.FileSystem;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Atlassian;
using Stratus.Sift.Connectors.Services;
using Stratus.Sift.Connectors.Slack;
using SMBLibrary;
using System.DirectoryServices.Protocols;
using System.Runtime.Versioning;
using System.Text.Json;

namespace Stratus.Sift.Cli.Tests;

public class CliNetworkScanTests
{
    [Fact]
    public void RemoteCliScans_DefaultToFullScan()
    {
        Assert.True(CliScanRunner.DefaultFullScan);
    }

    [Fact]
    public void SmbScans_DefaultToKerberosPreferredAuthentication()
    {
        var domainCredential = CliWindowsCredential.Create("alice", "secret", null, preferDomainAccount: true);
        var localCredential = CliWindowsCredential.Create("alice", "secret", null, useLocalMachine: true);

        Assert.True(CliScanRunner.ShouldUseKerberosPreferredAuthentication(null));
        Assert.True(CliScanRunner.ShouldUseKerberosPreferredAuthentication(domainCredential));
        Assert.False(CliScanRunner.ShouldUseKerberosPreferredAuthentication(localCredential));
    }

    [Theory]
    [InlineData(unchecked((int)0x80090303), true)]
    [InlineData(unchecked((int)0x8009030E), true)]
    [InlineData(unchecked((int)0x80090311), true)]
    [InlineData(unchecked((int)0x8009030C), false)]
    public void KerberosFallback_OnlyUsesNtlmForUnavailableConditions(int securityStatus, bool expected)
    {
        var exception = new SmbAuthenticationException(
            "Kerberos",
            NTStatus.STATUS_LOGON_FAILURE,
            securityStatus,
            "authentication failed");

        Assert.Equal(expected, SmbKerberosService.ShouldFallbackToNtlm(exception));
    }

    [Fact]
    public void SspiSmbAuthenticationClient_UsesExplicitPackagesWithoutNegotiate()
    {
        using var kerberos = new SspiSmbAuthenticationClient("server.contoso.com", "Kerberos");
        using var ntlm = new SspiSmbAuthenticationClient("server.contoso.com", "NTLM");

        Assert.Equal("Kerberos", kerberos.SecurityPackage);
        Assert.Equal("NTLM", ntlm.SecurityPackage);
        Assert.Equal("cifs/server.contoso.com", kerberos.TargetName);
    }

    [Fact]
    public void SspiSmbAuthenticationClient_TruncatesKerberosAesKeyForSmbSigning()
    {
        var kerberosAesKey = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();

        var smbSessionKey = SspiSmbAuthenticationClient.NormalizeSmbSessionKey(kerberosAesKey);

        Assert.Equal(16, smbSessionKey.Length);
        Assert.Equal(kerberosAesKey[..16], smbSessionKey);
    }

    [Fact]
    public void SspiSmbAuthenticationClient_PreservesShorterSessionKeys()
    {
        var sessionKey = Enumerable.Range(0, 8).Select(value => (byte)value).ToArray();

        var smbSessionKey = SspiSmbAuthenticationClient.NormalizeSmbSessionKey(sessionKey);

        Assert.Equal(sessionKey, smbSessionKey);
        Assert.NotSame(sessionKey, smbSessionKey);
    }

    [Fact]
    public void Parse_SelectsFolderMode()
    {
        var target = FileSystemScanTarget.Parse(@"C:\Data", domain: false, subnet: null, device: null);

        Assert.Equal(FileSystemScanMode.Folder, target.Mode);
        Assert.Equal(@"C:\Data", target.Value);
    }

    [Fact]
    public void Parse_SelectsDomainMode()
    {
        var target = FileSystemScanTarget.Parse(null, domain: true, subnet: null, device: null);

        Assert.Equal(FileSystemScanMode.Domain, target.Mode);
    }

    [Fact]
    public void Parse_RejectsMultipleModes()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            FileSystemScanTarget.Parse(@"C:\Data", domain: true, subnet: null, device: null));

        Assert.Contains("Specify exactly one", exception.Message);
    }

    [Fact]
    public void EnumerateSubnetHosts_ReturnsExpectedHostAddresses()
    {
        var hosts = SmbDiscoveryService.EnumerateSubnetHosts("10.0.0.0/30");

        Assert.Equal(["10.0.0.1", "10.0.0.2"], hosts);
    }

    [Fact]
    public void EnumerateSubnetHosts_AllowsSingleIpv4Host()
    {
        var hosts = SmbDiscoveryService.EnumerateSubnetHosts("10.0.0.10");

        Assert.Equal(["10.0.0.10"], hosts);
    }

    [Fact]
    public void BuildRootCommand_NetworkRequiresExactlyOneTarget()
    {
        var rootCommand = Program.BuildRootCommand();

        var noneSpecified = rootCommand.Parse(["network"]);
        var bothSpecified = rootCommand.Parse(["network", "--subnet", "10.0.0.10", "--device", "10.0.0.10"]);

        Assert.Contains(noneSpecified.Errors, error => error.Message.Contains("Specify exactly one of --subnet or --device.", StringComparison.Ordinal));
        Assert.Contains(bothSpecified.Errors, error => error.Message.Contains("Specify exactly one of --subnet or --device.", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_NetworkAcceptsSingleIpSubnet()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "--subnet", "10.0.0.10"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_NetworkAcceptsSingleIpDevice()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "--device", "10.0.0.10"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_LocalAcceptsShortAliases()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["local", "-p", @"C:\Data", "-e", "-b", "-r", @"C:\Rules", "-o", "scan.txt", "-f", "cli"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_LocalAcceptsSnafflerMode()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["local", "--path", @"C:\Data", "--snaffler-mode"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_FilesystemCommandsAcceptPerformanceOptions()
    {
        var rootCommand = Program.BuildRootCommand();

        var local = rootCommand.Parse([
            "local", "--path", @"C:\Data", "--threads", "12",
            "--max-read-mib-per-second", "64", "--diagnostics-output", "scan-diagnostics.json"]);
        var network = rootCommand.Parse([
            "network", "--device", "server", "--threads", "24",
            "--max-read-mib-per-second", "0"]);

        Assert.Empty(local.Errors);
        Assert.Empty(network.Errors);
    }

    [Theory]
    [InlineData("--threads", "-1")]
    [InlineData("--threads", "257")]
    [InlineData("--max-read-mib-per-second", "-1")]
    public void BuildRootCommand_LocalRejectsInvalidPerformanceOptions(string option, string value)
    {
        var parseResult = Program.BuildRootCommand().Parse(["local", "--path", @"C:\Data", option, value]);

        Assert.NotEmpty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_NetworkAcceptsEnumOnly()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "--device", "10.0.0.10", "--enum-only"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_NetworkAcceptsShortAliases()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "-s", "10.0.0.10", "-u", "alice", "-p", "secret", "-a", "contoso", "-e"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_DomainAcceptsImpersonationCredentials()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", "--username", "contoso\\alice", "--password", "secret"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_DomainAcceptsEnumOnly()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", "--enum-only"]);

        Assert.Empty(parseResult.Errors);
    }

    [Theory]
    [InlineData("--kerberos")]
    [InlineData("-k")]
    public void BuildRootCommand_NetworkAcceptsStrictKerberos(string option)
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "--device", "server.contoso.com", "--username", "alice", "--password", "secret", "--domain", "contoso.com", option]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_NetworkKerberosAcceptsUnqualifiedDomainUsername()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "--device", "10.0.0.10", "--username", "alice", "--password", "secret", "--kerberos"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_DomainAcceptsStrictKerberos()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", "--username", "alice", "--password", "secret", "--domain", "contoso.com", "--kerberos"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_KerberosRejectsLocalAuthentication()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "--device", "server", "--username", "alice", "--password", "secret", "--local", "--kerberos"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("cannot be combined with --local", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("dc01.contoso.com")]
    [InlineData("dc01")]
    [InlineData("10.0.0.10")]
    [InlineData("2001:db8::10")]
    public void BuildRootCommand_DomainAcceptsDomainController(string domainController)
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", "--domain-controller", domainController]);

        Assert.Empty(parseResult.Errors);
    }

    [Theory]
    [InlineData("--dc")]
    [InlineData("-dc")]
    public void BuildRootCommand_DomainAcceptsDomainControllerAlias(string alias)
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", alias, "10.0.0.10"]);

        Assert.Empty(parseResult.Errors);
    }

    [Theory]
    [InlineData("ldap://dc01.contoso.com")]
    [InlineData("dc01.contoso.com:389")]
    [InlineData("dc01.contoso.com/path")]
    public void BuildRootCommand_DomainRejectsInvalidDomainController(string domainController)
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", "--domain-controller", domainController]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("must be a hostname or IP address", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false, AuthType.Negotiate)]
    [InlineData(true, AuthType.Kerberos)]
    public void ActiveDirectoryDiscovery_UsesExpectedAuthentication(bool strictKerberos, AuthType expected)
    {
        Assert.Equal(expected, ActiveDirectoryLdapDiscovery.GetAuthenticationType(strictKerberos));
    }

    [Theory]
    [InlineData("10.0.0.10")]
    [InlineData("2001:db8::10")]
    public void ActiveDirectoryDiscovery_StrictKerberosRejectsIpController(string domainController)
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            ActiveDirectoryLdapDiscovery.ValidateAuthenticationTarget(domainController, strictKerberos: true));

        Assert.Contains("resolvable domain-controller hostname", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("10.0.0.10", false)]
    [InlineData("dc01.contoso.com", false)]
    [InlineData("dc01.contoso.com", true)]
    public void ActiveDirectoryDiscovery_AcceptsSupportedControllerAuthentication(string domainController, bool strictKerberos)
    {
        ActiveDirectoryLdapDiscovery.ValidateAuthenticationTarget(domainController, strictKerberos);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task ActiveDirectoryDiscovery_PreCancelledRequestDoesNotStartNetworkAccess()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var discovery = new ActiveDirectoryLdapDiscovery(new CliDnsResolver());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            discovery.EnumerateComputersAsync(
                "127.0.0.1",
                credential: null,
                strictKerberos: false,
                dnsServer: null,
                cancellation.Token));
    }

    [Fact]
    public void WindowsCredential_CreatesLdapNetworkCredentialWithoutChangingIdentity()
    {
        var credential = CliWindowsCredential.Create("alice", "secret", "CONTOSO", preferDomainAccount: true)!;

        var networkCredential = credential.ToNetworkCredential();

        Assert.Equal("alice", networkCredential.UserName);
        Assert.Equal("secret", networkCredential.Password);
        Assert.Equal("CONTOSO", networkCredential.Domain);
    }

    [Fact]
    public void BuildRootCommand_DomainAcceptsShortAliases()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", "-u", "alice", "-p", "secret", "-d", "contoso", "-e"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_Microsoft365AcceptsEnumOnly()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["m365", "--enum-only"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_Microsoft365AcceptsShortOptions()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["m365", "-s", "https://contoso.sharepoint.com/sites/Finance", "-i", "-e", "-o", "scan.json", "-f", "json"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_SlackAcceptsConnectorOptions()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["slack", "--token", "xoxb-test", "--channel", "security", "--channel", "C123", "--enum-only"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_SlackAcceptsBrowserAuthentication()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["slack", "--browser", "--workspace-url", "https://example.slack.com", "--browser-channel", "msedge", "--channel", "security", "--full-scan"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_SlackRejectsBrowserAndTokenTogether()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["slack", "--browser", "--token", "xoxb-test"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("either --browser or a Slack token", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("--full-scan")]
    [InlineData("--resume")]
    public void BuildRootCommand_AtlassianAcceptsScanModeOptions(string option)
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["atlassian", "--url", "https://example.atlassian.net", option]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_RejectsRemovedIncrementalAlias()
    {
        var parseResult = Program.BuildRootCommand().Parse(["local", "--path", @"C:\Data", "--incremental"]);

        Assert.NotEmpty(parseResult.Errors);
    }

    [Theory]
    [InlineData("local", "--path", @"C:\Data")]
    [InlineData("domain", null, null)]
    [InlineData("network", "--device", "server.example.test")]
    [InlineData("m365", null, null)]
    [InlineData("slack", "--token", "xoxb-test")]
    [InlineData("atlassian", "--url", "https://example.atlassian.net")]
    public void BuildRootCommand_AllScanTypesAcceptResume(string commandName, string? requiredOption, string? requiredValue)
    {
        var arguments = new List<string> { commandName };
        if (requiredOption != null)
        {
            arguments.Add(requiredOption);
            arguments.Add(requiredValue!);
        }
        arguments.Add("--resume");

        var parseResult = Program.BuildRootCommand().Parse(arguments.ToArray());

        Assert.Empty(parseResult.Errors);
    }

    [Theory]
    [InlineData("local", "--path", @"C:\Data")]
    [InlineData("domain", null, null)]
    [InlineData("network", "--device", "server.example.test")]
    [InlineData("m365", null, null)]
    [InlineData("slack", "--token", "xoxb-test")]
    [InlineData("atlassian", "--url", "https://example.atlassian.net")]
    public void BuildRootCommand_ResumeRejectsEnumerationOnly(string commandName, string? requiredOption, string? requiredValue)
    {
        var arguments = new List<string> { commandName };
        if (requiredOption != null)
        {
            arguments.Add(requiredOption);
            arguments.Add(requiredValue!);
        }
        arguments.AddRange(["--resume", "--enum-only"]);

        var parseResult = Program.BuildRootCommand().Parse(arguments.ToArray());

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("cannot be combined", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_AtlassianAcceptsExplicitIncrementalFullScanValue()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["atlassian", "--url", "https://example.atlassian.net", "--full-scan", "false"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void SlackBrowserCredential_ExtractsWebTokenOnlyFromSlackApiRequest()
    {
        var extracted = SlackBrowserCredential.TryExtract(
            "https://example.slack.com/api/client.boot",
            "token=xoxc-123456-ABCDEF&team_id=T123&include_min_version=1",
            out var credential);
        var rejected = SlackBrowserCredential.TryExtract(
            "https://slack.example.test/api/client.boot",
            "token=xoxc-stolen",
            out _);

        Assert.True(extracted);
        Assert.False(rejected);
        Assert.Equal("xoxc-123456-ABCDEF", credential.Token);
        Assert.Equal("https://example.slack.com/api/", credential.ApiBaseUri.AbsoluteUri);
        Assert.Equal("T123", credential.WorkspaceId);
    }

    [Fact]
    public async Task SlackBrowserDrive_PaginatesConversationHistory()
    {
        var session = new FakeSlackBrowserSession(
            """{"ok":true,"messages":[{"type":"message","user":"U1","text":"first secret","ts":"100.000001"}],"response_metadata":{"next_cursor":"page-2"}}""",
            """{"ok":true,"messages":[{"type":"message","user":"U2","text":"second secret","ts":"200.000001"}],"response_metadata":{"next_cursor":""}}""");
        var drive = new SlackBrowserDrive(session, "T1", "Example", "https://example.slack.com", "C1", "security");

        var result = await drive.GetChangesAsync(null);
        var files = result.Changes.ToArray();

        Assert.Equal(2, files.Length);
        Assert.Equal("200.000001", result.NewDeltaToken);
        Assert.Equal([null, "page-2"], session.Cursors);
    }

    [Fact]
    public async Task SlackBrowserDrive_EmitsAllRootMessagesBeforeExpandingThreads()
    {
        var session = new RoutingSlackBrowserSession((method, parameters) => (method, parameters.GetValueOrDefault("cursor")) switch
        {
            ("conversations.history", null) => """{"ok":true,"messages":[{"type":"message","user":"U1","text":"thread parent","ts":"100.000001","reply_count":1,"latest_reply":"150.000001"}],"response_metadata":{"next_cursor":"page-2"}}""",
            ("conversations.history", "page-2") => """{"ok":true,"messages":[{"type":"message","user":"U2","text":"later root","ts":"200.000001"}],"response_metadata":{"next_cursor":""}}""",
            ("conversations.replies", _) => """{"ok":true,"messages":[{"type":"message","user":"U1","text":"thread parent","ts":"100.000001"},{"type":"message","user":"U3","text":"thread reply","ts":"150.000001"}],"response_metadata":{"next_cursor":""}}""",
            _ => throw new InvalidOperationException(method)
        });
        var drive = new SlackBrowserDrive(session, "T1", "Example", "https://example.slack.com", "C1", "security");

        var result = await drive.GetChangesAsync(null);

        Assert.Equal(
            ["conversations.history", "conversations.history", "conversations.replies"],
            session.Calls.Select(call => call.Method));
        Assert.Equal(
            ["message-100-000001.txt", "message-200-000001.txt", "message-150-000001.txt"],
            result.Changes.Select(file => file.Name));
    }

    [Fact]
    public void SlackCheckpoint_RoundTripsHistoryAndReplyProgress()
    {
        var token = SlackDrive.CreateCheckpoint(
            "100.000001",
            "next-page",
            "300.000001",
            repliesPhase: true,
            ["110.000001", "120.000001"]);

        var resumed = SlackDrive.ParseCheckpoint(token);

        Assert.Equal("100.000001", resumed.Boundary);
        Assert.Equal("next-page", resumed.Cursor);
        Assert.Equal("300.000001", resumed.Newest);
        Assert.True(resumed.RepliesPhase);
        Assert.Equal(["110.000001", "120.000001"], resumed.ThreadParents);
    }

    [Fact]
    public void SmbCheckpoint_RoundTripsPendingDirectoryStack()
    {
        var pending = new Stack<string>();
        pending.Push(@"Finance\2025");
        pending.Push(@"Engineering\Builds");

        var resumed = SmbKerberosDrive.ParseCheckpoint(SmbKerberosDrive.CreateCheckpoint(pending));

        Assert.Equal(pending.ToArray(), resumed.ToArray());
    }

    [Fact]
    public async Task SlackBrowserDrive_DefaultRulesClassifySecretsInMessageText()
    {
        var browserSession = new RoutingSlackBrowserSession((method, _) => method switch
        {
            "conversations.history" => """{"ok":true,"messages":[{"type":"message","user":"U1","text":"api_secret: sK9pQ2vN7xL4mR8t","ts":"100.000001"}],"response_metadata":{"next_cursor":""}}""",
            _ => throw new InvalidOperationException(method)
        });
        var drive = new SlackBrowserDrive(browserSession, "T1", "Example", "https://example.slack.com", "C1", "security");
        await using var scannerSession = await CliScannerBootstrap.InitializeScannerAsync(null, Program.CreateHost);
        var scanner = scannerSession.Host.Services.GetRequiredService<RemoteDriveScanner>();
        var issues = new List<ScanFinding>();

        await scanner.ScanDriveChangesAsync(
            drive,
            deltaToken: null,
            scannerSession.Optimizer,
            scannerSession.PolicyMap,
            scannerSession.IgnoreRules,
            new Stratus.Sift.Scanner.Models.ScanOptions(),
            issue =>
            {
                issues.Add(issue);
                return Task.CompletedTask;
            },
            onCheckpointToken: null,
            onNewDeltaToken: _ => Task.CompletedTask,
            onFilesScanned: null,
            onQueueDepth: null,
            onCurrentPath: null,
            ensureScanActive: null,
            cancellationToken: CancellationToken.None);

        Assert.Contains(issues, issue => issue.ClassifierName == "Environment Secret Assignment");
    }

    [Fact]
    public async Task SlackBrowserDiscovery_UnionsUnjoinedPublicChannelsWithJoinedPrivateConversations()
    {
        var session = new RoutingSlackBrowserSession((method, parameters) => (method, parameters.GetValueOrDefault("cursor")) switch
        {
            ("conversations.list", null) => """{"ok":true,"channels":[{"id":"C1","name":"unjoined-public"},{"id":"C2","name":"shared-public"}],"response_metadata":{"next_cursor":"public-2"}}""",
            ("conversations.list", "public-2") => """{"ok":true,"channels":[{"id":"C3","name":"another-public"}],"response_metadata":{"next_cursor":""}}""",
            ("users.conversations", _) => """{"ok":true,"channels":[{"id":"C2","name":"shared-public"},{"id":"G1","name":"private-security"},{"id":"D1","is_im":true,"user":"U2"}],"response_metadata":{"next_cursor":""}}""",
            _ => throw new InvalidOperationException(method)
        });

        var conversations = await SlackBrowserConnector.DiscoverConversationsAsync(session, "T1");

        Assert.Equal(5, conversations.Count);
        Assert.Contains(conversations, conversation => conversation.Id == "C1" && conversation.Name == "unjoined-public");
        Assert.Contains(conversations, conversation => conversation.Id == "G1" && conversation.Name == "private-security");
        Assert.Contains(conversations, conversation => conversation.Id == "D1" && conversation.Name == "dm-U2");
        Assert.Equal(2, session.Calls.Count(call => call.Method == "conversations.list"));
        var joinedCall = Assert.Single(session.Calls, call => call.Method == "users.conversations");
        Assert.Equal("private_channel,mpim,im", joinedCall.Parameters.GetValueOrDefault("types"));
    }

    [Fact]
    public async Task SlackBrowserDrive_IncrementalScanOnlyLoadsThreadsWithNewReplies()
    {
        var session = new RoutingSlackBrowserSession((method, parameters) => method switch
        {
            "conversations.history" => """
                {"ok":true,"messages":[
                  {"type":"message","user":"U1","text":"edited parent","ts":"100.000001","edited":{"ts":"250.000001"},"reply_count":1,"latest_reply":"150.000001"},
                  {"type":"message","user":"U2","text":"active thread","ts":"110.000001","reply_count":1,"latest_reply":"300.000001"}
                ],"response_metadata":{"next_cursor":""}}
                """,
            "conversations.replies" => """
                {"ok":true,"messages":[
                  {"type":"message","user":"U2","text":"active thread","ts":"110.000001"},
                  {"type":"message","user":"U3","text":"new reply secret","ts":"300.000001"}
                ],"response_metadata":{"next_cursor":""}}
                """,
            _ => throw new InvalidOperationException(method)
        });
        var drive = new SlackBrowserDrive(session, "T1", "Example", "https://example.slack.com", "C1", "security");

        var result = await drive.GetChangesAsync("200.000001");
        var files = result.Changes.ToArray();

        Assert.Equal("300.000001", result.NewDeltaToken);
        Assert.Contains(files, file => file.Name == "message-100-000001.txt");
        Assert.Contains(files, file => file.Name == "message-300-000001.txt");
        var repliesCall = Assert.Single(session.Calls, call => call.Method == "conversations.replies");
        Assert.Equal("110.000001", repliesCall.Parameters.GetValueOrDefault("ts"));
        Assert.Equal("200.000001", repliesCall.Parameters.GetValueOrDefault("oldest"));
    }

    [Theory]
    [InlineData("sharepoint")]
    [InlineData("office365")]
    [InlineData("jira")]
    [InlineData("slack-export")]
    public void BuildRootCommand_RejectsRemovedSourceCommands(string commandName)
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse([commandName]);

        Assert.NotEmpty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_AtlassianAcceptsJiraAndConfluenceOptions()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["atlassian", "--url", "https://example.atlassian.net", "--email", "user@stratus.security", "--cloud-id", "cloud-1", "--token", "test", "--project", "SEC", "--space", "ENG", "--jql", "status != Done", "--enum-only"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void CreateHost_ResolvesCanonicalCloudConnectors()
    {
        using var host = Program.CreateHost();

        var providers = host.Services.GetServices<IConnector>().Select(connector => connector.ProviderName).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("Slack", providers);
        Assert.Contains("Atlassian", providers);
        Assert.Contains("Microsoft 365", providers);
    }

    [Fact]
    public void JiraDrive_GetDocumentText_FlattensAtlassianDocumentFormat()
    {
        using var document = JsonDocument.Parse("""
            {"description":{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"first secret"},{"type":"text","text":"second value"}]}]}}
            """);

        var text = JiraDrive.GetDocumentText(document.RootElement, "description");

        Assert.Contains("first secret", text, StringComparison.Ordinal);
        Assert.Contains("second value", text, StringComparison.Ordinal);
    }

    [Fact]
    public void SlackDrive_ExtractMessageText_IncludesBlockText()
    {
        using var document = JsonDocument.Parse("""
            {"text":"fallback text","blocks":[{"type":"section","text":{"type":"mrkdwn","text":"block secret"}}]}
            """);

        var text = SlackDrive.ExtractMessageText(document.RootElement);

        Assert.Contains("fallback text", text, StringComparison.Ordinal);
        Assert.Contains("block secret", text, StringComparison.Ordinal);
    }

    [Fact]
    public void CliSnafflerFormatter_FormatsFileResultsLikeSnaffler()
    {
        var formatter = new CliSnafflerFormatter("[alice@HOST]");
        var finding = new ScanFinding
        {
            ClassifierName = "Azure Client Secret",
            RuleName = "Azure Client Secret",
            ResourcePath = @"C:\temp\secret.txt",
            Severity = Severity.High,
            RedactedValue = "client_secret",
            Snippet = "client_secret = value"
        };
        var context = new CliSnafflerFormatter.CliFindingDisplayContext(
            CliSnafflerFormatter.CliSnafflerResultKind.File,
            128,
            new DateTime(2026, 3, 20, 1, 2, 3, DateTimeKind.Utc),
            "R");

        var line = formatter.FormatFinding(
            finding,
            finding.ResourcePath,
            context,
            new DateTimeOffset(2026, 3, 20, 4, 5, 6, TimeSpan.Zero));

        Assert.Equal("[alice@HOST] 2026-03-20 04:05:06Z [File] {Red}<Azure Client Secret|R|client_secret|128B|2026-03-20 01:02:03Z>(C:\\temp\\secret.txt) client_secret = value", line.PlainText);
    }

    [Fact]
    public void CliSnafflerFormatter_UsesRawSnippetValue_NotMaskedValue()
    {
        var formatter = new CliSnafflerFormatter("[alice@HOST]");
        var finding = new ScanFinding
        {
            ClassifierName = "API Key",
            RuleName = "API Key",
            ResourcePath = @"C:\temp\secret.txt",
            Severity = Severity.High,
            RedactedValue = "ab********",
            Snippet = "token = abcdefghij12345"
        };
        var context = new CliSnafflerFormatter.CliFindingDisplayContext(
            CliSnafflerFormatter.CliSnafflerResultKind.File,
            64,
            new DateTime(2026, 3, 20, 1, 2, 3, DateTimeKind.Utc),
            "R");

        var line = formatter.FormatFinding(
            finding,
            finding.ResourcePath,
            context,
            new DateTimeOffset(2026, 3, 20, 4, 5, 6, TimeSpan.Zero));

        Assert.Contains("|abcdefghij12345|", line.PlainText, StringComparison.Ordinal);
        Assert.DoesNotContain("|ab********|", line.PlainText, StringComparison.Ordinal);
    }

    [Fact]
    public void CliSnafflerFormatter_FormatsShareDiscoveryLikeSnaffler()
    {
        var formatter = new CliSnafflerFormatter("[alice@HOST]");

        var line = formatter.FormatShareDiscovery(
            @"\\server\C$",
            "R",
            null,
            new DateTimeOffset(2026, 3, 20, 4, 5, 6, TimeSpan.Zero));

        Assert.Equal("[alice@HOST] 2026-03-20 04:05:06Z [Share] {Green}<\\\\server\\C$>(R)", line.PlainText);
    }

    [Fact]
    public void CliSnafflerFormatter_FormatsDirectoryDiscoveryLikeSnaffler()
    {
        var formatter = new CliSnafflerFormatter("[alice@HOST]");

        var line = formatter.FormatDirectoryDiscovery(
            @"C:\Data",
            new DateTimeOffset(2026, 3, 20, 4, 5, 6, TimeSpan.Zero));

        Assert.Equal("[alice@HOST] 2026-03-20 04:05:06Z [Dir] {Green}(C:\\Data)", line.PlainText);
    }

    [Fact]
    public void CliSnafflerFormatter_FormatsDriveDiscoveryAsInfo()
    {
        var formatter = new CliSnafflerFormatter("[alice@HOST]");

        var line = formatter.FormatDriveDiscovery(
            "Finance",
            "drive-1",
            "SharePoint",
            "https://contoso.sharepoint.com/sites/Finance",
            new DateTimeOffset(2026, 3, 20, 4, 5, 6, TimeSpan.Zero));

        Assert.Equal("[alice@HOST] 2026-03-20 04:05:06Z [Info] Discovered drive: Finance (drive-1) [SharePoint] - https://contoso.sharepoint.com/sites/Finance", line.PlainText);
    }

    [Fact]
    public void CliAccessSummary_ReportsRwm_WhenAclAllowsModify()
    {
        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "S-1-5-21-test-1001" };
        var acls = new List<AclEntry>
        {
            new()
            {
                Identity = "S-1-5-21-test-1001",
                AccessControlType = "Allow",
                Permissions = "Modify, Synchronize"
            }
        };

        var summary = CliAccessSummary.ForReadableRoot(acls, identities);

        Assert.Equal("RWM", summary);
    }

    [Fact]
    public void CliAccessSummary_DoesNotReportWrite_WhenAclDeniesIt()
    {
        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "S-1-5-21-test-1001" };
        var acls = new List<AclEntry>
        {
            new()
            {
                Identity = "S-1-5-21-test-1001",
                AccessControlType = "Allow",
                Permissions = "Write, ReadAndExecute"
            },
            new()
            {
                Identity = "S-1-5-21-test-1001",
                AccessControlType = "Deny",
                Permissions = "Write"
            }
        };

        var summary = CliAccessSummary.ForReadableRoot(acls, identities);

        Assert.Equal("R", summary);
    }

    [Fact]
    public void BuildRootCommand_NetworkAcceptsExplicitImpersonationDomain()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "--device", "10.0.0.10", "--username", "alice", "--password", "secret", "--domain", "contoso"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_NetworkAcceptsLocalImpersonation()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "--device", "10.0.0.10", "--username", "alice", "--password", "secret", "--local"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_DomainRejectsIncompleteImpersonationCredentials()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", "--username", "alice"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("exactly one of --password or --nt-hash", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_DomainRejectsAmbiguousQualifiedUsernameAndDomain()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", "--username", "contoso\\alice", "--password", "secret", "--domain", "contoso"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("Use either a qualified --username or --domain", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_DomainRejectsConflictingLocalAndDomain()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["domain", "--username", "alice", "--password", "secret", "--domain", "contoso", "--local"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("Use either --domain or --local", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_NetworkAcceptsDomainNtHash()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse([
            "network", "--device", "10.0.0.10", "--username", "alice",
            "--nt-hash", "8846f7eaee8fb117ad06bdd830b7586c", "--domain", "contoso"]);

        Assert.Empty(parseResult.Errors);
    }

    [Fact]
    public void BuildRootCommand_NetworkAcceptsLocalNtHashAlias()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse([
            "network", "--device", "10.0.0.10", "--username", "Administrator",
            "-H", "8846F7EAEE8FB117AD06BDD830B7586C", "--local"]);

        Assert.Empty(parseResult.Errors);
    }

    [Theory]
    [InlineData("not-a-hash")]
    [InlineData("8846f7eaee8fb117ad06bdd830b7586")]
    [InlineData("8846f7eaee8fb117ad06bdd830b7586z")]
    public void BuildRootCommand_NetworkRejectsInvalidNtHash(string ntHash)
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse([
            "network", "--device", "10.0.0.10", "--username", "alice", "--nt-hash", ntHash]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("exactly 32 hexadecimal", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_NetworkRejectsPasswordAndNtHash()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse([
            "network", "--device", "10.0.0.10", "--username", "alice", "--password", "secret",
            "--nt-hash", "8846f7eaee8fb117ad06bdd830b7586c"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("either --password or --nt-hash", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_NetworkRejectsKerberosWithNtHash()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse([
            "network", "--device", "10.0.0.10", "--username", "alice",
            "--nt-hash", "8846f7eaee8fb117ad06bdd830b7586c", "--kerberos"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("pass-the-hash uses NTLMv2", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_NetworkRejectsUnqualifiedNtHashIdentity()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse([
            "network", "--device", "10.0.0.10", "--username", "alice",
            "--nt-hash", "8846f7eaee8fb117ad06bdd830b7586c"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("identity is unambiguous", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_DomainRejectsNtHash()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse([
            "domain", "--username", "alice", "--nt-hash", "8846f7eaee8fb117ad06bdd830b7586c"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("Domain-wide discovery uses LDAP", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRootCommand_NetworkRejectsInvalidSubnet()
    {
        var rootCommand = Program.BuildRootCommand();

        var parseResult = rootCommand.Parse(["network", "--subnet", "not-a-subnet"]);

        Assert.Contains(parseResult.Errors, error => error.Message.Contains("must be an IPv4 CIDR range", StringComparison.Ordinal));
    }

    [Fact]
    public void CreateHost_ResolvesStandardFileSystemEnumerator()
    {
        using var host = Program.CreateHost();

        var enumerator = host.Services.GetRequiredService<StandardFileSystemEnumerator>();

        Assert.NotNull(enumerator);
    }

    [Theory]
    [InlineData("IPC$", 0u, false)]
    [InlineData("ADMIN$", 0x80000000u, true)]
    [InlineData("print$", 0u, false)]
    [InlineData("C$", 0x80000000u, true)]
    [InlineData("Shared", 0u, true)]
    [InlineData("Printer", 1u, false)]
    public void IsCandidateShare_FiltersExpectedShareTypes(string shareName, uint shareType, bool expected)
    {
        var actual = SmbDiscoveryService.IsCandidateShare(shareName, shareType);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void SelectSharesForCoverage_UsesAdminShareWhenCDriveIsUnavailable()
    {
        var selected = SmbDiscoveryService.SelectSharesForCoverage(["ADMIN$", "Shared"]);

        Assert.Equal(["ADMIN$", "Shared"], selected);
    }

    [Fact]
    public void SelectSharesForCoverage_SuppressesAdminShareWhenCDriveIsReadable()
    {
        var selected = SmbDiscoveryService.SelectSharesForCoverage(["ADMIN$", "C$", "Shared"]);

        Assert.Equal(["C$", "Shared"], selected);
    }

    [Fact]
    public void CliWindowsCredential_Create_SplitsQualifiedDomainUser()
    {
        var credential = CliWindowsCredential.Create(@"contoso\alice", "secret", null);

        Assert.NotNull(credential);
        Assert.Equal("alice", credential!.UserName);
        Assert.Equal("contoso", credential.Domain);
    }

    [Fact]
    public void CliWindowsCredential_Create_UsesMachineNameForLocalFlag()
    {
        var credential = CliWindowsCredential.Create("alice", "secret", null, useLocalMachine: true);

        Assert.NotNull(credential);
        Assert.Equal(Environment.MachineName, credential!.Domain);
        Assert.True(credential.IsLocalMachineAccount);
    }

    [Fact]
    public void CliWindowsCredential_Create_LeavesUnqualifiedKerberosUserForRealmInference()
    {
        var credential = CliWindowsCredential.Create("alice", "secret", null, preferDomainAccount: true);

        Assert.NotNull(credential);
        Assert.Null(credential!.Domain);
        Assert.False(credential.IsLocalMachineAccount);
    }

    [Fact]
    public void CliWindowsCredential_Create_ParsesNtHashWithoutRetainingPasswordText()
    {
        var credential = CliWindowsCredential.Create(
            "alice",
            password: null,
            domain: "contoso",
            preferDomainAccount: true,
            ntHash: "8846f7eaee8fb117ad06bdd830b7586c");

        Assert.NotNull(credential);
        Assert.True(credential!.UsesNtHash);
        Assert.Null(credential.Password);
        Assert.Equal("8846F7EAEE8FB117AD06BDD830B7586C", Convert.ToHexString(credential.NtHash!));
        Assert.Throws<InvalidOperationException>(credential.ToNetworkCredential);
    }

    [Fact]
    public void NtlmHashAuthenticationClient_ComputesKnownNtlmv2ResponseKey()
    {
        var ntHash = Convert.FromHexString("8846F7EAEE8FB117AD06BDD830B7586C");

        var responseKey = NtlmHashAuthenticationClient.ComputeResponseKeyNt(ntHash, "User", "Domain");

        Assert.Equal("FD0FB734B3292256B3AAEA9E21F3494E", Convert.ToHexString(responseKey));
    }

    [Theory]
    [InlineData("atlassian://example.atlassian.net/jira/SEC/SEC-42.txt", "https://example.atlassian.net/browse/SEC-42")]
    [InlineData("atlassian://example.atlassian.net/jira/SEC/SEC-42/attachments/credentials.yml", "https://example.atlassian.net/browse/SEC-42")]
    [InlineData("atlassian://example.atlassian.net/confluence/ENG/pages/12345.txt", "https://example.atlassian.net/wiki/spaces/ENG/pages/12345")]
    [InlineData("atlassian://example.atlassian.net/confluence/ENG/blogposts/67890/footer-comments/1.txt", "https://example.atlassian.net/wiki/spaces/ENG/blog/67890")]
    public void CloudResourceLinkNormalizer_ConvertsLegacyAtlassianPaths(string legacyPath, string expected)
    {
        Assert.Equal(expected, CliCloudResourceLinkNormalizer.Normalize(legacyPath, []));
    }

    [Fact]
    public void CloudResourceLinkNormalizer_UsesDiscoveryToConvertLegacySlackMessagePath()
    {
        var events = new List<CliOutputEventRecord>
        {
            new()
            {
                Kind = "discovery",
                Message = "Discovered drive: security (C123) [Slack] - https://example.slack.com/archives/C123"
            }
        };

        var actual = CliCloudResourceLinkNormalizer.Normalize(
            "slack-browser://Example/security/message-1643337430-123456.txt",
            events);

        Assert.Equal("https://example.slack.com/archives/C123/p1643337430123456", actual);
    }

    [Fact]
    public void CloudResourceLinkNormalizer_UsesDiscoveryToConvertLegacySharePointPath()
    {
        var events = new List<CliOutputEventRecord>
        {
            new()
            {
                Kind = "discovery",
                Message = "Discovered drive: Documents (drive-1) [SharePoint] - https://contoso.sharepoint.com/sites/Engineering/Shared%20Documents"
            }
        };

        var actual = CliCloudResourceLinkNormalizer.Normalize("sharepoint://tenant/drive-1", events);

        Assert.Equal("https://contoso.sharepoint.com/sites/Engineering/Shared%20Documents", actual);
    }

    [Fact]
    public void CloudResourceLinkNormalizer_UsesSingleAzureContainerForLegacyBlobPath()
    {
        var events = new List<CliOutputEventRecord>
        {
            new()
            {
                Kind = "discovery",
                Message = "Discovered drive: secrets (secrets) [AzureBlob] - https://storage.blob.core.windows.net/secrets"
            }
        };

        var actual = CliCloudResourceLinkNormalizer.Normalize("build/config file.yml", events);

        Assert.Equal("https://storage.blob.core.windows.net/secrets/build/config%20file.yml", actual);
    }

    [Fact]
    public async Task AnalyzeLoader_PreservesLegacyTextDiscoveryEventsForLinkConversion()
    {
        var path = Path.Combine(Path.GetTempPath(), $"snare-analyze-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllTextAsync(path, """
                Remote Slack scan
                Discovered drive: security (C123) [Slack] - https://example.slack.com/archives/C123
                Finding: API secret
                  Risk: High
                  Path: slack://Example/security/message-1643337430-123456.txt
                  Evidence: api_secret: [REDACTED]
                """);

            var document = await CliAnalysisRunner.LoadAsync(path);

            Assert.Single(document.Events);
            Assert.Equal(
                "https://example.slack.com/archives/C123/p1643337430123456",
                CliCloudResourceLinkNormalizer.Normalize(document.FindingsList[0].ResourcePath, document.Events));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RemoteDriveScanner_FindingResourcePathPrefersBrowserUrlAndFallsBackToInternalPath()
    {
        var linked = new SimpleRemoteFile("1", "issue.txt", "atlassian://example/jira/SEC/SEC-1.txt", "https://example.atlassian.net/browse/SEC-1", "secret");
        var offline = new SimpleRemoteFile("2", "message.txt", "internal://source/message.txt", string.Empty, "secret");

        Assert.Equal("https://example.atlassian.net/browse/SEC-1", RemoteDriveScanner.GetFindingResourcePath(linked));
        Assert.Equal("internal://source/message.txt", RemoteDriveScanner.GetFindingResourcePath(offline));
    }

    private sealed class FakeSlackBrowserSession(params string[] responses) : ISlackBrowserSession
    {
        private readonly Queue<string> _responses = new(responses);
        internal List<string?> Cursors { get; } = [];

        public Task<JsonDocument> CallAsync(string method, IReadOnlyDictionary<string, string?>? parameters, CancellationToken cancellationToken)
        {
            Assert.Equal("conversations.history", method);
            Cursors.Add(parameters?.GetValueOrDefault("cursor"));
            return Task.FromResult(JsonDocument.Parse(_responses.Dequeue()));
        }

        public Task<Stream> DownloadAsync(Uri uri, long? rangeStart, long? rangeEnd, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private sealed class RoutingSlackBrowserSession(
        Func<string, IReadOnlyDictionary<string, string?>, string> responseFactory) : ISlackBrowserSession
    {
        internal List<SlackBrowserCall> Calls { get; } = [];

        public Task<JsonDocument> CallAsync(string method, IReadOnlyDictionary<string, string?>? parameters, CancellationToken cancellationToken)
        {
            var values = parameters == null
                ? new Dictionary<string, string?>()
                : new Dictionary<string, string?>(parameters);
            Calls.Add(new SlackBrowserCall(method, values));
            return Task.FromResult(JsonDocument.Parse(responseFactory(method, values)));
        }

        public Task<Stream> DownloadAsync(Uri uri, long? rangeStart, long? rangeEnd, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private sealed record SlackBrowserCall(string Method, IReadOnlyDictionary<string, string?> Parameters);
}
