using Microsoft.Extensions.Logging.Abstractions;
using Stratus.Sift.Cli;
using Stratus.Sift.Core.Enums;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Services;
using Stratus.Sift.Scanner.Validators;

namespace Stratus.Sift.Cli.Tests;

public class DefaultRulePortingTests : IDisposable
{
    private readonly string _tempDirectory;

    public DefaultRulePortingTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_tempDirectory);
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectPasswordManagerArtifact_ByExtension()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "vault.kdbx");
        await File.WriteAllTextAsync(filePath, "placeholder");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        var issue = Assert.Single(issues, i => i.ClassifierName == "Password Manager Artifact");
        Assert.Equal(Severity.Critical, issue.Severity);
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldSuppressOnlyWindowsDebugPasswdLogFilename()
    {
        var scanner = CreateScanner();
        var (classifiers, policies, ignoreRules) = await LoadDefaultConfigurationWithIgnoreRulesAsync();
        var windowsDebugDirectory = Path.Combine(_tempDirectory, "Windows", "debug");
        var unrelatedDirectory = Path.Combine(_tempDirectory, "operations");
        Directory.CreateDirectory(windowsDebugDirectory);
        Directory.CreateDirectory(unrelatedDirectory);
        var windowsDiagnosticPath = Path.Combine(windowsDebugDirectory, "PASSWD.LOG");
        var credentialOrientedPath = Path.Combine(unrelatedDirectory, "passwd.log");
        await File.WriteAllTextAsync(
            windowsDiagnosticPath,
            "Windows password-change diagnostic output\napiKey = \"Winterfell-Lab-Secret-2026\"");
        await File.WriteAllTextAsync(credentialOrientedPath, "operator-managed password export");

        var diagnosticIssues = scanner.ScanFile(windowsDiagnosticPath, classifiers, policies).ToList();
        var credentialIssues = scanner.ScanFile(credentialOrientedPath, classifiers, policies).ToList();
        var diagnosticIgnoreRules = IgnoreRuleEvaluator.GetMatchedRules(windowsDiagnosticPath, ignoreRules);

        Assert.DoesNotContain(
            diagnosticIssues,
            issue => issue.ClassifierName == "Credential-Oriented Filename");
        Assert.Contains(
            diagnosticIssues,
            issue => issue.ClassifierName == "Generic Secret Assignment");
        Assert.Contains(
            credentialIssues,
            issue => issue.ClassifierName == "Credential-Oriented Filename");
        Assert.DoesNotContain(
            diagnosticIgnoreRules,
            rule => rule.MatchTarget == RuleTarget.DirectoryPath
                && rule.Pattern.Contains("windows\\debug", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectCloudCredentialStorePath_ByPath()
    {
        var (classifiers, _) = await LoadDefaultConfigurationAsync();
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);
        var awsDirectory = Path.Combine(_tempDirectory, ".aws");
        Directory.CreateDirectory(awsDirectory);
        var filePath = Path.Combine(awsDirectory, "credentials");
        await File.WriteAllTextAsync(filePath, "[default]");

        var matches = optimizer.CheckMetadataClassifiers(filePath).ToList();

        Assert.Contains(matches, classifier => classifier.Name == "Cloud Credential Store Path");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectUnattendPassword_ViaNestedClassifier()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "unattend.xml");
        await File.WriteAllTextAsync(
            filePath,
            """
            <Unattend>
              <AdministratorPassword>
                <Value>Summer2026!</Value>
              </AdministratorPassword>
            </Unattend>
            """);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        var issue = Assert.Single(issues, i => i.ClassifierName == "Unattend Password");
        Assert.Equal(Severity.High, issue.Severity);
        Assert.DoesNotContain(issues, i => i.ClassifierName == "Unattend XML File");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectNetworkDeviceCredential_ViaNestedClassifier()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "running-config");
        await File.WriteAllTextAsync(
            filePath,
            """
            !
            snmp-server community public RW
            !
            """);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        var issue = Assert.Single(issues, i => i.ClassifierName == "Network Device Credential");
        Assert.Equal(Severity.High, issue.Severity);
        Assert.DoesNotContain(issues, i => i.ClassifierName == "Network Device Configuration File");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectAdditionalP2MetadataArtifacts()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();

        var expectations = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["recentservers.xml"] = "FTP Client Configuration File",
            ["backup_id_rsa"] = "SSH Keys",
            ["shadow"] = "Unix Local Hash Store",
            ["NTDS.DIT"] = "Windows Hash Store",
            ["identity.pfx"] = "Certificate Container Artifact"
        };

        foreach (var (fileName, classifierName) in expectations)
        {
            var filePath = Path.Combine(_tempDirectory, fileName);
            await File.WriteAllTextAsync(filePath, "placeholder");

            var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

            Assert.Single(issues, issue => issue.ClassifierName == classifierName);
            File.Delete(filePath);
        }
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldNotDetectWindowsHashStore_ForLowercaseSamFilename()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "sam");
        await File.WriteAllTextAsync(filePath, "placeholder");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.DoesNotContain(issues, issue => issue.ClassifierName == "Windows Hash Store");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldNotDetectUnixLocalHashStore_ForTitleCaseShadowFilename()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "Shadow");
        await File.WriteAllTextAsync(filePath, "placeholder");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.DoesNotContain(issues, issue => issue.ClassifierName == "Unix Local Hash Store");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldNotDetectAwsAccessKeyId_ForLowercasePrefix()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "aws.txt");
        await File.WriteAllTextAsync(filePath, "akia1234567890ABCDEF");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.DoesNotContain(issues, issue => issue.ClassifierName == "AWS Access Key ID");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldNotDetectJwt_ForWrongCasePrefix()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "jwt.txt");
        await File.WriteAllTextAsync(filePath, "eyjaGVhZGVy.eyJwYXlsb2Fk.ABCDEFGHIJKLMNOPQRSTUV");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.DoesNotContain(issues, issue => issue.ClassifierName == "JSON Web Token (JWT)");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldNotDetectGenericPrivateKey_ForLowercaseBeginMarker()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "key.txt");
        await File.WriteAllTextAsync(
            filePath,
            """
            -----begin private key-----
            abcdefghijklmnopqrstuvwxyz
            -----end private key-----
            """);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.DoesNotContain(issues, issue => issue.ClassifierName == "Generic Private Key (Embedded)");
        Assert.DoesNotContain(issues, issue => issue.ClassifierName == "SSH Keys");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectAdditionalP3Artifacts()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();

        var expectations = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [".env"] = "Shell RC / Environment File",
            ["LocalSettings.php"] = "PHP Sensitive Configuration File",
            ["terraform.tfvars"] = "Infrastructure as Code Variable File",
            ["Visual Studio Code Host_history.txt"] = "Shell History"
        };

        foreach (var (fileName, classifierName) in expectations)
        {
            var filePath = Path.Combine(_tempDirectory, fileName);
            await File.WriteAllTextAsync(filePath, "placeholder");

            var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

            Assert.Single(issues, issue => issue.ClassifierName == classifierName);
            File.Delete(filePath);
        }
    }

    [Theory]
    [InlineData("terraform.tfstate", "Terraform State or Plan Artifact", "High")]
    [InlineData("terraform.tfstate.backup", "Terraform State or Plan Artifact", "High")]
    [InlineData("saved.tfplan", "Terraform State or Plan Artifact", "High")]
    [InlineData("mcp.json", "MCP Configuration Artifact", "Medium")]
    [InlineData("AGENTS.md", "AI Instruction Artifact", "Low")]
    [InlineData("project.prompt.md", "AI Instruction Artifact", "Low")]
    [InlineData("state.vscdb", "AI Assistant State Artifact", "Medium")]
    [InlineData("capture.har", "HTTP Capture Artifact", "High")]
    public async Task DefaultConfiguration_ShouldDetectCloudAndAiArtifacts(
        string fileName,
        string classifierName,
        string severityName)
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, fileName);
        await File.WriteAllTextAsync(filePath, "placeholder");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        var issue = Assert.Single(issues, candidate => candidate.ClassifierName == classifierName);
        Assert.Equal(Enum.Parse<Severity>(severityName), issue.Severity);
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectAiConversationStateByPath()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var stateDirectory = Path.Combine(_tempDirectory, ".claude", "projects", "workspace");
        Directory.CreateDirectory(stateDirectory);
        var filePath = Path.Combine(stateDirectory, "session.jsonl");
        await File.WriteAllTextAsync(filePath, "{}");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(issues, issue => issue.ClassifierName == "AI Assistant State Artifact");
    }

    [Theory]
    [InlineData(".aws/cli/cache/session.json")]
    [InlineData(".azure/msal_token_cache.json")]
    [InlineData("gcloud/credentials.db")]
    [InlineData(".oci/sessions/DEFAULT/security_token")]
    public async Task DefaultConfiguration_ShouldDetectExpandedCloudCredentialStores(string relativePath)
    {
        var (classifiers, _) = await LoadDefaultConfigurationAsync();
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);
        var filePath = Path.Combine(
            _tempDirectory,
            relativePath.Replace('/', Path.DirectorySeparatorChar));

        var matches = optimizer.CheckMetadataClassifiers(filePath).ToList();

        Assert.Contains(matches, classifier => classifier.Name == "Cloud Credential Store Path");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectOpaqueEnvironmentStyleSecretInYaml()
    {
        var scanner = CreateScannerWithAdditionalValidators();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "settings.yml");
        await File.WriteAllTextAsync(filePath, "RefClientSecret: xWHbCd2vpcO0rltk_WhgA7roZ0c3BRxdS");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(issues, issue => issue.ClassifierName == "Environment Secret Assignment");
    }

    [Theory]
    [InlineData("API_KEY: REDACTED-REDACTED")]
    [InlineData("ACCESS_TOKEN: @" + "Microsoft.KeyVault(SecretUri=https://vault.example/secrets/app)")]
    [InlineData("PASSWORD: aaaaaaaaaaaaaaaa")]
    public async Task DefaultConfiguration_ShouldIgnoreEnvironmentSecretPlaceholders(string content)
    {
        var scanner = CreateScannerWithAdditionalValidators();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "settings.yml");
        await File.WriteAllTextAsync(filePath, content);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.DoesNotContain(issues, issue => issue.ClassifierName == "Environment Secret Assignment");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectFirefoxEncryptedCredential_ViaNestedClassifier()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "logins.json");
        await File.WriteAllTextAsync(
            filePath,
            """
            {
              "logins": [
                {
                  "encryptedPassword":"dGVzdC1wYXNzd29yZA=="
                }
              ]
            }
            """);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        var issue = Assert.Single(issues, i => i.ClassifierName == "Firefox Encrypted Credential");
        Assert.Equal(Severity.High, issue.Severity);
        Assert.DoesNotContain(issues, i => i.ClassifierName == "Firefox Login Store");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectSccmContentLibraryShare_ByShareName()
    {
        var (classifiers, _) = await LoadDefaultConfigurationAsync();
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);

        var matches = optimizer.CheckMetadataClassifiers(@"\\server\SCCMContentLib$\packages\image.wim").ToList();

        Assert.Contains(matches, classifier => classifier.Name == "SCCM Content Library Share");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldNotDetectS3UriInCode()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "appsettings.json");
        await File.WriteAllTextAsync(
            filePath,
            """
            {
              "ArchiveLocation": "s3://prod-backups"
            }
            """);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.DoesNotContain(issues, i => i.ClassifierName == "S3 URI in Code");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectSqlAccountCreationStatement_InTomlFile()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "database.toml");
        await File.WriteAllTextAsync(
            filePath,
            """
            sql = "CREATE LOGIN reporting WITH PASSWORD = 'supersecret'"
            """);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        var issue = Assert.Single(issues, i => i.ClassifierName == "SQL Account Creation Statement");
        Assert.Equal(Severity.High, issue.Severity);
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectRdpSavedCredential_InRdpFile()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "server.rdp");
        await File.WriteAllTextAsync(filePath, "password 51:b:0123456789ABCDEF");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(issues, i => i.ClassifierName == "RDP Saved Credential");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectOpenVpnConfiguration_InOvpnFile()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "client.ovpn");
        await File.WriteAllTextAsync(
            filePath,
            """
            <key>
            -----BEGIN PRIVATE KEY-----
            abcdef
            -----END PRIVATE KEY-----
            </key>
            """);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(issues, i => i.ClassifierName == "OpenVPN Configuration");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectMemoryDumpArtifact_ByExtension()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "process.dmp");
        await File.WriteAllTextAsync(filePath, "placeholder");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        var issue = Assert.Single(issues, i => i.ClassifierName == "Memory Dump Artifact");
        Assert.Equal(Severity.Critical, issue.Severity);
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectNetworkConfiguration_PcapNg()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "capture.pcapng");
        await File.WriteAllTextAsync(filePath, "placeholder");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(issues, i => i.ClassifierName == "Network Configuration");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectPowerShellCredentialUsage()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "script.ps1");
        await File.WriteAllTextAsync(filePath, "$cred = ConvertTo-SecureString 'hunter2' -AsPlainText -Force");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(issues, i => i.ClassifierName == "PowerShell Credential Usage");
    }

    [Theory]
    [InlineData("ConvertTo-SecureString -AsPlainText -Force -String 'Winterfell2026!'")]
    [InlineData("ConvertTo-SecureString ('Winterfell2026!') -AsPlainText -Force")]
    [InlineData("ConvertTo-SecureString $unknownPassword -AsPlainText -Force")]
    [InlineData("ConvertFrom-SecureString $securePassword -AsPlainText")]
    [InlineData("[System.Net.NetworkCredential]::new('', $securePassword).Password")]
    [InlineData("$credential.GetNetworkCredential().Password")]
    [InlineData("[Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)")]
    [InlineData("New-Object -TypeName System.Net.NetworkCredential")]
    public async Task DefaultConfiguration_ShouldRetainBroadPowerShellCredentialCoverage(string content)
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "script.ps1");
        await File.WriteAllTextAsync(filePath, content);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Contains(issues, issue => issue.ClassifierName == "PowerShell Credential Usage");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectCommandCredentialUsage()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "deploy.cmd");
        await File.WriteAllTextAsync(filePath, "cmdkey /user:contoso\\svc-deploy /pass:SuperSecret!");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(issues, i => i.ClassifierName == "Command Credential Usage");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectAzureStorageAccountKey()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, ".env");
        var key = Convert.ToBase64String(Enumerable.Range(0, 64).Select(i => (byte)i).ToArray());
        await File.WriteAllTextAsync(filePath, $"AZURE_STORAGE_KEY={key}");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        var issue = Assert.Single(issues, i => i.ClassifierName == "Azure Storage Account Key");
        Assert.Equal(Severity.Critical, issue.Severity);
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectNewSaasTokens()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();

        var expectations = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX1234567890abcd"] = "Anthropic API Key",
            ["dapi1234567890ABCDEF1234567890ABCDEF"] = "Databricks Personal Access Token",
            ["hf_abcdefghijklmnopqrstuvwxyz1234567890"] = "Hugging Face Access Token"
        };

        foreach (var (token, classifierName) in expectations)
        {
            var filePath = Path.Combine(_tempDirectory, "tokens.env");
            await File.WriteAllTextAsync(filePath, $"TOKEN={token}");

            var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

            var issue = Assert.Single(issues, i => i.ClassifierName == classifierName);
            Assert.Equal(Severity.Critical, issue.Severity);
        }
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldSplitGitConfigurationArtifacts()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();

        var expectations = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [".gitconfig"] = "Git Configuration",
            [".git-credentials"] = "Git Credential File"
        };

        foreach (var (fileName, classifierName) in expectations)
        {
            var filePath = Path.Combine(_tempDirectory, fileName);
            await File.WriteAllTextAsync(filePath, "placeholder");

            var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

            Assert.Single(issues, issue => issue.ClassifierName == classifierName);
            File.Delete(filePath);
        }
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectGitRepositoryDirectory_ByDirectoryName()
    {
        var (classifiers, _) = await LoadDefaultConfigurationAsync();
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);

        var gitDirectory = Path.Combine(_tempDirectory, "repo", ".git");
        Directory.CreateDirectory(gitDirectory);
        var filePath = Path.Combine(gitDirectory, "config");
        await File.WriteAllTextAsync(filePath, "[core]");

        var matches = optimizer.CheckMetadataClassifiers(filePath).ToList();

        Assert.Contains(matches, classifier => classifier.Name == "Git Repository Directory");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldNotDetectGitRepositoryDirectory_ForUppercaseDirectoryName()
    {
        var (classifiers, _) = await LoadDefaultConfigurationAsync();
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);

        var gitDirectory = Path.Combine(_tempDirectory, "repo", ".GIT");
        Directory.CreateDirectory(gitDirectory);
        var filePath = Path.Combine(gitDirectory, "config");
        await File.WriteAllTextAsync(filePath, "[core]");

        var matches = optimizer.CheckMetadataClassifiers(filePath).ToList();

        Assert.DoesNotContain(matches, classifier => classifier.Name == "Git Repository Directory");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldScanCDriveAdministrativeShare()
    {
        var (_, _, ignoreRules) = await LoadDefaultConfigurationWithIgnoreRulesAsync();

        var matchedRules = IgnoreRuleEvaluator.GetMatchedRules(@"\\server\C$\Windows\system32\config.txt", ignoreRules);

        Assert.DoesNotContain(matchedRules, rule => rule.MatchTarget == RuleTarget.ShareName && rule.Pattern == "C$");
        Assert.Contains(ignoreRules, rule =>
            rule.MatchTarget == RuleTarget.ShareName
            && rule.Pattern == "C$"
            && !rule.IsEnabled);
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectGenericSecretAssignment()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "secrets.js");
        await File.WriteAllTextAsync(filePath, "const apiKey = \"super-secret-token\";");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Single(issues, i => i.ClassifierName == "Generic Secret Assignment");
    }

    [Theory]
    [InlineData("module.psm1", "$NuGetApiKey = \"$(Get-Random)\"")]
    [InlineData("validation.psm1", "$result = Invoke-Pester -Path $path -PassThru")]
    [InlineData("CHANGELOG.md", "Added -Passthu to Setup to obtain file system object references")]
    public async Task DefaultConfiguration_ShouldNotTreatPowerShellExpressionsOrPassThruAsGenericSecrets(
        string fileName,
        string content)
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, fileName);
        await File.WriteAllTextAsync(filePath, content);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.DoesNotContain(issues, issue => issue.ClassifierName == "Generic Secret Assignment");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldNotTreatRuntimePowerShellConversionAsEmbeddedCredential()
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, "module.psm1");
        await File.WriteAllTextAsync(
            filePath,
            """
            $password = [System.Text.RegularExpressions.Regex]::Match($content, '(?<=Password: ).*')
            $secstr = ConvertTo-SecureString $password -AsPlainText -Force
            """);

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.DoesNotContain(issues, issue => issue.ClassifierName == "PowerShell Credential Usage");
    }

    [Theory]
    [InlineData("main.go")]
    [InlineData("main.tf")]
    [InlineData("variables.hcl")]
    [InlineData("README.md")]
    [InlineData("build.gradle")]
    [InlineData("Dockerfile")]
    public async Task DefaultConfiguration_ShouldRunExistingSecretRulesAcrossSourceAndConfigProfile(string fileName)
    {
        var scanner = CreateScanner();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var filePath = Path.Combine(_tempDirectory, fileName);
        await File.WriteAllTextAsync(filePath, "const apiKey = \"Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0\";");

        var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

        Assert.Contains(issues, issue => issue.ClassifierName == "Generic Secret Assignment");
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectNewProviderAndInfrastructureSecrets()
    {
        var scanner = CreateScannerWithAdditionalValidators();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var azurePat = BuildToken(75) + "AZDO" + BuildToken(5);
        var cases = new Dictionary<string, (string Content, string Classifier)>(StringComparer.Ordinal)
        {
            ["azure.go"] = ($"AZURE_DEVOPS_PAT={azurePat}", "Azure DevOps Personal Access Token"),
            ["aws.tf"] = ($"AWS_SESSION_TOKEN={BuildBase64Token(120)}", "AWS Session Token"),
            ["gitlab.md"] = ("glrt-" + BuildToken(24), "GitLab Operational Token"),
            ["pypi.pypirc"] = ("password=pypi-" + BuildToken(90), "PyPI API Token"),
            ["docker.env"] = ("TOKEN=dckr_pat_" + BuildToken(24), "Docker Access Token"),
            ["vault.hcl"] = ("VAULT_TOKEN=hvs." + BuildToken(30), "Vault Token"),
            ["terraform.rc"] = ("token=tftk." + BuildToken(30), "HCP Terraform Token"),
            ["redis.go"] = ("redis://app:S3cret-value@stratus.security:6379/0", "Credentialed Service URI"),
            ["bearer.md"] = ("Authorization: Bearer Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0", "HTTP Bearer Token")
        };

        foreach (var (fileName, expectation) in cases)
        {
            var filePath = Path.Combine(_tempDirectory, fileName);
            await File.WriteAllTextAsync(filePath, expectation.Content);

            var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

            Assert.True(
                issues.Any(issue => issue.ClassifierName == expectation.Classifier),
                $"Expected {expectation.Classifier} for {fileName}; found: {string.Join(", ", issues.Select(issue => issue.ClassifierName))}");
        }
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldDetectStructuredPackageAndContainerSecrets()
    {
        var scanner = CreateScannerWithAdditionalValidators();
        var (classifiers, policies) = await LoadDefaultConfigurationAsync();
        var dockerAuth = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("builder:S3cret-value"));
        var cases = new Dictionary<string, (string Content, string Classifier)>(StringComparer.Ordinal)
        {
            ["config.json"] = ($"{{\"auths\":{{\"registry.example\":{{\"auth\":\"{dockerAuth}\"}}}}}}", "Docker Registry Credential"),
            ["NuGet.Config"] = ("<packageSourceCredentials><private><add key=\"ClearTextPassword\" value=\"S3cret-value\" /></private></packageSourceCredentials>", "NuGet Cleartext Credential"),
            ["credentials"] = (":rubygems_api_key: Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8", "RubyGems API Credential"),
            ["secret.yaml"] = ("apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\nstringData:\n  password: S3cret-value\n", "Kubernetes Secret Manifest")
        };

        foreach (var (fileName, expectation) in cases)
        {
            var filePath = Path.Combine(_tempDirectory, fileName);
            await File.WriteAllTextAsync(filePath, expectation.Content);

            var issues = scanner.ScanFile(filePath, classifiers, policies).ToList();

            Assert.True(
                issues.Any(issue => issue.ClassifierName == expectation.Classifier),
                $"Expected {expectation.Classifier} for {fileName}; found: {string.Join(", ", issues.Select(issue => issue.ClassifierName))}");
        }
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldRecognizeExpandedCredentialStorePaths()
    {
        var (classifiers, _) = await LoadDefaultConfigurationAsync();
        var optimizer = new ClassifierOptimizer();
        optimizer.LoadClassifiers(classifiers);
        var paths = new[]
        {
            @"C:\Profiles\alice\AppData\Roaming\gcloud\application_default_credentials.json",
            @"C:\Profiles\alice\.terraform.d\credentials.tfrc.json",
            @"C:\Profiles\alice\.docker\config.json",
            @"C:\Profiles\alice\AppData\Roaming\GitHub CLI\hosts.yml"
        };

        foreach (var path in paths)
        {
            Assert.Contains(optimizer.CheckMetadataClassifiers(path), classifier => classifier.Name == "Cloud Credential Store Path");
        }
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldKeepHighFalsePositivePiiPoliciesOptIn()
    {
        var (_, policies) = await LoadDefaultConfigurationAsync();
        var names = new[]
        {
            "International Bank Account Number",
            "Australian Tax File Number",
            "Australian Medicare Number",
            "Passport Number (Contextual)",
            "Medical Record Number (Contextual)"
        };

        foreach (var name in names)
        {
            var policy = Assert.Single(policies, candidate => candidate.Name == name);
            Assert.False(policy.Active);
        }
    }

    [Fact]
    public async Task DefaultConfiguration_ShouldUseProfilesInsteadOfCopiedExtensionCatalogs()
    {
        var (classifiers, _) = await LoadDefaultConfigurationAsync();
        var allClassifiers = Flatten(classifiers).ToList();

        Assert.DoesNotContain(
            allClassifiers.SelectMany(classifier => classifier.Matches),
            match => match.IncludedExtensions.Count > 20);
        Assert.All(
            new[] { "AWS Access Key ID", "GitHub Personal Access Token", "Generic Secret Assignment", "OpenAI API Key" },
            name => Assert.Contains(
                allClassifiers.Single(classifier => classifier.Name == name).Matches,
                match => match.ExtensionProfile == Stratus.Sift.Core.Validation.ContentExtensionProfiles.SourceAndConfig));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory))
        {
            Directory.Delete(_tempDirectory, recursive: true);
        }
    }

    [Fact]
    public void CliPolicyMap_ExcludesInactivePolicies()
    {
        var classifier = new Classifier { Name = "Example" };
        var active = CreateLinkedPolicy("Active", classifier, active: true);
        var inactive = CreateLinkedPolicy("Inactive", classifier, active: false);

        var map = CliScannerBootstrap.BuildPolicyMap([active, inactive]);

        var policy = Assert.Single(map[classifier.Id]);
        Assert.Same(active, policy);
    }

    private static FileScanner CreateScanner()
    {
        return new FileScanner(
            NullLogger<FileScanner>.Instance,
            new ContentExtractor(),
            new ValidatorFactory([new PowerShellCredentialUsageValidator()]));
    }

    private static FileScanner CreateScannerWithAdditionalValidators()
    {
        IValidator[] validators =
        [
            new AzureDevOpsPatValidator(),
            new AwsSessionTokenValidator(),
            new GitLabOperationalTokenValidator(),
            new PyPiApiTokenValidator(),
            new DockerAccessTokenValidator(),
            new DockerConfigAuthValidator(),
            new VaultTokenValidator(),
            new TerraformTokenValidator(),
            new CredentialedServiceUriValidator(),
            new BearerTokenValidator(),
            new EnvironmentSecretAssignmentValidator(),
            new PowerShellCredentialUsageValidator()
        ];

        return new FileScanner(
            NullLogger<FileScanner>.Instance,
            new ContentExtractor(),
            new ValidatorFactory(validators));
    }

    private static IEnumerable<Classifier> Flatten(IEnumerable<Classifier> classifiers)
    {
        foreach (var classifier in classifiers)
        {
            yield return classifier;
            foreach (var child in Flatten(classifier.SubClassifiers ?? []))
            {
                yield return child;
            }
        }
    }

    private static Policy CreateLinkedPolicy(string name, Classifier classifier, bool active)
    {
        var policy = new Policy
        {
            Name = name,
            Active = active
        };
        policy.PolicyClassifiers.Add(new PolicyClassifier
        {
            Policy = policy,
            PolicyId = policy.Id,
            Classifier = classifier,
            ClassifierId = classifier.Id
        });
        return policy;
    }

    private static string BuildToken(int length)
    {
        const string alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        return new string(Enumerable.Range(0, length).Select(index => alphabet[(index * 17 + 11) % alphabet.Length]).ToArray());
    }

    private static string BuildBase64Token(int length)
    {
        const string alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
        return new string(Enumerable.Range(0, length).Select(index => alphabet[(index * 19 + 7) % alphabet.Length]).ToArray());
    }

    private static async Task<(List<Classifier> Classifiers, List<Policy> Policies)> LoadDefaultConfigurationAsync()
    {
        var (classifiers, policies, _) = await LoadDefaultConfigurationWithIgnoreRulesAsync();
        return (classifiers, policies);
    }

    private static async Task<(List<Classifier> Classifiers, List<Policy> Policies, List<IgnoreRule> IgnoreRules)> LoadDefaultConfigurationWithIgnoreRulesAsync()
    {
        var config = await CliRuleCatalogLoader.LoadAsync(null, NullLogger.Instance);
        return (config.Classifiers, config.Policies, config.IgnoreRules);
    }
}
