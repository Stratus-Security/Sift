using System.Text;
using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Validators;

namespace Stratus.Sift.Cli.Tests;

public sealed class AdditionalRuleValidatorTests
{
    [Fact]
    public void AzureDevOpsPatValidator_AcceptsCurrentSignatureAndRejectsWrongPosition()
    {
        var validator = new AzureDevOpsPatValidator();
        var token = BuildToken(75) + "AZDO" + BuildToken(5);

        Assert.True(validator.Validate(CreateContext(token)).IsValid);
        Assert.False(validator.Validate(CreateContext(BuildToken(84))).IsValid);
    }

    [Fact]
    public void AzureDevOpsPatValidator_RequiresContextForLegacyTokens()
    {
        var validator = new AzureDevOpsPatValidator();
        var token = BuildToken(52);

        Assert.False(validator.Validate(CreateContext(token)).IsValid);
        Assert.True(validator.Validate(CreateContext(token, $"AZURE_DEVOPS_PAT={token}")).IsValid);
    }

    [Fact]
    public void AwsSessionTokenValidator_AcceptsStructuredAssignmentAndRejectsShortValue()
    {
        var validator = new AwsSessionTokenValidator();

        Assert.True(validator.Validate(CreateContext($"AWS_SESSION_TOKEN={BuildBase64Token(120)}")).IsValid);
        Assert.False(validator.Validate(CreateContext("AWS_SESSION_TOKEN=too-short")).IsValid);
    }

    [Theory]
    [InlineData("glrt-")]
    [InlineData("glptt-")]
    [InlineData("glagent-")]
    public void GitLabOperationalTokenValidator_AcceptsDocumentedPrefixes(string prefix)
    {
        var token = prefix + BuildToken(24);
        Assert.True(new GitLabOperationalTokenValidator().Validate(CreateContext(token)).IsValid);
    }

    [Fact]
    public void PyPiApiTokenValidator_EnforcesPrefixAndMinimumPayload()
    {
        var validator = new PyPiApiTokenValidator();

        Assert.True(validator.Validate(CreateContext("pypi-" + BuildToken(90))).IsValid);
        Assert.False(validator.Validate(CreateContext("pypi-" + BuildToken(40))).IsValid);
    }

    [Theory]
    [InlineData("dckr_pat_")]
    [InlineData("dckr_oat_")]
    public void DockerAccessTokenValidator_AcceptsPersonalAndOrganizationTokens(string prefix)
    {
        var token = prefix + BuildToken(24);
        Assert.True(new DockerAccessTokenValidator().Validate(CreateContext(token)).IsValid);
    }

    [Fact]
    public void DockerConfigAuthValidator_DecodesUsernameAndSecret()
    {
        var validator = new DockerConfigAuthValidator();
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("builder:S3cret-value"));

        Assert.True(validator.Validate(CreateContext($"\"auth\": \"{encoded}\"")).IsValid);
        Assert.False(validator.Validate(CreateContext("\"auth\": \"bm90LWEtdHVwbGU=\"")).IsValid);
    }

    [Fact]
    public void VaultTokenValidator_AcceptsCurrentTokenAndContextQualifiesLegacyToken()
    {
        var validator = new VaultTokenValidator();
        var current = "hvs." + BuildToken(30);
        var legacy = "s." + BuildToken(30);

        Assert.True(validator.Validate(CreateContext(current)).IsValid);
        Assert.False(validator.Validate(CreateContext(legacy)).IsValid);
        Assert.True(validator.Validate(CreateContext(legacy, $"VAULT_TOKEN={legacy}")).IsValid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TerraformTokenValidator_AcceptsCurrentAndLegacyTokens(bool legacy)
    {
        var token = legacy
            ? BuildToken(10) + ".atlasv1." + BuildToken(32)
            : "tftk." + BuildToken(32);
        Assert.True(new TerraformTokenValidator().Validate(CreateContext(token)).IsValid);
    }

    [Theory]
    [InlineData("mysql://app:S3cret-value@stratus.security/main")]
    [InlineData("rediss://default:S3cret-value@stratus.security:6380/0")]
    [InlineData("amqps://worker:S3cret-value@stratus.security/vhost")]
    [InlineData("neo4j+s://graph:S3cret-value@stratus.security")]
    public void CredentialedServiceUriValidator_AcceptsSupportedUris(string uri)
    {
        Assert.True(new CredentialedServiceUriValidator().Validate(CreateContext(uri)).IsValid);
    }

    [Fact]
    public void CredentialedServiceUriValidator_RetainsWeakPasswordAtLowConfidence()
    {
        var result = new CredentialedServiceUriValidator().Validate(CreateContext("redis://admin:x@stratus.security"));

        Assert.True(result.IsValid);
        Assert.InRange(result.Confidence, 0.0, 0.49);
    }

    [Fact]
    public void BearerTokenValidator_DefersJwtAndProviderSpecificTokens()
    {
        var validator = new BearerTokenValidator();

        Assert.True(validator.Validate(CreateContext("Authorization: Bearer Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0")).IsValid);
        var shortToken = validator.Validate(CreateContext("Authorization: Bearer abc123"));
        Assert.True(shortToken.IsValid);
        Assert.InRange(shortToken.Confidence, 0.0, 0.49);
        Assert.False(validator.Validate(CreateContext("Authorization: Bearer ghp_" + BuildToken(36))).IsValid);
        Assert.False(validator.Validate(CreateContext("Authorization: Bearer aaa.bbb.ccc")).IsValid);
    }

    [Theory]
    [InlineData("CLIENT_SECRET=xWHbCd2vpcO0rltk_WhgA7roZ0c3BRxdS", true)]
    [InlineData("\"RefClientSecret\": \"xWHbCd2vpcO0rltk_WhgA7roZ0c3BRxdS", true)]
    [InlineData("API_KEY=REDACTED-REDACTED", true)]
    [InlineData("ACCESS_TOKEN=@" + "Microsoft.KeyVault(SecretUri=https://vault.example/secrets/app)", false)]
    [InlineData("PASSWORD=aaaaaaaaaaaaaaaa", true)]
    [InlineData("PASSWORD=letmein1", true)]
    [InlineData("PASSWORD=$2b$12$abcdefghijklmnopqrstuv", true)]
    [InlineData("PASSWORD=%21encoded", true)]
    [InlineData("Credentials = credentials;", true)]
    [InlineData("publicKeyToken=cc7b13ffcd2ddd51", false)]
    [InlineData("PUBLIC_KEY_TOKEN=31bf3856ad364e35", false)]
    public void EnvironmentSecretAssignmentValidator_FiltersReferencesAndPlaceholders(string candidate, bool expected)
    {
        Assert.Equal(expected, new EnvironmentSecretAssignmentValidator().Validate(CreateContext(candidate)).IsValid);
    }

    [Fact]
    public void EnvironmentSecretAssignmentValidator_LowersConfidenceForWeakValues()
    {
        var result = new EnvironmentSecretAssignmentValidator().Validate(CreateContext("PASSWORD=aaaaaaaaaaaaaaaa"));

        Assert.True(result.IsValid);
        Assert.InRange(result.Confidence, 0.0, 0.49);
    }

    [Theory]
    [InlineData("GB82 WEST 1234 5698 7654 32", true)]
    [InlineData("GB82 WEST 1234 5698 7654 33", false)]
    public void IbanValidator_UsesMod97Checksum(string candidate, bool expected)
    {
        Assert.Equal(expected, new IbanValidator().Validate(CreateContext(candidate)).IsValid);
    }

    [Theory]
    [InlineData("123 456 782", true)]
    [InlineData("123 456 789", false)]
    public void AustralianTfnValidator_UsesChecksum(string candidate, bool expected)
    {
        Assert.Equal(expected, new AustralianTfnValidator().Validate(CreateContext(candidate)).IsValid);
    }

    [Theory]
    [InlineData("2123 45670 1", true)]
    [InlineData("2123 45671 1", false)]
    public void AustralianMedicareValidator_UsesChecksum(string candidate, bool expected)
    {
        Assert.Equal(expected, new AustralianMedicareValidator().Validate(CreateContext(candidate)).IsValid);
    }

    private static ValidationContext CreateContext(string candidate, string? fullText = null)
    {
        var text = fullText ?? candidate;
        return new ValidationContext
        {
            Candidate = candidate,
            FilePath = "settings.json",
            FullFileContent = text,
            Index = Math.Max(text.IndexOf(candidate, StringComparison.Ordinal), 0)
        };
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
}
