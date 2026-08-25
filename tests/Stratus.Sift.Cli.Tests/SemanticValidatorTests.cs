using System.Text.Json;
using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Validators;

namespace Stratus.Sift.Cli.Tests;

public class SemanticValidatorTests
{
    [Fact]
    public void BasicAuthValidator_AcceptsValidHeader()
    {
        var validator = new BasicAuthValidator();

        var result = validator.Validate(CreateContext("Authorization: Basic dXNlcjpwQHNzdzByZA=="));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void BasicAuthValidator_RejectsMalformedPayload()
    {
        var validator = new BasicAuthValidator();

        var result = validator.Validate(CreateContext("Authorization: Basic definitely-not-base64"));

        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("YWRtaW46YWRtaW4=")]
    [InlineData("OnNlY3JldA==")]
    [InlineData("dXNlcjo=")]
    public void BasicAuthValidator_RetainsShortOrEmptyPartCredentials(string payload)
    {
        var result = new BasicAuthValidator().Validate(CreateContext($"Authorization: Basic {payload}"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void JwtValidator_AcceptsValidJwt()
    {
        var validator = new JwtValidator();
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        var result = validator.Validate(CreateContext(jwt));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void JwtValidator_RejectsNonJsonPayload()
    {
        var validator = new JwtValidator();
        var malformed = "eyJhbGciOiJIUzI1NiJ9.bm90LWpzb24.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        var result = validator.Validate(CreateContext(malformed));

        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UifQ.")]
    [InlineData("eyJhbGciOiJub25lIn0.e30.")]
    public void JwtValidator_AcceptsUnsecuredJwtIncludingEmptyClaims(string jwt)
    {
        Assert.True(new JwtValidator().Validate(CreateContext(jwt)).IsValid);
    }

    [Fact]
    public void SqlConnectionStringValidator_AcceptsStructuredConnectionString()
    {
        var validator = new SqlConnectionStringValidator();

        var result = validator.Validate(CreateContext("Server=db.example;User ID=app;Password=S3cret!"));

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("Server=db;User ID=sa;Database=app;Password=x")]
    [InlineData("Password=x;Encrypt=True;Server=db;User ID=sa")]
    [InlineData("Server=db;Password=")]
    public void SqlConnectionStringValidator_RetainsWeakCredentialsInAnyFieldOrder(string connectionString)
    {
        Assert.True(new SqlConnectionStringValidator().Validate(CreateContext(connectionString)).IsValid);
    }

    [Fact]
    public void MongoConnectionStringValidator_AcceptsConnectionStringWithHost()
    {
        var validator = new MongoConnectionStringValidator();
        var candidate = "mongodb://app:secret@stratus.security";
        var fullText = "mongodb://app:secret@stratus.security/admin";

        var result = validator.Validate(CreateContext(candidate, fullText, 0));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void PostgresConnectionStringValidator_AcceptsPostgresUri()
    {
        var validator = new PostgresConnectionStringValidator();

        var result = validator.Validate(CreateContext("postgresql://app:secret@stratus.security"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void AzureSasValidator_RejectsSignatureWithoutSupportingParameters()
    {
        var validator = new AzureSasValidator();
        var candidate = "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2B%2F%3D%3D";
        var fullText = $"?sig={candidate}&sv=2023-11-03";

        var result = validator.Validate(CreateContext(candidate, fullText, fullText.IndexOf(candidate, StringComparison.Ordinal)));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void AzureSasValidator_AcceptsCoherentSasToken()
    {
        var validator = new AzureSasValidator();
        var candidate = "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2B%2F%3D%3D";
        var fullText = $"https://acct.blob.core.windows.net/c?sv=2023-11-03&sr=c&sp=r&se=2026-04-08T00%3A00%3A00Z&sig={candidate}";

        var result = validator.Validate(CreateContext(candidate, fullText, fullText.IndexOf(candidate, StringComparison.Ordinal)));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void TwilioValidator_RejectsPublicIdentifier()
    {
        var validator = new TwilioValidator();

        var result = validator.Validate(CreateContext("TWILIO_ACCOUNT_SID=AC00000000000000000000000000000000"));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void TwilioValidator_AcceptsAssignedAuthToken()
    {
        var validator = new TwilioValidator();

        var result = validator.Validate(CreateContext("TWILIO_AUTH_TOKEN=0123456789abcdef0123456789abcdef"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void TwilioValidator_RetainsPlaceholderSecretAtLowConfidence()
    {
        var result = new TwilioValidator().Validate(CreateContext("TWILIO_API_SECRET=exampleexampleexample"));

        AssertLowConfidence(result);
    }

    [Fact]
    public void SlackTokenValidator_AcceptsStructuredToken()
    {
        var validator = new SlackTokenValidator();

        var result = validator.Validate(CreateContext("xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void SlackTokenValidator_RetainsPlaceholderSegmentAtLowConfidence()
    {
        var validator = new SlackTokenValidator();

        var result = validator.Validate(CreateContext("xoxb-123456789012-123456789012-exampleexampleexample"));

        AssertLowConfidence(result);
    }

    [Fact]
    public void StripeSecretKeyValidator_AcceptsStructuredKey()
    {
        var validator = new StripeSecretKeyValidator();

        var result = validator.Validate(CreateContext("sk_live_1234567890abcdefghijklmnopqrstUV"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void StripeSecretKeyValidator_RetainsPlaceholderSuffixAtLowConfidence()
    {
        var validator = new StripeSecretKeyValidator();

        var result = validator.Validate(CreateContext("sk_test_exampleexampleexampleexample1234"));

        AssertLowConfidence(result);
    }

    [Fact]
    public void OpenAiApiKeyValidator_AcceptsStructuredKey()
    {
        var validator = new OpenAiApiKeyValidator();

        var result = validator.Validate(CreateContext("sk-proj-1234567890abcdef1234567890abcdef123456"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void OpenAiApiKeyValidator_RetainsPlaceholderKeyAtLowConfidence()
    {
        var validator = new OpenAiApiKeyValidator();

        var result = validator.Validate(CreateContext("sk-proj-exampleexampleexampleexampleexample12"));

        AssertLowConfidence(result);
    }

    [Fact]
    public void GitHubPatValidator_AcceptsClassicToken()
    {
        var validator = new GitHubPatValidator();

        var result = validator.Validate(CreateContext("ghp_1234567890abcdef1234567890abcdefQRST"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void GitHubPatValidator_RetainsPlaceholderFineGrainedTokenAtLowConfidence()
    {
        var validator = new GitHubPatValidator();
        var suffix = string.Concat(Enumerable.Repeat("example", 12));

        var result = validator.Validate(CreateContext($"github_pat_{suffix}"));

        AssertLowConfidence(result);
    }

    [Fact]
    public void GitLabPatValidator_AcceptsStructuredToken()
    {
        var validator = new GitLabPatValidator();

        var result = validator.Validate(CreateContext("glpat-1a2B3c4D5e6F7g8H9i0J"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void GitLabPatValidator_RetainsPlaceholderTokenAtLowConfidence()
    {
        var validator = new GitLabPatValidator();

        var result = validator.Validate(CreateContext("glpat-exampleexampleexample"));

        AssertLowConfidence(result);
    }

    [Fact]
    public void NpmAccessTokenValidator_AcceptsStructuredToken()
    {
        var validator = new NpmAccessTokenValidator();

        var result = validator.Validate(CreateContext("npm_1234567890abcdefghijklmnopqrstuvABCD"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void NpmAccessTokenValidator_RetainsRepeatedPlaceholderTokenAtLowConfidence()
    {
        var validator = new NpmAccessTokenValidator();

        var result = validator.Validate(CreateContext("npm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

        AssertLowConfidence(result);
    }

    [Fact]
    public void SendGridApiKeyValidator_AcceptsStructuredToken()
    {
        var validator = new SendGridApiKeyValidator();

        var result = validator.Validate(CreateContext("SG.ABCDEFGHIJKLMNOPQRSTUVWX.YZabcdef0123456789YZabcdef0123456789YZabcdef01"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void SendGridApiKeyValidator_RetainsPlaceholderSegmentsAtLowConfidence()
    {
        var validator = new SendGridApiKeyValidator();

        var result = validator.Validate(CreateContext("SG.exampleexampleexampleex.placeholderplaceholderplaceholderplaceholder12"));

        AssertLowConfidence(result);
    }

    [Fact]
    public void TelegramBotTokenValidator_AcceptsStructuredToken()
    {
        var validator = new TelegramBotTokenValidator();

        var result = validator.Validate(CreateContext("123456789:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void TelegramBotTokenValidator_RejectsZeroBotIdentifier()
    {
        var validator = new TelegramBotTokenValidator();

        var result = validator.Validate(CreateContext("000000000:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void MailchimpApiKeyValidator_AcceptsStructuredKey()
    {
        var validator = new MailchimpApiKeyValidator();

        var result = validator.Validate(CreateContext("0123456789abcdeffedcba9876543210-us19"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void MailchimpApiKeyValidator_AcceptsUs21DataCenter()
    {
        var result = new MailchimpApiKeyValidator().Validate(CreateContext("0123456789abcdeffedcba9876543210-us21"));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void MailchimpApiKeyValidator_RetainsRepeatedHalfAtLowConfidence()
    {
        var validator = new MailchimpApiKeyValidator();

        var result = validator.Validate(CreateContext("0123456789abcdef0123456789abcdef-us19"));

        AssertLowConfidence(result);
    }

    private static void AssertLowConfidence(ValidationResult result)
    {
        Assert.True(result.IsValid);
        Assert.InRange(result.Confidence, 0.0, 0.49);
        Assert.False(string.IsNullOrWhiteSpace(result.Reason));
    }

    private static ValidationContext CreateContext(string candidate, string? fullText = null, int? index = null)
    {
        var text = fullText ?? candidate;
        return new ValidationContext
        {
            Candidate = candidate,
            FilePath = "settings.json",
            FullFileContent = text,
            Index = index ?? Math.Max(text.IndexOf(candidate, StringComparison.Ordinal), 0)
        };
    }
}
