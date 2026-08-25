using Stratus.Sift.Scanner.Interfaces;
using Stratus.Sift.Scanner.Validators;

namespace Stratus.Sift.Cli.Tests;

public sealed class PowerShellCredentialUsageValidatorTests
{
    private readonly PowerShellCredentialUsageValidator _validator = new();

    [Theory]
    [InlineData("ConvertTo-SecureString 'Winterfell2026!' -AsPlainText -Force")]
    [InlineData("ConvertTo-SecureString -String 'Winterfell2026!' -AsPlainText -Force")]
    [InlineData("ConvertTo-SecureString -AsPlainText -Force -String 'Winterfell2026!'")]
    [InlineData("ConvertTo-SecureString -AsPlainText -Force 'Winterfell2026!'")]
    [InlineData("ConvertTo-SecureString ('Winterfell2026!') -AsPlainText -Force")]
    [InlineData("ConvertTo-SecureString $unknownPassword -AsPlainText -Force")]
    [InlineData("ConvertFrom-SecureString $securePassword -AsPlainText")]
    public void Validate_RetainsPlaintextConversionsForRecall(string content)
    {
        var result = _validator.Validate(CreateContext("-AsPlainText", content));

        Assert.True(result.IsValid, result.Reason);
    }

    [Fact]
    public void Validate_DetectsLiteralAssignedToVariable()
    {
        const string content = """
            $pw = 'Winterfell2026!'
            ConvertTo-SecureString $pw -AsPlainText -Force
            """;

        var result = _validator.Validate(CreateContext("-AsPlainText", content));

        Assert.True(result.IsValid, result.Reason);
        Assert.Equal(1.0, result.Confidence);
    }

    [Theory]
    [InlineData("$pw = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('V2ludGVyZmVsbDIwMjYh'))")]
    [InlineData("$pw = $prefix + 'Winterfell2026!'")]
    public void Validate_RetainsExpressionAssignmentsThatCouldEmbedASecret(string assignment)
    {
        var content = $"{assignment}{Environment.NewLine}ConvertTo-SecureString $pw -AsPlainText -Force";

        var result = _validator.Validate(CreateContext("-AsPlainText", content));

        Assert.True(result.IsValid, result.Reason);
    }

    [Theory]
    [InlineData("$password = [Regex]::Match($content, '(?<=Password: ).*')")]
    [InlineData("$password = Read-Host")]
    [InlineData("$password = Get-Content $passwordFile")]
    [InlineData("$password = $env:DEPLOY_PASSWORD")]
    [InlineData("$password = \"$(Get-Random)\"")]
    public void Validate_SuppressesVariablesProvenToComeFromRuntimeExpressions(string assignment)
    {
        var content = $"{assignment}{Environment.NewLine}ConvertTo-SecureString $password -AsPlainText -Force";

        var result = _validator.Validate(CreateContext("-AsPlainText", content));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_SuppressesNormalSecureStringSerialization()
    {
        const string content = "ConvertFrom-SecureString -SecureString $securePassword";

        var result = _validator.Validate(CreateContext("-SecureString", content));

        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("[Net.NetworkCredential]::new('', $securePassword)", "[Net.NetworkCredential]::new(")]
    [InlineData("[System.Net.NetworkCredential]::new('', $securePassword)", "[System.Net.NetworkCredential]::new(")]
    [InlineData("$credential.GetNetworkCredential().Password", ".GetNetworkCredential().Password")]
    [InlineData("[Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)", "[Runtime.InteropServices.Marshal]::SecureStringToBSTR(")]
    public void Validate_RetainsPlaintextMaterializationPatterns(string content, string candidate)
    {
        var result = _validator.Validate(CreateContext(candidate, content));

        Assert.True(result.IsValid, result.Reason);
    }

    private static ValidationContext CreateContext(string candidate, string content)
    {
        return new ValidationContext
        {
            Candidate = candidate,
            FilePath = "deploy.ps1",
            FullFileContent = content,
            Index = content.IndexOf(candidate, StringComparison.OrdinalIgnoreCase)
        };
    }
}
