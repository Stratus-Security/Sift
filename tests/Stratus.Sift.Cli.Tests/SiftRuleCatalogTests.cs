using Stratus.Sift.Core;

namespace Stratus.Sift.Cli.Tests;

public sealed class SiftRuleCatalogTests
{
    [Theory]
    [InlineData("4111 1111 1111 1111", true)]
    [InlineData("4111 1111 1111 1112", false)]
    [InlineData("1111 1111 1111 1111", false)]
    public void PaymentCardValidation_UsesLuhn(string value, bool expected)
        => Assert.Equal(expected, SiftRuleCatalog.IsValidPaymentCard(value));

    [Theory]
    [InlineData("GB82 WEST 1234 5698 7654 32", true)]
    [InlineData("GB82 WEST 1234 5698 7654 31", false)]
    public void IbanValidation_UsesMod97(string value, bool expected)
        => Assert.Equal(expected, SiftRuleCatalog.IsValidIban(value));

    [Fact]
    public void DefaultRules_HaveStableUniqueIds()
    {
        Assert.NotEmpty(SiftRuleCatalog.Default);
        Assert.Equal(
            SiftRuleCatalog.Default.Count,
            SiftRuleCatalog.Default.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count());
    }
}
