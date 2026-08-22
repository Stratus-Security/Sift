using Stratus.Sift.Scanner.Validators;
using Xunit;

namespace Stratus.Sift.Cli.Tests;

public class LuhnValidatorTests
{
    [Fact]
    public void Validate_ReturnsExpectedResult()
    {
        var expectations = new[]
        {
            new { Candidate = "4539148803436467", Expected = true },
            new { Candidate = "4539148803436460", Expected = false },
            new { Candidate = "1234567812345670", Expected = true },
            new { Candidate = "1234567812345678", Expected = false },
            new { Candidate = "0000000000000", Expected = true },
            new { Candidate = "123", Expected = false },
            new { Candidate = "123456789012345678901", Expected = false },
            new { Candidate = "abc", Expected = false }
        };

        var validator = new LuhnValidator();
        foreach (var expectation in expectations)
        {
            var context = new Stratus.Sift.Scanner.Interfaces.ValidationContext
            {
                Candidate = expectation.Candidate,
                FilePath = "TestFile.cs",
                FullFileContent = expectation.Candidate,
                Index = 0
            };

            var result = validator.Validate(context);
            Assert.Equal(expectation.Expected, result.IsValid);
        }
    }
}
