namespace Stratus.Sift.Scanner.Interfaces;

public class ValidationContext
{
    public required string Candidate { get; set; }      // The potential secret (e.g. "4532...")
    public required string FilePath { get; set; }       // The file name (e.g. "PaymentTests.cs")
    public required string FullFileContent { get; set; } // The full text (for looking at surrounding words)
    public int Index { get; set; }             // Where the match was found
}

public class ValidationResult
{
    public bool IsValid { get; set; }
    public double Confidence { get; set; } = 1.0; // 0.0 to 1.0
    public string? Reason { get; set; } // "Failed Luhn check" or "Located in Test file"
}

public interface IValidator
{
    string Name { get; }
    ValidationResult Validate(ValidationContext context);
}
