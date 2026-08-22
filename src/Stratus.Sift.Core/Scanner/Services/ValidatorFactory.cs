using Stratus.Sift.Scanner.Interfaces;

namespace Stratus.Sift.Scanner.Services;

public class ValidatorFactory
{
    private readonly Dictionary<string, IValidator> _validators;

    public ValidatorFactory(IEnumerable<IValidator> validators)
    {
        _validators = validators.ToDictionary(v => v.Name, v => v, StringComparer.OrdinalIgnoreCase);
    }

    public IValidator? GetValidator(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        return _validators.TryGetValue(name, out var validator) ? validator : null;
    }
}
