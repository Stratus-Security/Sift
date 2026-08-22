using Microsoft.Extensions.Logging;
using Stratus.Sift.Core.Models;
using Stratus.Sift.Core.Validation;

namespace Stratus.Sift.Scanner.Services;

public static class ClassifierRuntimeValidator
{
    public static IReadOnlyList<Classifier> FilterValidClassifiers(IEnumerable<Classifier> classifiers, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(classifiers);
        ArgumentNullException.ThrowIfNull(logger);

        var valid = new List<Classifier>();

        foreach (var classifier in classifiers)
        {
            var errors = ClassifierConventions.ValidateClassifier(classifier);
            if (errors.Count == 0)
            {
                valid.Add(classifier);
                continue;
            }

            logger.LogWarning(
                "Skipping classifier {ClassifierName} because its configuration is invalid: {Errors}",
                string.IsNullOrWhiteSpace(classifier.Name) ? "<unnamed>" : classifier.Name,
                string.Join("; ", errors.SelectMany(pair => pair.Value)));
        }

        return valid;
    }
}
