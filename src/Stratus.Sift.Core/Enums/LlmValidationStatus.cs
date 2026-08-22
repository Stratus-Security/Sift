using System.Text.Json.Serialization;

namespace Stratus.Sift.Core.Enums;

[JsonConverter(typeof(JsonStringEnumConverter<LlmValidationStatus>))]
public enum LlmValidationStatus
{
    Skipped,
    Accepted,
    Rejected,
    Error
}
