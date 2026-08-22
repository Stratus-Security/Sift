using System.Text.Json.Serialization;

namespace Stratus.Sift.Core.Enums;

[JsonConverter(typeof(JsonStringEnumConverter<ConfidenceLevel>))]
public enum ConfidenceLevel
{
    Low,
    Medium,
    High
}
