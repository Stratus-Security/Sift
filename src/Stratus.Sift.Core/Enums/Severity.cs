using System.Text.Json.Serialization;

namespace Stratus.Sift.Core.Enums;

[JsonConverter(typeof(JsonStringEnumConverter<Severity>))]
public enum Severity
{
    Info,
    Informational,
    Low,
    Medium,
    High,
    Critical
}
