using System.Text.Json.Serialization;

namespace Stratus.Sift.Core.Enums;

[JsonConverter(typeof(JsonStringEnumConverter<PolicyDomain>))]
public enum PolicyDomain
{
    Data,
    Infra,
    Identity,
    Secrets,
    Code,
    Ai
}
