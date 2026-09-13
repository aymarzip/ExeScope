using System.Text.Json.Serialization;

namespace ExeScope.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EventCategory
{
    Process,
    File,
    Registry,
    Network,
    Injection,
    Diagnostic
}
