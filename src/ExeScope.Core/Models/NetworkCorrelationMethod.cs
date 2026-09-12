using System.Text.Json.Serialization;

namespace ExeScope.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum NetworkCorrelationMethod
{
    ExactPidMatch,
    PortBindingHeuristic,
    DnsClientCorrelation,
    Uncorrelated
}
