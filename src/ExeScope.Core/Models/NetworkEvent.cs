using System.Text.Json.Serialization;

namespace ExeScope.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum NetworkDirection
{
    Inbound,
    Outbound,
    Unknown
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum NetworkProtocol
{
    TCP,
    UDP,
    DNS,
    ICMP,
    Other
}

public class NetworkEvent : AnalysisEvent
{
    public NetworkProtocol Protocol { get; set; } = NetworkProtocol.TCP;

    public NetworkDirection Direction { get; set; } = NetworkDirection.Outbound;

    public string LocalAddress { get; set; } = string.Empty;

    public int LocalPort { get; set; }

    public string RemoteAddress { get; set; } = string.Empty;

    public int RemotePort { get; set; }

    public long? BytesTransferred { get; set; }

    public string? DnsQuery { get; set; }

    public string? DnsResponse { get; set; }

    public NetworkCorrelationMethod CorrelationMethod { get; set; } = NetworkCorrelationMethod.ExactPidMatch;

    /// <summary>
    /// Confidence of association with the monitored process: "High", "Medium", "Low".
    /// </summary>
    public string Confidence { get; set; } = "High";

    /// <summary>
    /// Explicit notes indicating privacy/encryption status (e.g. "Encrypted TLS stream, payload not decrypted").
    /// </summary>
    public string? SecurityNotes { get; set; }

    public string LocalEndpoint => $"{LocalAddress}:{LocalPort}";
    public string RemoteEndpoint => Protocol == NetworkProtocol.DNS ? $"DNS: {DnsQuery} -> {DnsResponse}" : $"{RemoteAddress}:{RemotePort}";

    public NetworkEvent() : base(EventCategory.Network)
    {
    }
}
