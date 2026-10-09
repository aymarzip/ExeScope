namespace ExeScope.Contracts.Events;

public sealed record NetworkConnectionEvent(
    long EventId,
    DateTime TimestampUtc,
    int ProcessId,
    string ProcessImage,
    string Protocol,
    string Direction,
    string LocalEndpoint,
    string RemoteEndpoint,
    long? BytesTransferred,
    string? DnsQuery,
    string? DnsResponse,
    string CorrelationMethod,
    string Confidence,
    string? SecurityNotes
);
