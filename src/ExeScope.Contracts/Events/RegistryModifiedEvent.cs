namespace ExeScope.Contracts.Events;

public sealed record RegistryModifiedEvent(
    long EventId,
    DateTime TimestampUtc,
    int ProcessId,
    string ProcessImage,
    string Operation,
    string KeyPath,
    string? ValueName,
    string? ValueType,
    string? ValueDataSummary,
    string Result
);
