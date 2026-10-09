namespace ExeScope.Contracts.Events;

public sealed record ProcessStartedEvent(
    long EventId,
    DateTime TimestampUtc,
    int ProcessId,
    int ParentProcessId,
    string ProcessImage,
    string? ParentImage,
    string? ImagePath,
    string? CommandLine
);
