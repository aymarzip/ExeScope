namespace ExeScope.Contracts.Events;

public sealed record FileModifiedEvent(
    long EventId,
    DateTime TimestampUtc,
    int ProcessId,
    string ProcessImage,
    string Operation,
    string FilePath,
    string Result,
    long? ByteOffset = null,
    long? ByteCount = null
);
