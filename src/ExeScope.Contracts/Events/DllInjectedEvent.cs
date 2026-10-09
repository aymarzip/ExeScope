namespace ExeScope.Contracts.Events;

public sealed record DllInjectedEvent(
    long EventId,
    DateTime TimestampUtc,
    int SourceProcessId,
    string? SourceProcessImage,
    int TargetProcessId,
    string? TargetProcessImage,
    string? InjectedModulePath,
    string Technique,
    string? Details,
    ulong? RemoteThreadStartAddress = null
);
