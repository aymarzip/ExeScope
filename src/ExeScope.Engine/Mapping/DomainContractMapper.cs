using ExeScope.Core.Models;
using ExeScope.Contracts.Mapping;
using EventModel = ExeScope.Contracts.Events;
using GrpcModel = ExeScope.Contracts.Grpc;

namespace ExeScope.Engine.Mapping;

public static class DomainContractMapper
{
    public static GrpcModel.TelemetryEnvelope ToGrpcEnvelope(AnalysisEvent domainEvent)
    {
        return domainEvent switch
        {
            ProcessEvent pe when pe.EventType == ProcessEventType.Started =>
                ContractMapper.ToEnvelope(new EventModel.ProcessStartedEvent(
                    EventId: pe.EventId,
                    TimestampUtc: pe.TimestampUtc,
                    ProcessId: pe.ProcessId,
                    ParentProcessId: pe.ParentProcessId,
                    ProcessImage: pe.ProcessImage,
                    ParentImage: pe.ParentImage,
                    ImagePath: pe.ImagePath,
                    CommandLine: pe.CommandLine
                )),

            ProcessEvent pe when pe.EventType == ProcessEventType.Terminated =>
                new GrpcModel.TelemetryEnvelope
                {
                    EventId = pe.EventId,
                    TimestampUtc = pe.TimestampUtc.ToString("o"),
                    Category = "Process",
                    ProcessId = pe.ProcessId,
                    ProcessImage = pe.ProcessImage,
                    Summary = $"Process terminated: {pe.ProcessImage} (PID: {pe.ProcessId}, ExitCode: {pe.ExitCode})",
                    ProcessTerminated = new GrpcModel.ProcessTerminatedEvent
                    {
                        ProcessId = pe.ProcessId,
                        ImagePath = pe.ImagePath ?? string.Empty,
                        ExitCode = pe.ExitCode ?? 0,
                        TimestampUtc = pe.TimestampUtc.ToString("o")
                    }
                },

            InjectionEvent ie =>
                ContractMapper.ToEnvelope(new EventModel.DllInjectedEvent(
                    EventId: ie.EventId,
                    TimestampUtc: ie.TimestampUtc,
                    SourceProcessId: ie.SourceProcessId,
                    SourceProcessImage: ie.SourceProcessImage,
                    TargetProcessId: ie.TargetProcessId,
                    TargetProcessImage: ie.TargetProcessImage,
                    InjectedModulePath: ie.InjectedModulePath,
                    Technique: ie.Technique.ToString(),
                    Details: ie.Details,
                    RemoteThreadStartAddress: ie.RemoteThreadStartAddress
                )),

            RegistryEvent re =>
                ContractMapper.ToEnvelope(new EventModel.RegistryModifiedEvent(
                    EventId: re.EventId,
                    TimestampUtc: re.TimestampUtc,
                    ProcessId: re.ProcessId,
                    ProcessImage: re.ProcessImage,
                    Operation: re.Operation.ToString(),
                    KeyPath: re.KeyPath,
                    ValueName: re.ValueName,
                    ValueType: re.ValueType,
                    ValueDataSummary: re.ValueDataSummary,
                    Result: re.Result
                )),

            NetworkEvent ne =>
                ContractMapper.ToEnvelope(new EventModel.NetworkConnectionEvent(
                    EventId: ne.EventId,
                    TimestampUtc: ne.TimestampUtc,
                    ProcessId: ne.ProcessId,
                    ProcessImage: ne.ProcessImage,
                    Protocol: ne.Protocol.ToString(),
                    Direction: ne.Direction.ToString(),
                    LocalEndpoint: ne.LocalEndpoint,
                    RemoteEndpoint: ne.RemoteEndpoint,
                    BytesTransferred: ne.BytesTransferred,
                    DnsQuery: ne.DnsQuery,
                    DnsResponse: ne.DnsResponse,
                    CorrelationMethod: ne.CorrelationMethod.ToString(),
                    Confidence: ne.Confidence,
                    SecurityNotes: ne.SecurityNotes
                )),

            FileEvent fe =>
                ContractMapper.ToEnvelope(new EventModel.FileModifiedEvent(
                    EventId: fe.EventId,
                    TimestampUtc: fe.TimestampUtc,
                    ProcessId: fe.ProcessId,
                    ProcessImage: fe.ProcessImage,
                    Operation: fe.Operation.ToString(),
                    FilePath: fe.Path,
                    Result: fe.Result,
                    ByteOffset: fe.ByteOffset,
                    ByteCount: fe.ByteCount
                )),

            DiagnosticEvent de =>
                new GrpcModel.TelemetryEnvelope
                {
                    EventId = de.EventId,
                    TimestampUtc = de.TimestampUtc.ToString("o"),
                    Category = "Diagnostic",
                    ProcessId = de.ProcessId,
                    ProcessImage = de.ProcessImage,
                    Summary = $"[{de.Level}] {de.Source}: {de.Message}",
                    DiagnosticMessage = new GrpcModel.DiagnosticMessageEvent
                    {
                        Level = de.Level,
                        Source = de.Source ?? string.Empty,
                        Message = de.Message,
                        TimestampUtc = de.TimestampUtc.ToString("o")
                    }
                },

            _ => new GrpcModel.TelemetryEnvelope
            {
                EventId = domainEvent.EventId,
                TimestampUtc = domainEvent.TimestampUtc.ToString("o"),
                Category = domainEvent.Category.ToString(),
                ProcessId = domainEvent.ProcessId,
                ProcessImage = domainEvent.ProcessImage,
                Summary = domainEvent.Summary
            }
        };
    }
}
