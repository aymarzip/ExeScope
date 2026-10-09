using GrpcModel = ExeScope.Contracts.Grpc;
using EventModel = ExeScope.Contracts.Events;

namespace ExeScope.Contracts.Mapping;

public static class ContractMapper
{
    public static GrpcModel.TelemetryEnvelope ToEnvelope(EventModel.ProcessStartedEvent evt)
    {
        return new GrpcModel.TelemetryEnvelope
        {
            EventId = evt.EventId,
            TimestampUtc = evt.TimestampUtc.ToString("o"),
            Category = "Process",
            ProcessId = evt.ProcessId,
            ProcessImage = evt.ProcessImage,
            Summary = $"Process started: {evt.ProcessImage} (PID: {evt.ProcessId})",
            ProcessStarted = new GrpcModel.ProcessStartedEvent
            {
                ProcessId = evt.ProcessId,
                ParentProcessId = evt.ParentProcessId,
                ParentImage = evt.ParentImage ?? string.Empty,
                ImagePath = evt.ImagePath ?? string.Empty,
                CommandLine = evt.CommandLine ?? string.Empty,
                TimestampUtc = evt.TimestampUtc.ToString("o")
            }
        };
    }

    public static GrpcModel.TelemetryEnvelope ToEnvelope(EventModel.DllInjectedEvent evt)
    {
        return new GrpcModel.TelemetryEnvelope
        {
            EventId = evt.EventId,
            TimestampUtc = evt.TimestampUtc.ToString("o"),
            Category = "Injection",
            ProcessId = evt.SourceProcessId,
            ProcessImage = evt.SourceProcessImage ?? string.Empty,
            Summary = $"Injection [{evt.Technique}]: PID {evt.SourceProcessId} -> PID {evt.TargetProcessId}",
            DllInjected = new GrpcModel.DllInjectedEvent
            {
                SourceProcessId = evt.SourceProcessId,
                SourceProcessImage = evt.SourceProcessImage ?? string.Empty,
                TargetProcessId = evt.TargetProcessId,
                TargetProcessImage = evt.TargetProcessImage ?? string.Empty,
                InjectedModulePath = evt.InjectedModulePath ?? string.Empty,
                Technique = evt.Technique,
                Details = evt.Details ?? string.Empty,
                RemoteThreadAddress = evt.RemoteThreadStartAddress ?? 0,
                TimestampUtc = evt.TimestampUtc.ToString("o")
            }
        };
    }

    public static GrpcModel.TelemetryEnvelope ToEnvelope(EventModel.RegistryModifiedEvent evt)
    {
        return new GrpcModel.TelemetryEnvelope
        {
            EventId = evt.EventId,
            TimestampUtc = evt.TimestampUtc.ToString("o"),
            Category = "Registry",
            ProcessId = evt.ProcessId,
            ProcessImage = evt.ProcessImage,
            Summary = $"Registry {evt.Operation}: {evt.KeyPath}",
            RegistryModified = new GrpcModel.RegistryModifiedEvent
            {
                ProcessId = evt.ProcessId,
                ProcessImage = evt.ProcessImage,
                Operation = evt.Operation,
                KeyPath = evt.KeyPath,
                ValueName = evt.ValueName ?? string.Empty,
                ValueType = evt.ValueType ?? string.Empty,
                ValueDataSummary = evt.ValueDataSummary ?? string.Empty,
                Result = evt.Result,
                TimestampUtc = evt.TimestampUtc.ToString("o")
            }
        };
    }

    public static GrpcModel.TelemetryEnvelope ToEnvelope(EventModel.NetworkConnectionEvent evt)
    {
        return new GrpcModel.TelemetryEnvelope
        {
            EventId = evt.EventId,
            TimestampUtc = evt.TimestampUtc.ToString("o"),
            Category = "Network",
            ProcessId = evt.ProcessId,
            ProcessImage = evt.ProcessImage,
            Summary = $"Network {evt.Protocol} {evt.Direction}: {evt.RemoteEndpoint}",
            NetworkConnection = new GrpcModel.NetworkConnectionEvent
            {
                ProcessId = evt.ProcessId,
                ProcessImage = evt.ProcessImage,
                Protocol = evt.Protocol,
                Direction = evt.Direction,
                LocalEndpoint = evt.LocalEndpoint,
                RemoteEndpoint = evt.RemoteEndpoint,
                BytesTransferred = evt.BytesTransferred ?? 0,
                DnsQuery = evt.DnsQuery ?? string.Empty,
                DnsResponse = evt.DnsResponse ?? string.Empty,
                CorrelationMethod = evt.CorrelationMethod,
                Confidence = evt.Confidence,
                SecurityNotes = evt.SecurityNotes ?? string.Empty,
                TimestampUtc = evt.TimestampUtc.ToString("o")
            }
        };
    }

    public static GrpcModel.TelemetryEnvelope ToEnvelope(EventModel.FileModifiedEvent evt)
    {
        return new GrpcModel.TelemetryEnvelope
        {
            EventId = evt.EventId,
            TimestampUtc = evt.TimestampUtc.ToString("o"),
            Category = "File",
            ProcessId = evt.ProcessId,
            ProcessImage = evt.ProcessImage,
            Summary = $"File {evt.Operation}: {evt.FilePath}",
            FileModified = new GrpcModel.FileModifiedEvent
            {
                ProcessId = evt.ProcessId,
                ProcessImage = evt.ProcessImage,
                Operation = evt.Operation,
                FilePath = evt.FilePath,
                Result = evt.Result,
                ByteOffset = evt.ByteOffset ?? 0,
                ByteCount = evt.ByteCount ?? 0,
                TimestampUtc = evt.TimestampUtc.ToString("o")
            }
        };
    }

    public static EventModel.ProcessStartedEvent? FromEnvelopeToProcess(GrpcModel.TelemetryEnvelope env)
    {
        if (env.PayloadCase != GrpcModel.TelemetryEnvelope.PayloadOneofCase.ProcessStarted)
            return null;

        var p = env.ProcessStarted;
        DateTime ts = DateTime.TryParse(p.TimestampUtc, out var dt) ? dt : DateTime.UtcNow;
        return new EventModel.ProcessStartedEvent(
            EventId: env.EventId,
            TimestampUtc: ts,
            ProcessId: p.ProcessId,
            ParentProcessId: p.ParentProcessId,
            ProcessImage: env.ProcessImage,
            ParentImage: p.ParentImage,
            ImagePath: p.ImagePath,
            CommandLine: p.CommandLine
        );
    }

    public static EventModel.DllInjectedEvent? FromEnvelopeToInjection(GrpcModel.TelemetryEnvelope env)
    {
        if (env.PayloadCase != GrpcModel.TelemetryEnvelope.PayloadOneofCase.DllInjected)
            return null;

        var i = env.DllInjected;
        DateTime ts = DateTime.TryParse(i.TimestampUtc, out var dt) ? dt : DateTime.UtcNow;
        return new EventModel.DllInjectedEvent(
            EventId: env.EventId,
            TimestampUtc: ts,
            SourceProcessId: i.SourceProcessId,
            SourceProcessImage: i.SourceProcessImage,
            TargetProcessId: i.TargetProcessId,
            TargetProcessImage: i.TargetProcessImage,
            InjectedModulePath: i.InjectedModulePath,
            Technique: i.Technique,
            Details: i.Details,
            RemoteThreadStartAddress: i.RemoteThreadAddress
        );
    }

    public static EventModel.RegistryModifiedEvent? FromEnvelopeToRegistry(GrpcModel.TelemetryEnvelope env)
    {
        if (env.PayloadCase != GrpcModel.TelemetryEnvelope.PayloadOneofCase.RegistryModified)
            return null;

        var r = env.RegistryModified;
        DateTime ts = DateTime.TryParse(r.TimestampUtc, out var dt) ? dt : DateTime.UtcNow;
        return new EventModel.RegistryModifiedEvent(
            EventId: env.EventId,
            TimestampUtc: ts,
            ProcessId: r.ProcessId,
            ProcessImage: env.ProcessImage,
            Operation: r.Operation,
            KeyPath: r.KeyPath,
            ValueName: r.ValueName,
            ValueType: r.ValueType,
            ValueDataSummary: r.ValueDataSummary,
            Result: r.Result
        );
    }

    public static EventModel.NetworkConnectionEvent? FromEnvelopeToNetwork(GrpcModel.TelemetryEnvelope env)
    {
        if (env.PayloadCase != GrpcModel.TelemetryEnvelope.PayloadOneofCase.NetworkConnection)
            return null;

        var n = env.NetworkConnection;
        DateTime ts = DateTime.TryParse(n.TimestampUtc, out var dt) ? dt : DateTime.UtcNow;
        return new EventModel.NetworkConnectionEvent(
            EventId: env.EventId,
            TimestampUtc: ts,
            ProcessId: n.ProcessId,
            ProcessImage: env.ProcessImage,
            Protocol: n.Protocol,
            Direction: n.Direction,
            LocalEndpoint: n.LocalEndpoint,
            RemoteEndpoint: n.RemoteEndpoint,
            BytesTransferred: n.BytesTransferred,
            DnsQuery: n.DnsQuery,
            DnsResponse: n.DnsResponse,
            CorrelationMethod: n.CorrelationMethod,
            Confidence: n.Confidence,
            SecurityNotes: n.SecurityNotes
        );
    }

    public static EventModel.FileModifiedEvent? FromEnvelopeToFile(GrpcModel.TelemetryEnvelope env)
    {
        if (env.PayloadCase != GrpcModel.TelemetryEnvelope.PayloadOneofCase.FileModified)
            return null;

        var f = env.FileModified;
        DateTime ts = DateTime.TryParse(f.TimestampUtc, out var dt) ? dt : DateTime.UtcNow;
        return new EventModel.FileModifiedEvent(
            EventId: env.EventId,
            TimestampUtc: ts,
            ProcessId: f.ProcessId,
            ProcessImage: env.ProcessImage,
            Operation: f.Operation,
            FilePath: f.FilePath,
            Result: f.Result,
            ByteOffset: f.ByteOffset,
            ByteCount: f.ByteCount
        );
    }
}
