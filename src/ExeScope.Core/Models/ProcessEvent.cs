using System.Text.Json.Serialization;

namespace ExeScope.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ProcessEventType
{
    Started,
    Terminated,
    ModuleLoaded
}

public class ProcessEvent : AnalysisEvent
{
    public ProcessEventType EventType { get; set; }

    public int ParentProcessId { get; set; }

    public string? ParentImage { get; set; }

    public string? ImagePath { get; set; }

    public string? CommandLine { get; set; }

    public int? ExitCode { get; set; }

    public string? ModulePath { get; set; }

    public ulong? ModuleBaseAddress { get; set; }

    public uint? ModuleSize { get; set; }

    public ProcessEvent() : base(EventCategory.Process)
    {
    }
}
