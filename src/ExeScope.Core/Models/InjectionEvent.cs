using System.Text.Json.Serialization;

namespace ExeScope.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum InjectionTechnique
{
    DllInjection,
    ManualMapping,
    ProcessHollowing,
    ThreadHijacking,
    Unknown
}

public class InjectionEvent : AnalysisEvent
{
    public InjectionTechnique Technique { get; set; }

    public int SourceProcessId { get; set; }

    public string? SourceProcessImage { get; set; }

    public int TargetProcessId { get; set; }

    public string? TargetProcessImage { get; set; }

    public string? InjectedModulePath { get; set; }

    public ulong? RemoteThreadStartAddress { get; set; }

    public string? Details { get; set; }

    public InjectionEvent() : base(EventCategory.Injection)
    {
    }
}
