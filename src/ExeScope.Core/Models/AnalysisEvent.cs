using System.Text.Json.Serialization;

namespace ExeScope.Core.Models;

[JsonPolymorphic(TypeDiscriminatorPropertyName = "$type")]
[JsonDerivedType(typeof(ProcessEvent), typeDiscriminator: "process")]
[JsonDerivedType(typeof(FileEvent), typeDiscriminator: "file")]
[JsonDerivedType(typeof(RegistryEvent), typeDiscriminator: "registry")]
[JsonDerivedType(typeof(NetworkEvent), typeDiscriminator: "network")]
[JsonDerivedType(typeof(DiagnosticEvent), typeDiscriminator: "diagnostic")]
public abstract class AnalysisEvent
{
    public long EventId { get; set; }

    /// <summary>
    /// UTC timestamp of the event.
    /// </summary>
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    public EventCategory Category { get; set; }

    public int ProcessId { get; set; }

    public string ProcessImage { get; set; } = string.Empty;

    public string Summary { get; set; } = string.Empty;

    public Dictionary<string, string>? Metadata { get; set; }

    protected AnalysisEvent(EventCategory category)
    {
        Category = category;
    }
}

public class DiagnosticEvent : AnalysisEvent
{
    public string Level { get; set; } = "INFO";
    public string Message { get; set; } = string.Empty;
    public string? Source { get; set; }

    public DiagnosticEvent() : base(EventCategory.Diagnostic)
    {
    }
}
