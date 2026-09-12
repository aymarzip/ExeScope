using System.Text.Json.Serialization;

namespace ExeScope.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RegistryOperationType
{
    CreateKey,
    OpenKey,
    DeleteKey,
    SetValue,
    DeleteValue,
    QueryValue,
    Other
}

public class RegistryEvent : AnalysisEvent
{
    public RegistryOperationType Operation { get; set; }

    public string KeyPath { get; set; } = string.Empty;

    public string? ValueName { get; set; }

    public string? ValueType { get; set; }

    public string? ValueDataSummary { get; set; }

    public string Result { get; set; } = "SUCCESS";

    public RegistryEvent() : base(EventCategory.Registry)
    {
    }
}
