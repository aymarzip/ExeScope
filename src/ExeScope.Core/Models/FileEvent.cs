using System.Text.Json.Serialization;

namespace ExeScope.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FileOperationType
{
    Create,
    Open,
    Read,
    Write,
    Rename,
    Delete,
    Close,
    Other
}

public class FileEvent : AnalysisEvent
{
    public FileOperationType Operation { get; set; }

    public string Path { get; set; } = string.Empty;

    public string? NewPath { get; set; }

    public string Result { get; set; } = "SUCCESS";

    public long? ByteOffset { get; set; }

    public long? ByteCount { get; set; }

    /// <summary>
    /// Explicit flag clarifying that an operation log does not include or guarantee file bytes.
    /// File bytes are only captured in preserved artifacts according to policies.
    /// </summary>
    public bool HasCapturedBytes { get; set; } = false;

    public FileEvent() : base(EventCategory.File)
    {
    }
}
