namespace ExeScope.Core.Models;

public class SessionMetadata
{
    public string SessionId { get; set; } = string.Empty;

    public string SessionDirectory { get; set; } = string.Empty;

    public TargetExeInfo? TargetExe { get; set; }

    public SessionConfig Config { get; set; } = new();

    public DateTime SessionCreatedUtc { get; set; } = DateTime.UtcNow;

    public DateTime? WaitingStartedUtc { get; set; }

    public DateTime? TargetLaunchDetectedUtc { get; set; }

    public DateTime? RecordingEndedUtc { get; set; }

    public int RootProcessId { get; set; }

    public long TotalEventsRecorded { get; set; }

    public long TotalEventsDropped { get; set; }

    public long TotalArtifactsSaved { get; set; }

    public long TotalArtifactsSkipped { get; set; }

    public long TotalArtifactBytesWritten { get; set; }

    public bool IsElevated { get; set; }

    public string ExitReason { get; set; } = string.Empty;

    public List<string> ActiveCapabilities { get; set; } = new();

    public List<string> SourceLimitations { get; set; } = new();

    public bool TargetModifiedAfterSelection { get; set; }

    public string? TargetModifiedWarning { get; set; }
}
