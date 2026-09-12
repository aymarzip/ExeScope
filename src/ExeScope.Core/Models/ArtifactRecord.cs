using System.Text.Json.Serialization;

namespace ExeScope.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ArtifactCopyStatus
{
    Success,
    Locked,
    DeletedBeforeCopy,
    QuotaExceeded,
    SizeLimitExceeded,
    DirectoryExcluded,
    AccessDenied,
    Error
}

public class ArtifactRecord
{
    public string OriginalPath { get; set; } = string.Empty;

    public string ArtifactFileName { get; set; } = string.Empty;

    public string RelativeStoragePath { get; set; } = string.Empty;

    public string Sha256 { get; set; } = string.Empty;

    public long SizeBytes { get; set; }

    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    public ArtifactCopyStatus CopyStatus { get; set; } = ArtifactCopyStatus.Success;

    public string? FailureReason { get; set; }

    /// <summary>
    /// Set to true if the file was modified or length changed while reading.
    /// </summary>
    public bool MightHaveChangedDuringCopy { get; set; }

    public int OriginatingProcessId { get; set; }

    public string? OriginatingProcessImage { get; set; }
}
