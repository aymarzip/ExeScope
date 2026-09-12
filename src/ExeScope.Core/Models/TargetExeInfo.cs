namespace ExeScope.Core.Models;

public class TargetExeInfo
{
    public string OriginalPath { get; set; } = string.Empty;

    public string CanonicalPath { get; set; } = string.Empty;

    public string FileName { get; set; } = string.Empty;

    public long FileSizeBytes { get; set; }

    public DateTime CreationTimeUtc { get; set; }

    public DateTime LastWriteTimeUtc { get; set; }

    public string Sha256 { get; set; } = string.Empty;

    public bool IsSigned { get; set; }

    public string? SignerSubject { get; set; }

    public string? SignerIssuer { get; set; }

    public string? CertificateThumbprint { get; set; }

    public string? SignatureStatus { get; set; }

    public DateTime SnapshotTimeUtc { get; set; } = DateTime.UtcNow;
}
