namespace ExeScope.Core.Models;

public class SessionConfig
{
    public string TargetExePath { get; set; } = string.Empty;

    public string OutputDirectory { get; set; } = string.Empty;

    public long MaxTotalEvents { get; set; } = 500_000;

    public int MaxChannelCapacity { get; set; } = 50_000;

    public bool EnableArtifactSaving { get; set; } = true;

    public long MaxArtifactFileSizeBytes { get; set; } = 10 * 1024 * 1024; // 10 MB per file

    public long MaxTotalArtifactStorageBytes { get; set; } = 100 * 1024 * 1024; // 100 MB total budget

    /// <summary>
    /// Safe directories to monitor for saving artifacts.
    /// Excludes system directories by default to prevent copying OS system binaries.
    /// </summary>
    public List<string> ArtifactMonitoredDirectories { get; set; } = new()
    {
        Path.GetTempPath(),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
    };

    /// <summary>
    /// Promiscuous / raw packet capture to PCAPNG.
    /// Default is false, with explicit warnings before enabling.
    /// </summary>
    public bool EnablePacketCapture { get; set; } = false;

    /// <summary>
    /// Automatically complete session once all tracked processes exit.
    /// If false, wait for manual user stop.
    /// </summary>
    public bool AutoCompleteOnAllProcessesExit { get; set; } = true;
}
