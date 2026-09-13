namespace ExeScope.Engine.Tracking;

public class TrackedProcess
{
    public int ProcessId { get; set; }

    public int ParentProcessId { get; set; }

    public string ImagePath { get; set; } = string.Empty;

    public string ImageName { get; set; } = string.Empty;

    public string CommandLine { get; set; } = string.Empty;

    public DateTime StartTimeUtc { get; set; } = DateTime.UtcNow;

    public DateTime? ExitTimeUtc { get; set; }

    public int? ExitCode { get; set; }

    public bool IsRoot { get; set; }

    public bool IsInjectionTarget { get; set; }

    public int? InjectedByPid { get; set; }

    public bool IsAlive => !ExitTimeUtc.HasValue;

    public HashSet<string> LoadedModules { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> InjectedModules { get; } = new();

    public List<TrackedProcess> Children { get; } = new();
}
