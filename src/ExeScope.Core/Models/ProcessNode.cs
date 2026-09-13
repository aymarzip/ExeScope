namespace ExeScope.Core.Models;

public class ProcessNode
{
    public int ProcessId { get; set; }

    public int ParentProcessId { get; set; }

    public string ImageName { get; set; } = string.Empty;

    public string ImagePath { get; set; } = string.Empty;

    public string CommandLine { get; set; } = string.Empty;

    public DateTime StartTimeUtc { get; set; }

    public DateTime? ExitTimeUtc { get; set; }

    public int? ExitCode { get; set; }

    public bool IsRoot { get; set; }

    public bool IsInjectionTarget { get; set; }

    public int? InjectedByPid { get; set; }

    public bool IsAlive => !ExitTimeUtc.HasValue;

    public List<ProcessNode> Children { get; set; } = new();

    public List<string> LoadedModules { get; set; } = new();

    public List<string> InjectedModules { get; set; } = new();
}
