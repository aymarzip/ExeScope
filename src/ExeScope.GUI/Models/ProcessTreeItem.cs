using System.Collections.ObjectModel;

namespace ExeScope.GUI.Models;

public class ProcessTreeItem
{
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string ImageName { get; set; } = string.Empty;
    public string ImagePath { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public DateTime StartTimeUtc { get; set; }
    public DateTime? ExitTimeUtc { get; set; }
    public int? ExitCode { get; set; }
    public bool IsRunning => !ExitTimeUtc.HasValue;

    public bool IsInjectionTarget { get; set; }
    public int? InjectedByPid { get; set; }
    public List<string> InjectedModules { get; set; } = new();

    public string InjectedModulesSummary => InjectedModules.Count > 0 ? string.Join(", ", InjectedModules) : string.Empty;
    public string StatusText => IsRunning ? "RUNNING" : $"EXITED ({ExitCode ?? 0})";

    public ObservableCollection<ProcessTreeItem> Children { get; } = new();
}
