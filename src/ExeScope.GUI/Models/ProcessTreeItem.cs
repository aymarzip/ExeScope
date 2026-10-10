using System.Collections.ObjectModel;
using ExeScope.GUI.ViewModels;

namespace ExeScope.GUI.Models;

public class ProcessTreeItem : ViewModelBase
{
    private int _processId;
    private int _parentProcessId;
    private string _imageName = string.Empty;
    private string _imagePath = string.Empty;
    private string _commandLine = string.Empty;
    private DateTime _startTimeUtc;
    private DateTime? _exitTimeUtc;
    private int? _exitCode;
    private bool _isInjectionTarget;
    private int? _injectedByPid;

    public int ProcessId
    {
        get => _processId;
        set => SetProperty(ref _processId, value);
    }

    public int ParentProcessId
    {
        get => _parentProcessId;
        set => SetProperty(ref _parentProcessId, value);
    }

    public string ImageName
    {
        get => _imageName;
        set => SetProperty(ref _imageName, value);
    }

    public string ImagePath
    {
        get => _imagePath;
        set => SetProperty(ref _imagePath, value);
    }

    public string CommandLine
    {
        get => _commandLine;
        set => SetProperty(ref _commandLine, value);
    }

    public DateTime StartTimeUtc
    {
        get => _startTimeUtc;
        set => SetProperty(ref _startTimeUtc, value);
    }

    public DateTime? ExitTimeUtc
    {
        get => _exitTimeUtc;
        set
        {
            if (SetProperty(ref _exitTimeUtc, value))
            {
                OnPropertyChanged(nameof(IsRunning));
                OnPropertyChanged(nameof(StatusText));
            }
        }
    }

    public int? ExitCode
    {
        get => _exitCode;
        set
        {
            if (SetProperty(ref _exitCode, value))
            {
                OnPropertyChanged(nameof(StatusText));
            }
        }
    }

    public bool IsRunning => !ExitTimeUtc.HasValue;

    public bool IsInjectionTarget
    {
        get => _isInjectionTarget;
        set => SetProperty(ref _isInjectionTarget, value);
    }

    public int? InjectedByPid
    {
        get => _injectedByPid;
        set => SetProperty(ref _injectedByPid, value);
    }

    public List<string> InjectedModules { get; } = new();

    public void AddInjectedModule(string module)
    {
        if (!string.IsNullOrWhiteSpace(module) && !InjectedModules.Contains(module))
        {
            InjectedModules.Add(module);
            OnPropertyChanged(nameof(InjectedModulesSummary));
        }
    }

    public string InjectedModulesSummary => InjectedModules.Count > 0 ? string.Join(", ", InjectedModules) : string.Empty;
    public string StatusText => IsRunning ? "RUNNING" : $"EXITED ({ExitCode ?? 0})";

    public ObservableCollection<ProcessTreeItem> Children { get; } = new();
}
