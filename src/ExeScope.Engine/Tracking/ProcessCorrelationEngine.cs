using System.Collections.Concurrent;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Core.Utilities;

namespace ExeScope.Engine.Tracking;

public class ProcessCorrelationEngine
{
    private readonly object _sync = new();
    private readonly IDiagnosticLogger _logger;
    private readonly TargetExeInfo _targetExe;

    // Track all processes by unique key: (PID, StartTimeUtc ticks)
    private readonly List<TrackedProcess> _allProcesses = new();
    private readonly Dictionary<int, List<TrackedProcess>> _processesByPid = new();
    private readonly Dictionary<int, TrackedProcess> _injectionTargets = new();

    private TrackedProcess? _rootProcess;
    private bool _rootProcessLaunched;

    public bool HasRootLaunched => _rootProcessLaunched;
    public TrackedProcess? RootProcess => _rootProcess;

    public event Action<TrackedProcess>? OnProcessStarted;
    public event Action<TrackedProcess>? OnProcessTerminated;
    public event Action<TrackedProcess>? OnRepeatedLaunchDetected;
    public event Action? OnAllTrackedProcessesExited;
    public event Action<TrackedProcess>? OnInjectionTargetRegistered;

    public ProcessCorrelationEngine(TargetExeInfo targetExe, IDiagnosticLogger logger)
    {
        _targetExe = targetExe;
        _logger = logger;
    }

    /// <summary>
    /// Evaluates whether a newly started process matches the target executable or is a child of a tracked process.
    /// </summary>
    public bool TryRegisterProcess(int pid, int parentPid, string imagePath, string commandLine, DateTime startTimeUtc, out TrackedProcess? registered)
    {
        registered = null;
        lock (_sync)
        {
            string canonicalImage = PathSanitizer.NormalizeCanonicalPath(imagePath);
            bool matchesTargetExe = PathSanitizer.ArePathsEquivalent(canonicalImage, _targetExe.CanonicalPath);

            // Match primary target launch
            if (matchesTargetExe && !_rootProcessLaunched)
            {
                _rootProcess = new TrackedProcess
                {
                    ProcessId = pid,
                    ParentProcessId = parentPid,
                    ImagePath = canonicalImage,
                    ImageName = Path.GetFileName(imagePath),
                    CommandLine = commandLine,
                    StartTimeUtc = startTimeUtc,
                    IsRoot = true
                };

                _rootProcessLaunched = true;
                AddProcessInternal(_rootProcess);

                _logger.Info("ProcessCorrelation", $"Target executable launch confirmed! PID: {pid}, Image: {canonicalImage}");
                registered = _rootProcess;
                OnProcessStarted?.Invoke(_rootProcess);
                return true;
            }

            // Descendant of any active or previously tracked process
            if (_rootProcessLaunched && parentPid > 0)
            {
                var parent = FindActiveParent(parentPid, startTimeUtc);
                if (parent != null)
                {
                    var child = new TrackedProcess
                    {
                        ProcessId = pid,
                        ParentProcessId = parentPid,
                        ImagePath = canonicalImage,
                        ImageName = Path.GetFileName(imagePath),
                        CommandLine = commandLine,
                        StartTimeUtc = startTimeUtc,
                        IsRoot = false
                    };

                    parent.Children.Add(child);
                    AddProcessInternal(child);

                    _logger.Info("ProcessCorrelation", $"Tracked child process spawned! PID: {pid}, Parent PID: {parentPid}, Image: {canonicalImage}");
                    registered = child;
                    OnProcessStarted?.Invoke(child);
                    return true;
                }
            }

            // Repeated launch of the root executable (not spawned by a tracked process)
            if (matchesTargetExe && _rootProcessLaunched)
            {
                var repeated = new TrackedProcess
                {
                    ProcessId = pid,
                    ParentProcessId = parentPid,
                    ImagePath = canonicalImage,
                    ImageName = Path.GetFileName(imagePath),
                    CommandLine = commandLine,
                    StartTimeUtc = startTimeUtc,
                    IsRoot = true
                };

                _logger.Warn("ProcessCorrelation", $"Repeated launch of target executable detected! New PID: {pid}. Raising separate session event.");
                OnRepeatedLaunchDetected?.Invoke(repeated);
                return false;
            }

            return false;
        }
    }

    /// <summary>
    /// Marks a process as terminated. Checks whether all tracked processes have completed.
    /// </summary>
    public bool RegisterProcessExit(int pid, DateTime exitTimeUtc, int? exitCode)
    {
        lock (_sync)
        {
            if (!_processesByPid.TryGetValue(pid, out var list))
                return false;

            // Find the most recent process with this PID that is not yet terminated
            var proc = list.LastOrDefault(p => !p.ExitTimeUtc.HasValue);
            if (proc == null)
                return false;

            proc.ExitTimeUtc = exitTimeUtc;
            proc.ExitCode = exitCode;

            _logger.Info("ProcessCorrelation", $"Tracked process exited: PID {pid}, Image: {proc.ImageName}, ExitCode: {exitCode}");
            OnProcessTerminated?.Invoke(proc);

            // Check if any tracked processes are still running
            if (!HasActiveTrackedProcesses())
            {
                _logger.Info("ProcessCorrelation", "All tracked processes (root and children) have exited.");
                OnAllTrackedProcessesExited?.Invoke();
            }

            return true;
        }
    }

    /// <summary>
    /// Registers a module loaded by a tracked process.
    /// </summary>
    public void RegisterModuleLoaded(int pid, string modulePath, DateTime timestampUtc)
    {
        lock (_sync)
        {
            var proc = FindTrackedProcess(pid, timestampUtc);
            if (proc != null && !string.IsNullOrWhiteSpace(modulePath))
            {
                proc.LoadedModules.Add(modulePath);
            }
        }
    }

    /// <summary>
    /// Checks whether an event occurring at timestampUtc associated with PID is from a tracked process.
    /// Correctly guards against Windows PID recycling.
    /// </summary>
    public bool IsProcessTracked(int pid, DateTime timestampUtc, out TrackedProcess? tracked)
    {
        lock (_sync)
        {
            tracked = FindTrackedProcess(pid, timestampUtc);
            return tracked != null;
        }
    }

    public bool HasActiveTrackedProcesses()
    {
        lock (_sync)
        {
            return _allProcesses.Any(p => p.IsAlive);
        }
    }

    public IReadOnlyList<TrackedProcess> GetAllTrackedProcesses()
    {
        lock (_sync)
        {
            return _allProcesses.ToList();
        }
    }

    public ProcessNode? BuildProcessTree()
    {
        lock (_sync)
        {
            if (_rootProcess == null)
                return null;

            return MapToNode(_rootProcess);
        }
    }

    public void RegisterInjectionTarget(int pid, string imagePath, int injectedByPid, string? modulePath, DateTime timestampUtc)
    {
        lock (_sync)
        {
            if (_injectionTargets.ContainsKey(pid))
            {
                if (modulePath != null)
                    _injectionTargets[pid].InjectedModules.Add(modulePath);
                return;
            }

            var target = new TrackedProcess
            {
                ProcessId = pid,
                ImagePath = PathSanitizer.NormalizeCanonicalPath(imagePath),
                ImageName = Path.GetFileName(imagePath),
                StartTimeUtc = timestampUtc,
                IsInjectionTarget = true,
                InjectedByPid = injectedByPid
            };

            if (modulePath != null)
                target.InjectedModules.Add(modulePath);

            _injectionTargets[pid] = target;
            AddProcessInternal(target);

            _logger.Info("ProcessCorrelation", $"Injection target registered: PID {pid} ({target.ImageName}), injected by PID {injectedByPid}");
            OnInjectionTargetRegistered?.Invoke(target);
        }
    }

    public bool IsInjectionTarget(int pid)
    {
        lock (_sync)
        {
            return _injectionTargets.ContainsKey(pid);
        }
    }

    public bool IsProcessTrackedOrInjectionTarget(int pid, DateTime timestampUtc, out TrackedProcess? tracked)
    {
        lock (_sync)
        {
            tracked = FindTrackedProcess(pid, timestampUtc);
            if (tracked != null)
                return true;

            if (_injectionTargets.TryGetValue(pid, out tracked))
                return true;

            return false;
        }
    }

    public IReadOnlyList<TrackedProcess> GetInjectionTargets()
    {
        lock (_sync)
        {
            return _injectionTargets.Values.ToList();
        }
    }

    private ProcessNode MapToNode(TrackedProcess proc)
    {
        var node = new ProcessNode
        {
            ProcessId = proc.ProcessId,
            ParentProcessId = proc.ParentProcessId,
            ImageName = proc.ImageName,
            ImagePath = proc.ImagePath,
            CommandLine = proc.CommandLine,
            StartTimeUtc = proc.StartTimeUtc,
            ExitTimeUtc = proc.ExitTimeUtc,
            ExitCode = proc.ExitCode,
            IsRoot = proc.IsRoot,
            IsInjectionTarget = proc.IsInjectionTarget,
            InjectedByPid = proc.InjectedByPid,
            LoadedModules = proc.LoadedModules.ToList(),
            InjectedModules = proc.InjectedModules.ToList()
        };

        foreach (var child in proc.Children)
        {
            node.Children.Add(MapToNode(child));
        }

        return node;
    }

    private void AddProcessInternal(TrackedProcess proc)
    {
        _allProcesses.Add(proc);
        if (!_processesByPid.TryGetValue(proc.ProcessId, out var list))
        {
            list = new List<TrackedProcess>();
            _processesByPid[proc.ProcessId] = list;
        }
        list.Add(proc);
    }

    private TrackedProcess? FindActiveParent(int parentPid, DateTime childStartTimeUtc)
    {
        if (!_processesByPid.TryGetValue(parentPid, out var list))
            return null;

        // Parent must have started before child and not exited significantly before child creation
        return list.LastOrDefault(p => p.StartTimeUtc <= childStartTimeUtc &&
            (!p.ExitTimeUtc.HasValue || childStartTimeUtc <= p.ExitTimeUtc.Value.AddSeconds(2)));
    }

    private TrackedProcess? FindTrackedProcess(int pid, DateTime timestampUtc)
    {
        if (!_processesByPid.TryGetValue(pid, out var list))
            return null;

        // Find process whose lifetime encompasses timestampUtc (with small clock skew tolerance)
        return list.LastOrDefault(p => p.StartTimeUtc <= timestampUtc.AddSeconds(1) &&
            (!p.ExitTimeUtc.HasValue || timestampUtc <= p.ExitTimeUtc.Value.AddSeconds(2)));
    }
}
