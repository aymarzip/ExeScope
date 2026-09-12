using System.Diagnostics;
using System.Runtime.InteropServices;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Tracking;

namespace ExeScope.Engine.Collectors;

public class PollingProcessWatcher : IEventCollector
{
    #region Win32 Toolhelp & Process P/Invoke

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    #endregion

    private readonly ProcessCorrelationEngine _correlationEngine;
    private readonly IDiagnosticLogger _logger;
    private readonly HashSet<int> _knownSystemPids = new();
    private readonly Dictionary<int, DateTime> _knownProcessStartTimes = new();
    private CancellationTokenSource? _cts;
    private Task? _pollTask;
    private bool _isRunning;
    private long _nextEventId = 1000;

    public string Name => "Process Snapshot & Lifecycle Watcher";
    public bool IsSupported => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
    public string StatusDescription { get; private set; } = "Ready";

    public event Action<AnalysisEvent>? EventEmitted;

    public PollingProcessWatcher(ProcessCorrelationEngine correlationEngine, IDiagnosticLogger logger)
    {
        _correlationEngine = correlationEngine;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (_isRunning)
            return Task.CompletedTask;

        _isRunning = true;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Pre-populate baseline system PIDs to avoid reporting pre-existing processes as new
        SnapshotProcesses(isBaseline: true);

        _pollTask = Task.Run(() => PollLoopAsync(_cts.Token), _cts.Token);
        StatusDescription = "Active (Monitoring process hierarchy)";
        _logger.Info("ProcessWatcher", "Process snapshot monitor started.");
        return Task.CompletedTask;
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _isRunning)
        {
            try
            {
                SnapshotProcesses(isBaseline: false);
                await Task.Delay(100, ct); // 100ms rapid detection
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error("ProcessWatcher", "Error in process polling loop", ex);
                await Task.Delay(500, ct);
            }
        }
    }

    private void SnapshotProcesses(bool isBaseline)
    {
        IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return;

        var currentPids = new HashSet<int>();

        try
        {
            var entry = new PROCESSENTRY32();
            entry.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>();

            if (Process32First(hSnapshot, ref entry))
            {
                do
                {
                    int pid = (int)entry.th32ProcessID;
                    int parentPid = (int)entry.th32ParentProcessID;
                    string exeName = entry.szExeFile;
                    currentPids.Add(pid);

                    if (isBaseline)
                    {
                        _knownSystemPids.Add(pid);
                        continue;
                    }

                    if (!_knownSystemPids.Contains(pid))
                    {
                        // New process detected
                        _knownSystemPids.Add(pid);
                        var nowUtc = DateTime.UtcNow;
                        _knownProcessStartTimes[pid] = nowUtc;

                        string fullImagePath = TryGetProcessPath(pid, exeName);
                        string commandLine = TryGetCommandLine(pid);

                        if (_correlationEngine.TryRegisterProcess(pid, parentPid, fullImagePath, commandLine, nowUtc, out var tracked))
                        {
                            var evt = new ProcessEvent
                            {
                                EventId = Interlocked.Increment(ref _nextEventId),
                                TimestampUtc = nowUtc,
                                ProcessId = pid,
                                ParentProcessId = parentPid,
                                ProcessImage = tracked?.ImageName ?? exeName,
                                ImagePath = tracked?.ImagePath ?? fullImagePath,
                                CommandLine = commandLine,
                                EventType = ProcessEventType.Started,
                                Summary = $"Process detected: {exeName} (PID: {pid}, Parent: {parentPid})"
                            };
                            EventEmitted?.Invoke(evt);
                        }
                    }
                }
                while (Process32Next(hSnapshot, ref entry));
            }

            if (!isBaseline)
            {
                _knownSystemPids.IntersectWith(currentPids);

                var trackedProcesses = _correlationEngine.GetAllTrackedProcesses();
                foreach (var proc in trackedProcesses)
                {
                    if (proc.IsAlive && !currentPids.Contains(proc.ProcessId))
                    {
                        var exitTime = DateTime.UtcNow;
                        _correlationEngine.RegisterProcessExit(proc.ProcessId, exitTime, exitCode: null);

                        var evt = new ProcessEvent
                        {
                            EventId = Interlocked.Increment(ref _nextEventId),
                            TimestampUtc = exitTime,
                            ProcessId = proc.ProcessId,
                            ProcessImage = proc.ImageName,
                            ImagePath = proc.ImagePath,
                            EventType = ProcessEventType.Terminated,
                            Summary = $"Process exited: {proc.ImageName} (PID: {proc.ProcessId})"
                        };
                        EventEmitted?.Invoke(evt);
                    }
                }
            }
        }
        finally
        {
            CloseHandle(hSnapshot);
        }
    }

    private static string TryGetProcessPath(int pid, string fallback)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.MainModule?.FileName ?? fallback;
        }
        catch
        {
            return fallback;
        }
    }

    private static string TryGetCommandLine(int pid)
    {
        // Safe query without crashing if process exited
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.StartInfo.Arguments;
        }
        catch
        {
            return string.Empty;
        }
    }

    public async Task StopAsync()
    {
        if (!_isRunning)
            return;

        _isRunning = false;
        StatusDescription = "Stopped";

        try
        {
            _cts?.Cancel();
            if (_pollTask != null)
            {
                await Task.WhenAny(_pollTask, Task.Delay(1000));
            }
        }
        catch (Exception ex)
        {
            _logger.Error("ProcessWatcher", "Error stopping process watcher", ex);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts?.Dispose();
    }
}
