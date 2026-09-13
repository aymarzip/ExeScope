using System.Collections.Concurrent;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Tracking;

namespace ExeScope.Engine.Detection;

public class InjectionDetector : IDisposable
{
    private readonly ProcessCorrelationEngine _correlationEngine;
    private readonly IDiagnosticLogger _logger;
    private readonly bool _trackTargetEvents;

    private readonly ConcurrentDictionary<string, DllWriteRecord> _recentDllWrites = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, RemoteThreadRecord> _suspiciousThreads = new();
    private readonly ConcurrentDictionary<int, byte> _confirmedTargetPids = new();

    private readonly Timer _cleanupTimer;
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(15);

    private long _nextEventId;
    private bool _disposed;

    public event Action<InjectionEvent>? InjectionDetected;

    public InjectionDetector(
        ProcessCorrelationEngine correlationEngine,
        IDiagnosticLogger logger,
        bool trackTargetEvents = true,
        long startEventId = 900_000_000)
    {
        _correlationEngine = correlationEngine;
        _logger = logger;
        _trackTargetEvents = trackTargetEvents;
        _nextEventId = startEventId;

        _cleanupTimer = new Timer(_ => CleanupStaleRecords(), null, CleanupInterval, CleanupInterval);
    }

    public void OnFileWriteByTrackedProcess(int pid, string filePath, DateTime timestampUtc)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return;

        if (!IsDllOrExecutable(filePath))
            return;

        string canonical = ExeScope.Core.Utilities.PathSanitizer.NormalizeCanonicalPath(filePath);
        _recentDllWrites[canonical] = new DllWriteRecord
        {
            WriterPid = pid,
            FilePath = canonical,
            TimestampUtc = timestampUtc
        };

        if (!string.Equals(canonical, filePath, StringComparison.OrdinalIgnoreCase))
        {
            _recentDllWrites[filePath] = new DllWriteRecord
            {
                WriterPid = pid,
                FilePath = filePath,
                TimestampUtc = timestampUtc
            };
        }
    }

    private bool TryFindRecentWrite(string modulePath, out DllWriteRecord? record)
    {
        string canonical = ExeScope.Core.Utilities.PathSanitizer.NormalizeCanonicalPath(modulePath);
        if (_recentDllWrites.TryGetValue(canonical, out record))
            return true;

        if (_recentDllWrites.TryGetValue(modulePath, out record))
            return true;

        // Check if matching by filename for non-system modules (e.g. 8.3 short name alias)
        string fileName = Path.GetFileName(modulePath);
        if (!string.IsNullOrEmpty(fileName))
        {
            foreach (var kvp in _recentDllWrites)
            {
                if (string.Equals(Path.GetFileName(kvp.Key), fileName, StringComparison.OrdinalIgnoreCase))
                {
                    record = kvp.Value;
                    return true;
                }
            }
        }

        record = null;
        return false;
    }

    public void OnImageLoadInAnyProcess(int pid, string modulePath, ulong baseAddress, uint size, DateTime timestampUtc)
    {
        if (string.IsNullOrWhiteSpace(modulePath))
            return;

        if (_correlationEngine.IsRootOrChildProcess(pid, timestampUtc, out _))
            return;

        if (IsSystemModule(modulePath))
            return;

        if (TryFindRecentWrite(modulePath, out var writeRecord) && writeRecord != null)
        {
            var timeDiff = timestampUtc - writeRecord.TimestampUtc;
            if (timeDiff >= TimeSpan.Zero && timeDiff <= CorrelationWindow)
            {
                string targetImage = TryGetProcessImage(pid);
                var evt = CreateInjectionEvent(
                    InjectionTechnique.DllInjection,
                    writeRecord.WriterPid,
                    pid,
                    targetImage,
                    modulePath,
                    null,
                    timestampUtc,
                    $"DLL записана отслеживаемым процессом и загружена в PID {pid} ({targetImage}) через {timeDiff.TotalMilliseconds:F0}ms");

                _confirmedTargetPids.TryAdd(pid, 0);

                if (_trackTargetEvents)
                {
                    _correlationEngine.RegisterInjectionTarget(
                        pid, targetImage, writeRecord.WriterPid, modulePath, timestampUtc);
                }

                _recentDllWrites.TryRemove(writeRecord.FilePath, out _);
                _recentDllWrites.TryRemove(modulePath, out _);
                EmitInjection(evt);
                return;
            }
        }

        if (_confirmedTargetPids.ContainsKey(pid) && !IsSystemModule(modulePath))
        {
            string targetImage = TryGetProcessImage(pid);
            var evt = CreateInjectionEvent(
                InjectionTechnique.Unknown,
                0,
                pid,
                targetImage,
                modulePath,
                null,
                timestampUtc,
                $"Подозрительная загрузка модуля в процесс-жертву инъекции: {Path.GetFileName(modulePath)}");

            EmitInjection(evt);
        }
    }

    public void OnThreadStartInExternalProcess(int targetPid, ulong startAddress, DateTime timestampUtc)
    {
        if (_correlationEngine.IsRootOrChildProcess(targetPid, timestampUtc, out _))
            return;

        _suspiciousThreads[targetPid] = new RemoteThreadRecord
        {
            TargetPid = targetPid,
            StartAddress = startAddress,
            TimestampUtc = timestampUtc
        };

        if (_confirmedTargetPids.ContainsKey(targetPid))
        {
            string targetImage = TryGetProcessImage(targetPid);
            var evt = CreateInjectionEvent(
                InjectionTechnique.ManualMapping,
                0,
                targetPid,
                targetImage,
                null,
                startAddress,
                timestampUtc,
                $"Новый поток в процессе-жертве: PID {targetPid}, StartAddr 0x{startAddress:X}");

            EmitInjection(evt);
            return;
        }

        Task.Delay(500).ContinueWith(_ =>
        {
            if (!_suspiciousThreads.TryGetValue(targetPid, out var record))
                return;
            if (record.TimestampUtc != timestampUtc)
                return;

            if (_confirmedTargetPids.ContainsKey(targetPid))
            {
                string targetImage = TryGetProcessImage(targetPid);
                var evt = CreateInjectionEvent(
                    InjectionTechnique.ManualMapping,
                    0,
                    targetPid,
                    targetImage,
                    null,
                    startAddress,
                    timestampUtc,
                    $"Remote thread без ImageLoad в PID {targetPid}, вероятный manual mapping");

                EmitInjection(evt);
            }
        });
    }

    public void OnProcessHandleOpened(int sourcePid, int targetPid, DateTime timestampUtc)
    {
        if (!_correlationEngine.IsProcessTracked(sourcePid, timestampUtc, out _))
            return;

        if (_correlationEngine.IsRootOrChildProcess(targetPid, timestampUtc, out _))
            return;

        string targetImage = TryGetProcessImage(targetPid);
        _logger.Info("InjectionDetector",
            $"Отслеживаемый процесс (PID {sourcePid}) открыл хэндл на внешний процесс PID {targetPid} ({targetImage})");

        _confirmedTargetPids.TryAdd(targetPid, 0);

        if (_trackTargetEvents)
        {
            _correlationEngine.RegisterInjectionTarget(
                targetPid, targetImage, sourcePid, null, timestampUtc);
        }
    }

    private InjectionEvent CreateInjectionEvent(
        InjectionTechnique technique,
        int sourcePid,
        int targetPid,
        string targetImage,
        string? modulePath,
        ulong? threadStartAddr,
        DateTime timestampUtc,
        string details)
    {
        string sourceImage = sourcePid > 0 ? TryGetProcessImage(sourcePid) : string.Empty;

        return new InjectionEvent
        {
            EventId = Interlocked.Increment(ref _nextEventId),
            TimestampUtc = timestampUtc,
            ProcessId = sourcePid,
            ProcessImage = sourceImage,
            Technique = technique,
            SourceProcessId = sourcePid,
            SourceProcessImage = sourceImage,
            TargetProcessId = targetPid,
            TargetProcessImage = targetImage,
            InjectedModulePath = modulePath,
            RemoteThreadStartAddress = threadStartAddr,
            Details = details,
            Summary = $"[{technique}] {sourceImage} → {targetImage}"
                      + (modulePath != null ? $" ({Path.GetFileName(modulePath)})" : "")
        };
    }

    private void EmitInjection(InjectionEvent evt)
    {
        _logger.Info("InjectionDetector",
            $"Injection detected: {evt.Technique}, Source PID {evt.SourceProcessId} → Target PID {evt.TargetProcessId}, Module: {evt.InjectedModulePath ?? "N/A"}");
        InjectionDetected?.Invoke(evt);
    }

    private static bool IsDllOrExecutable(string path)
    {
        var ext = Path.GetExtension(path);
        return ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".sys", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".drv", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".ocx", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSystemModule(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return true;

        var normalized = path.Replace('/', '\\');

        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(winDir) && normalized.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
            return true;

        if (normalized.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase))
            return true;
        if (normalized.StartsWith(@"C:\Program Files\dotnet\", StringComparison.OrdinalIgnoreCase))
            return true;
        if (normalized.Contains(@"\Microsoft.NET\", StringComparison.OrdinalIgnoreCase))
            return true;
        if (normalized.Contains(@"\WinSxS\", StringComparison.OrdinalIgnoreCase))
            return true;
        if (normalized.Contains(@"\dotnet\shared\", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    private static string TryGetProcessImage(int pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            return proc.MainModule?.FileName ?? proc.ProcessName;
        }
        catch
        {
            return $"PID:{pid}";
        }
    }

    private void CleanupStaleRecords()
    {
        var cutoff = DateTime.UtcNow - CorrelationWindow * 3;

        foreach (var kvp in _recentDllWrites)
        {
            if (kvp.Value.TimestampUtc < cutoff)
                _recentDllWrites.TryRemove(kvp.Key, out _);
        }

        foreach (var kvp in _suspiciousThreads)
        {
            if (kvp.Value.TimestampUtc < cutoff)
                _suspiciousThreads.TryRemove(kvp.Key, out _);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cleanupTimer.Dispose();
    }

    private record DllWriteRecord
    {
        public int WriterPid { get; init; }
        public string FilePath { get; init; } = string.Empty;
        public DateTime TimestampUtc { get; init; }
    }

    private record RemoteThreadRecord
    {
        public int TargetPid { get; init; }
        public ulong StartAddress { get; init; }
        public DateTime TimestampUtc { get; init; }
    }
}
