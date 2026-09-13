using System.Diagnostics;
using System.Security.Principal;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Core.Utilities;
using ExeScope.Engine.Collectors;
using ExeScope.Engine.Detection;
using ExeScope.Engine.Network;
using ExeScope.Engine.Reporting;
using ExeScope.Engine.Storage;
using ExeScope.Engine.Tracking;

namespace ExeScope.Engine.Session;

public class AnalysisSessionManager : IAsyncDisposable
{
    private readonly IDiagnosticLogger _logger;
    private readonly object _stateLock = new();

    private AnalysisSessionState _state = AnalysisSessionState.Ready;
    private SessionConfig _config = new();
    private TargetExeInfo? _targetExe;
    private SessionMetadata? _currentMetadata;
    private ProcessCorrelationEngine? _correlationEngine;
    private ISessionStorage? _storage;
    private FileArtifactCollector? _artifactCollector;
    private PcapngWriter? _pcapWriter;
    private RawSocketCapture? _rawSocketCapture;
    private InjectionDetector? _injectionDetector;

    private readonly List<IEventCollector> _collectors = new();
    private readonly RollingBuffer<AnalysisEvent> _inMemoryEvents = new(50_000);
    private readonly RollingBuffer<ArtifactRecord> _inMemoryArtifacts = new(10_000);

    private CancellationTokenSource? _sessionCts;
    private bool _isElevated;

    public AnalysisSessionState State
    {
        get => _state;
        private set
        {
            if (_state != value)
            {
                _state = value;
                StateChanged?.Invoke(_state);
            }
        }
    }

    public TargetExeInfo? TargetExe => _targetExe;
    public SessionConfig Config => _config;
    public SessionMetadata? CurrentMetadata => _currentMetadata;
    public string? CurrentSessionDirectory => _storage?.SessionDirectory;
    public long TotalEventsRecorded => _storage?.TotalEventsWritten ?? _inMemoryEvents.TotalAdded;
    public long TotalEventsDropped => _storage?.TotalEventsDropped ?? 0;
    public long SessionSizeBytes => _storage?.CalculateSessionSizeBytes() ?? 0;
    public bool IsElevated => _isElevated;

    public event Action<AnalysisSessionState>? StateChanged;
    public event Action<AnalysisEvent>? EventRecorded;
    public event Action<ArtifactRecord>? ArtifactSaved;
    public event Action<ProcessNode>? ProcessTreeUpdated;
    public event Action<string>? TargetIntegrityWarning;
    public event Action<TrackedProcess>? RepeatedLaunchDetected;

    public AnalysisSessionManager(IDiagnosticLogger logger)
    {
        _logger = logger;
        CheckElevation();
    }

    private void CheckElevation()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(id);
            _isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            _isElevated = false;
        }
    }

    public void SetTargetExe(string exePath)
    {
        if (State == AnalysisSessionState.WaitingForLaunch || State == AnalysisSessionState.Recording)
            throw new InvalidOperationException("Cannot change target executable while a session is active.");

        _targetExe = AuthenticodeHelper.InspectExecutable(exePath);
        _logger.Info("SessionManager", $"Target selected: {_targetExe.FileName} (SHA-256: {_targetExe.Sha256}, Signed: {_targetExe.IsSigned})");
    }

    public void UpdateConfig(SessionConfig newConfig)
    {
        if (State == AnalysisSessionState.WaitingForLaunch || State == AnalysisSessionState.Recording)
            throw new InvalidOperationException("Cannot change configuration while a session is active.");

        _config = newConfig;
    }

    public async Task StartWaitingAsync()
    {
        lock (_stateLock)
        {
            if (State != AnalysisSessionState.Ready && State != AnalysisSessionState.Completed && State != AnalysisSessionState.Error)
                throw new InvalidOperationException($"Cannot start waiting from state: {State}");

            if (_targetExe == null || !File.Exists(_targetExe.OriginalPath))
                throw new InvalidOperationException("Valid target executable must be selected before waiting for launch.");

            if (string.IsNullOrWhiteSpace(_config.OutputDirectory))
                throw new InvalidOperationException("Output directory must be configured.");

            State = AnalysisSessionState.WaitingForLaunch;
        }

        _logger.Info("SessionManager", "Pre-activating telemetry sources before target execution.");
        _sessionCts = new CancellationTokenSource();

        _correlationEngine = new ProcessCorrelationEngine(_targetExe, _logger)
        {
            TrackInjectionTargetEvents = _config.TrackInjectionTargetEvents
        };
        _correlationEngine.OnProcessStarted += HandleProcessStarted;
        _correlationEngine.OnProcessTerminated += HandleProcessTerminated;
        _correlationEngine.OnRepeatedLaunchDetected += HandleRepeatedLaunchDetected;
        _correlationEngine.OnAllTrackedProcessesExited += HandleAllTrackedProcessesExited;

        _inMemoryEvents.Clear();
        _inMemoryArtifacts.Clear();
        if (_storage != null)
        {
            await _storage.DisposeAsync().ConfigureAwait(false);
            _storage = null;
        }

        _collectors.Clear();

        if (_config.EnableInjectionTracking)
        {
            _injectionDetector = new InjectionDetector(_correlationEngine, _logger, _config.TrackInjectionTargetEvents);
            _injectionDetector.InjectionDetected += OnInjectionDetected;
        }

        var etwCollector = new EtwEventCollector(_correlationEngine, _logger,
            onFileModifiedForArtifact: (path, pid, image) =>
            {
                _artifactCollector?.QueueFile(path, pid, image);
            },
            injectionDetector: _injectionDetector);
        _collectors.Add(etwCollector);

        var processWatcher = new PollingProcessWatcher(_correlationEngine, _logger);
        _collectors.Add(processWatcher);

        var netTracker = new NetworkConnectionTracker(_correlationEngine, _logger);
        _collectors.Add(netTracker);

        foreach (var collector in _collectors)
        {
            collector.EventEmitted += OnCollectorEventEmitted;
            try
            {
                await collector.StartAsync(_sessionCts.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.Error("SessionManager", $"Failed to start collector {collector.Name}", ex);
            }
        }

        _logger.Info("SessionManager", "Monitoring ready. Awaiting process launch.");
    }

    private void OnInjectionDetected(InjectionEvent evt)
    {
        _storage?.EnqueueEvent(evt);
        _inMemoryEvents.Add(evt);
        EventRecorded?.Invoke(evt);

        if (!string.IsNullOrEmpty(evt.InjectedModulePath))
        {
            _artifactCollector?.QueueFile(evt.InjectedModulePath, evt.SourceProcessId, evt.SourceProcessImage ?? "", bypassDirectoryFilter: true);
        }

        var tree = _correlationEngine?.BuildProcessTree();
        if (tree != null) ProcessTreeUpdated?.Invoke(tree);
    }

    private void HandleProcessStarted(TrackedProcess proc)
    {
        if (proc.IsRoot)
        {
            lock (_stateLock)
            {
                if (State == AnalysisSessionState.WaitingForLaunch)
                {
                    OnRootProcessLaunchDetected(proc);
                }
            }
        }

        ProcessTreeUpdated?.Invoke(_correlationEngine?.BuildProcessTree()!);
    }

    private void OnRootProcessLaunchDetected(TrackedProcess root)
    {
        State = AnalysisSessionState.Recording;
        var nowUtc = DateTime.UtcNow;

        _logger.Info("SessionManager", $"Target process detected, entering Recording state. PID: {root.ProcessId}");

        bool targetModified = false;
        string? modifiedWarning = null;
        try
        {
            var currentFile = new FileInfo(_targetExe!.OriginalPath);
            if (currentFile.Exists)
            {
                string currentHash = HashHelper.ComputeSha256(_targetExe.OriginalPath);
                if (!string.Equals(currentHash, _targetExe.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    targetModified = true;
                    modifiedWarning = $"Хеш файла изменился после выбора! Исходный: {_targetExe.Sha256[..8]}..., Текущий: {currentHash[..8]}...";
                    _logger.Warn("SessionManager", $"Target integrity changed: {modifiedWarning}");
                    TargetIntegrityWarning?.Invoke(modifiedWarning);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error("SessionManager", "Error verifying target integrity on launch", ex);
        }

        _storage = new FileSessionStorage(_config.OutputDirectory, root.ProcessId, _logger, _config.MaxChannelCapacity);

        if (_config.EnableArtifactSaving)
        {
            _artifactCollector = new FileArtifactCollector(_config, _storage.SessionDirectory, _logger);
            _artifactCollector.ArtifactPreserved += record =>
            {
                _inMemoryArtifacts.Add(record);
                ArtifactSaved?.Invoke(record);
            };
            _artifactCollector.Start();
        }

        if (_config.EnablePacketCapture)
        {
            try
            {
                string pcapPath = Path.Combine(_storage.SessionDirectory, "network.pcapng");
                _pcapWriter = new PcapngWriter(pcapPath);
                _rawSocketCapture = new RawSocketCapture(_correlationEngine!, _pcapWriter, _logger);
                _rawSocketCapture.Start();
            }
            catch (Exception ex)
            {
                _logger.Error("SessionManager", "Failed to start PCAPNG packet capture", ex);
            }
        }

        _currentMetadata = new SessionMetadata
        {
            SessionId = Path.GetFileName(_storage.SessionDirectory),
            SessionDirectory = _storage.SessionDirectory,
            TargetExe = _targetExe,
            Config = _config,
            SessionCreatedUtc = nowUtc,
            TargetLaunchDetectedUtc = root.StartTimeUtc,
            RootProcessId = root.ProcessId,
            IsElevated = _isElevated,
            TargetModifiedAfterSelection = targetModified,
            TargetModifiedWarning = modifiedWarning
        };

        foreach (var c in _collectors)
        {
            if (c.IsSupported)
                _currentMetadata.ActiveCapabilities.Add($"{c.Name}: {c.StatusDescription}");
            else
                _currentMetadata.SourceLimitations.Add($"{c.Name}: {c.StatusDescription}");
        }

        _storage.SaveSessionMetadata(_currentMetadata);
    }

    private void HandleProcessTerminated(TrackedProcess proc)
    {
        ProcessTreeUpdated?.Invoke(_correlationEngine?.BuildProcessTree()!);
    }

    private void HandleAllTrackedProcessesExited()
    {
        if (_config.AutoCompleteOnAllProcessesExit && State == AnalysisSessionState.Recording)
        {
            _logger.Info("SessionManager", "All tracked processes exited. Auto-completing session.");
            _ = StopRecordingAsync("All tracked processes terminated");
        }
    }

    private void HandleRepeatedLaunchDetected(TrackedProcess repeated)
    {
        _logger.Warn("SessionManager", $"Repeated launch detected (PID: {repeated.ProcessId}). Isolating into new session.");
        RepeatedLaunchDetected?.Invoke(repeated);

        Task.Run(async () =>
        {
            try
            {
                if (State == AnalysisSessionState.Recording)
                {
                    await StopRecordingAsync("Session completed due to target re-launch").ConfigureAwait(false);
                }

                await Task.Delay(200).ConfigureAwait(false);

                await StartWaitingAsync().ConfigureAwait(false);

                _correlationEngine?.TryRegisterProcess(
                    repeated.ProcessId,
                    repeated.ParentProcessId,
                    repeated.ImagePath,
                    repeated.CommandLine,
                    repeated.StartTimeUtc,
                    out _);
            }
            catch (Exception ex)
            {
                _logger.Error("SessionManager", "Error transitioning to new session on repeated launch", ex);
            }
        });
    }

    private void OnCollectorEventEmitted(AnalysisEvent evt)
    {
        if (evt is NetworkEvent ne)
        {
            if (ne.LocalPort > 0) _rawSocketCapture?.RegisterTrackedPort(ne.LocalPort);
            if (ne.RemotePort > 0) _rawSocketCapture?.RegisterTrackedPort(ne.RemotePort);
        }

        _storage?.EnqueueEvent(evt);
        _inMemoryEvents.Add(evt);
        EventRecorded?.Invoke(evt);
    }

    public async Task StopRecordingAsync(string reason = "User stopped recording")
    {
        lock (_stateLock)
        {
            if (State != AnalysisSessionState.Recording && State != AnalysisSessionState.WaitingForLaunch)
                return;

            State = AnalysisSessionState.Completed;
        }

        _logger.Info("SessionManager", $"Stopping analysis session: {reason}");

        try
        {
            _sessionCts?.Cancel();

            foreach (var c in _collectors)
            {
                try
                {
                    await c.StopAsync().ConfigureAwait(false);
                    if (c is IAsyncDisposable asyncDisp)
                    {
                        await asyncDisp.DisposeAsync().ConfigureAwait(false);
                    }
                    else if (c is IDisposable disp)
                    {
                        disp.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error("SessionManager", $"Error stopping collector {c.Name}", ex);
                }
            }

            if (_rawSocketCapture != null)
            {
                await _rawSocketCapture.DisposeAsync().ConfigureAwait(false);
                _rawSocketCapture = null;
            }
            _pcapWriter?.Dispose();
            _pcapWriter = null;

            if (_artifactCollector != null)
            {
                await _artifactCollector.DisposeAsync().ConfigureAwait(false);
                _artifactCollector = null;
            }

            _injectionDetector?.Dispose();
            _injectionDetector = null;

            if (_currentMetadata != null)
            {
                _currentMetadata.RecordingEndedUtc = DateTime.UtcNow;
                _currentMetadata.ExitReason = reason;
                _currentMetadata.TotalEventsRecorded = _storage?.TotalEventsWritten ?? _inMemoryEvents.TotalAdded;
                _currentMetadata.TotalEventsDropped = _storage?.TotalEventsDropped ?? 0;
                _currentMetadata.TotalArtifactsSaved = _artifactCollector?.TotalSaved ?? 0;
                _currentMetadata.TotalArtifactsSkipped = _artifactCollector?.TotalSkipped ?? 0;
                _currentMetadata.TotalArtifactBytesWritten = _artifactCollector?.TotalBytesWritten ?? 0;

                _storage?.SaveSessionMetadata(_currentMetadata);
            }

            var tree = _correlationEngine?.BuildProcessTree();
            _storage?.SaveProcessTree(tree);

            await GenerateReportAsync().ConfigureAwait(false);

            if (_storage != null)
            {
                await _storage.DisposeAsync().ConfigureAwait(false);
            }

            _logger.Info("SessionManager", $"Session finalized. Directory: {CurrentSessionDirectory}");
        }
        catch (Exception ex)
        {
            State = AnalysisSessionState.Error;
            _logger.Error("SessionManager", "Error finalizing analysis session", ex);
        }
    }

    public async Task GenerateReportAsync()
    {
        if (_storage == null || _currentMetadata == null)
            return;

        try
        {
            var tree = _correlationEngine?.BuildProcessTree();
            var eventsList = _inMemoryEvents.ToList();
            var artifactsList = _inMemoryArtifacts.ToList();
            var diagnosticsList = _logger.GetEntries();

            string html = HtmlReportGenerator.GenerateReport(
                _currentMetadata,
                tree,
                eventsList,
                artifactsList,
                diagnosticsList);

            string reportPath = Path.Combine(_storage.SessionDirectory, "report.html");
            await File.WriteAllTextAsync(reportPath, html).ConfigureAwait(false);
            _logger.Info("SessionManager", $"Report generated: {reportPath}");
        }
        catch (Exception ex)
        {
            _logger.Error("SessionManager", "Failed to generate HTML report", ex);
        }
    }

    public void OpenResultsFolder()
    {
        string? dir = CurrentSessionDirectory;
        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true
            });
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopRecordingAsync("Disposed").ConfigureAwait(false);
        if (_storage != null)
        {
            await _storage.DisposeAsync().ConfigureAwait(false);
        }
    }
}
