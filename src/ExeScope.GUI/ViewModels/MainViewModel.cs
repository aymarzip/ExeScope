using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using Avalonia.Threading;
using EventModel = ExeScope.Contracts.Events;
using GrpcModel = ExeScope.Contracts.Grpc;
using ExeScope.Contracts.Mapping;
using ExeScope.Contracts.Security;
using ExeScope.Contracts.Threat;
using ExeScope.Core.Models;
using ExeScope.Core.Utilities;
using ExeScope.GUI.Common;
using ExeScope.GUI.Models;
using ExeScope.GUI.Services;

namespace ExeScope.GUI.ViewModels;

public class MainViewModel : ViewModelBase
{
    private readonly AgentClientService _agentService = new();
    private readonly DispatcherTimer _batchTimer;
    private readonly DispatcherTimer _threatUpdateTimer;

    private readonly ConcurrentQueue<GrpcModel.TelemetryEnvelope> _incomingQueue = new();
    private readonly List<EventModel.ProcessStartedEvent> _accumulatedProcesses = new();
    private readonly List<EventModel.DllInjectedEvent> _accumulatedInjections = new();
    private readonly List<EventModel.RegistryModifiedEvent> _accumulatedRegistry = new();
    private readonly List<EventModel.NetworkConnectionEvent> _accumulatedNetwork = new();
    private readonly List<EventModel.FileModifiedEvent> _accumulatedFiles = new();
    private readonly Dictionary<int, ProcessTreeItem> _processMap = new();

    private string _targetExePath = string.Empty;
    private string _targetSha256 = string.Empty;
    private string _signatureStatus = "Unknown";
    private string _outputDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "ExeScope_Results");
    private string _agentAddress = "127.0.0.1:50051";
    private string _authToken = string.Empty;
    private string _agentStatusText = "Disconnected";
    private bool _isAgentConnected;
    private bool _isElevated;

    private AnalysisSessionState _state = AnalysisSessionState.Ready;
    private string _statusMessage = "Ready for analysis";
    private string _searchText = string.Empty;
    private int? _searchPid;
    private string _selectedCategory = "All";

    // Threat Verdict
    private int _threatScore = 0;
    private ThreatLevel _threatLevel = ThreatLevel.Clean;
    private string _threatSummaryText = "Clean / Baseline Behavior. Awaiting session telemetry.";
    private string _threatHexColor = "#8c9ba5";

    // Statistics
    private long _totalEventsCount;
    private long _droppedEventsCount;
    private long _injectionsCount;
    private long _filesCount;
    private long _registryCount;
    private long _networkCount;

    // Collections
    public BulkObservableCollection<GrpcModel.TelemetryEnvelope> AllEvents { get; } = new(50_000);
    public BulkObservableCollection<GrpcModel.TelemetryEnvelope> DisplayEvents { get; } = new(50_000);
    public ObservableCollection<ProcessTreeItem> ProcessTreeNodes { get; } = new();
    public ObservableCollection<IndicatorOfCompromise> ThreatIndicators { get; } = new();

    // Hotkey and Action Commands
    public RelayCommand SelectTargetCommand { get; }
    public RelayCommand StartSessionCommand { get; }
    public RelayCommand StopSessionCommand { get; }
    public RelayCommand ExportReportCommand { get; }
    public RelayCommand ConnectAgentCommand { get; }
    public RelayCommand OpenResultsFolderCommand { get; }
    public RelayCommand CopyHashCommand { get; }
    public RelayCommand CopyPathCommand { get; }
    public RelayCommand CopyIocCommand { get; }
    public RelayCommand ClearEventsCommand { get; }

    public string TargetExePath
    {
        get => _targetExePath;
        set
        {
            if (SetProperty(ref _targetExePath, value))
            {
                InspectTarget();
            }
        }
    }

    public string TargetSha256
    {
        get => _targetSha256;
        private set => SetProperty(ref _targetSha256, value);
    }

    public string SignatureStatus
    {
        get => _signatureStatus;
        private set => SetProperty(ref _signatureStatus, value);
    }

    public string OutputDirectory
    {
        get => _outputDirectory;
        set => SetProperty(ref _outputDirectory, value);
    }

    public string AgentAddress
    {
        get => _agentAddress;
        set => SetProperty(ref _agentAddress, value);
    }

    public string AuthToken
    {
        get => _authToken;
        set => SetProperty(ref _authToken, value);
    }

    public string AgentStatusText
    {
        get => _agentStatusText;
        private set => SetProperty(ref _agentStatusText, value);
    }

    public bool IsAgentConnected
    {
        get => _isAgentConnected;
        private set
        {
            if (SetProperty(ref _isAgentConnected, value))
            {
                OnPropertyChanged(nameof(CanStartSession));
                StartSessionCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsElevated
    {
        get => _isElevated;
        private set => SetProperty(ref _isElevated, value);
    }

    public AnalysisSessionState State
    {
        get => _state;
        private set
        {
            if (SetProperty(ref _state, value))
            {
                OnPropertyChanged(nameof(CanStartSession));
                OnPropertyChanged(nameof(CanStopSession));
                OnPropertyChanged(nameof(CanExportReport));
                StartSessionCommand.RaiseCanExecuteChanged();
                StopSessionCommand.RaiseCanExecuteChanged();
                ExportReportCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                _searchPid = int.TryParse(value?.Trim(), out int pid) ? pid : null;
                ApplyFilter();
            }
        }
    }

    public string SelectedCategory
    {
        get => _selectedCategory;
        set
        {
            if (SetProperty(ref _selectedCategory, value))
            {
                ApplyFilter();
            }
        }
    }

    public int ThreatScore
    {
        get => _threatScore;
        private set => SetProperty(ref _threatScore, value);
    }

    public ThreatLevel ThreatLevel
    {
        get => _threatLevel;
        private set => SetProperty(ref _threatLevel, value);
    }

    public string ThreatSummaryText
    {
        get => _threatSummaryText;
        private set => SetProperty(ref _threatSummaryText, value);
    }

    public string ThreatHexColor
    {
        get => _threatHexColor;
        private set => SetProperty(ref _threatHexColor, value);
    }

    public long TotalEventsCount
    {
        get => _totalEventsCount;
        private set => SetProperty(ref _totalEventsCount, value);
    }

    public long DroppedEventsCount
    {
        get => _droppedEventsCount;
        private set => SetProperty(ref _droppedEventsCount, value);
    }

    public long InjectionsCount
    {
        get => _injectionsCount;
        private set => SetProperty(ref _injectionsCount, value);
    }

    public long FilesCount
    {
        get => _filesCount;
        private set => SetProperty(ref _filesCount, value);
    }

    public long RegistryCount
    {
        get => _registryCount;
        private set => SetProperty(ref _registryCount, value);
    }

    public long NetworkCount
    {
        get => _networkCount;
        private set => SetProperty(ref _networkCount, value);
    }

    public bool CanStartSession => (State == AnalysisSessionState.Ready || State == AnalysisSessionState.Completed || State == AnalysisSessionState.Error)
                                   && !string.IsNullOrWhiteSpace(TargetExePath);

    public bool CanStopSession => State == AnalysisSessionState.WaitingForLaunch || State == AnalysisSessionState.Recording;

    public bool CanExportReport => AllEvents.Count > 0 || State == AnalysisSessionState.Completed;

    public MainViewModel()
    {
        _authToken = IpcAuthToken.LoadOrCreateToken();

        SelectTargetCommand = new RelayCommand(ExecuteSelectTarget);
        StartSessionCommand = new RelayCommand(async () => await ExecuteStartSessionAsync(), () => CanStartSession);
        StopSessionCommand = new RelayCommand(async () => await ExecuteStopSessionAsync(), () => CanStopSession);
        ExportReportCommand = new RelayCommand(async () => await ExecuteExportReportAsync(), () => CanExportReport);
        ConnectAgentCommand = new RelayCommand(async () => await ExecuteConnectAgentAsync());
        OpenResultsFolderCommand = new RelayCommand(ExecuteOpenResultsFolder);
        CopyHashCommand = new RelayCommand(ExecuteCopyHash);
        CopyPathCommand = new RelayCommand(ExecuteCopyPath);
        CopyIocCommand = new RelayCommand(ExecuteCopyIoc);
        ClearEventsCommand = new RelayCommand(ExecuteClearEvents);

        _agentService.ConnectionStateChanged += (connected, status) =>
        {
            Dispatcher.UIThread.Post(() =>
            {
                IsAgentConnected = connected;
                AgentStatusText = status;
            });
        };

        _agentService.EventReceived += envelope =>
        {
            _incomingQueue.Enqueue(envelope);
        };

        // UI Dispatcher batch timer (50ms interval = 20 batches/sec throttled updates for zero UI lag)
        _batchTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(50)
        };
        _batchTimer.Tick += OnBatchTimerTick;
        _batchTimer.Start();

        // Threat evaluation background periodic updater (every 250ms)
        _threatUpdateTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(250)
        };
        _threatUpdateTimer.Tick += OnThreatUpdateTimerTick;
        _threatUpdateTimer.Start();

        // Try automatic local connection on startup
        _ = AutoConnectLocalAsync();
    }

    private async Task AutoConnectLocalAsync()
    {
        try
        {
            await _agentService.ConnectAsync(AgentAddress, AuthToken);
        }
        catch
        {
            // Agent might start later
        }
    }

    private void InspectTarget()
    {
        if (File.Exists(_targetExePath))
        {
            try
            {
                TargetSha256 = HashHelper.ComputeSha256(_targetExePath);
                var info = AuthenticodeHelper.InspectExecutable(_targetExePath);
                SignatureStatus = info.SignatureStatus ?? (info.IsSigned ? "Valid" : "Unsigned");
            }
            catch (Exception ex)
            {
                TargetSha256 = "Error computing hash";
                SignatureStatus = ex.Message;
            }
        }
        else
        {
            TargetSha256 = string.Empty;
            SignatureStatus = "File not found";
        }

        StartSessionCommand.RaiseCanExecuteChanged();
    }

    private void OnBatchTimerTick(object? sender, EventArgs e)
    {
        if (_incomingQueue.IsEmpty) return;

        var batch = new List<GrpcModel.TelemetryEnvelope>(2000);
        while (batch.Count < 2000 && _incomingQueue.TryDequeue(out var env))
        {
            batch.Add(env);

            // Accumulate typed events for threat engine and process tree
            switch (env.PayloadCase)
            {
                case GrpcModel.TelemetryEnvelope.PayloadOneofCase.ProcessStarted:
                    var proc = ContractMapper.FromEnvelopeToProcess(env);
                    if (proc != null)
                    {
                        _accumulatedProcesses.Add(proc);
                        UpdateProcessTree(proc);
                    }
                    break;

                case GrpcModel.TelemetryEnvelope.PayloadOneofCase.ProcessTerminated:
                    UpdateProcessTermination(env.ProcessTerminated);
                    break;

                case GrpcModel.TelemetryEnvelope.PayloadOneofCase.DllInjected:
                    var inj = ContractMapper.FromEnvelopeToInjection(env);
                    if (inj != null)
                    {
                        _accumulatedInjections.Add(inj);
                        InjectionsCount++;
                        MarkInjectedProcess(inj);
                    }
                    break;

                case GrpcModel.TelemetryEnvelope.PayloadOneofCase.FileModified:
                    var f = ContractMapper.FromEnvelopeToFile(env);
                    if (f != null)
                    {
                        _accumulatedFiles.Add(f);
                        FilesCount++;
                    }
                    break;

                case GrpcModel.TelemetryEnvelope.PayloadOneofCase.RegistryModified:
                    var r = ContractMapper.FromEnvelopeToRegistry(env);
                    if (r != null)
                    {
                        _accumulatedRegistry.Add(r);
                        RegistryCount++;
                    }
                    break;

                case GrpcModel.TelemetryEnvelope.PayloadOneofCase.NetworkConnection:
                    var n = ContractMapper.FromEnvelopeToNetwork(env);
                    if (n != null)
                    {
                        _accumulatedNetwork.Add(n);
                        NetworkCount++;
                    }
                    break;
            }
        }

        AllEvents.AddRange(batch);
        TotalEventsCount = AllEvents.Count;

        // Apply instant filter
        if (string.IsNullOrWhiteSpace(_searchText) && _selectedCategory == "All")
        {
            DisplayEvents.AddRange(batch);
        }
        else
        {
            var filtered = batch.Where(MatchesFilter).ToList();
            if (filtered.Count > 0)
            {
                DisplayEvents.AddRange(filtered);
            }
        }

        if (State == AnalysisSessionState.WaitingForLaunch && _accumulatedProcesses.Count > 0)
        {
            State = AnalysisSessionState.Recording;
            StatusMessage = $"Recording telemetry. Active PID: {_accumulatedProcesses[0].ProcessId}";
        }
    }

    private void UpdateProcessTree(EventModel.ProcessStartedEvent proc)
    {
        var item = new ProcessTreeItem
        {
            ProcessId = proc.ProcessId,
            ParentProcessId = proc.ParentProcessId,
            ImageName = proc.ProcessImage,
            ImagePath = proc.ImagePath ?? proc.ProcessImage,
            CommandLine = proc.CommandLine ?? string.Empty,
            StartTimeUtc = proc.TimestampUtc
        };

        _processMap[proc.ProcessId] = item;

        if (_processMap.TryGetValue(proc.ParentProcessId, out var parent))
        {
            parent.Children.Add(item);
        }
        else
        {
            ProcessTreeNodes.Add(item);
        }
    }

    private void UpdateProcessTermination(GrpcModel.ProcessTerminatedEvent? term)
    {
        if (term != null && _processMap.TryGetValue(term.ProcessId, out var node))
        {
            node.ExitCode = term.ExitCode;
            node.ExitTimeUtc = DateTime.TryParse(term.TimestampUtc, out var dt) ? dt : DateTime.UtcNow;
        }
    }

    private void MarkInjectedProcess(EventModel.DllInjectedEvent inj)
    {
        if (_processMap.TryGetValue(inj.TargetProcessId, out var target))
        {
            target.IsInjectionTarget = true;
            target.InjectedByPid = inj.SourceProcessId;
            if (!string.IsNullOrEmpty(inj.InjectedModulePath))
            {
                target.AddInjectedModule(inj.InjectedModulePath);
            }
        }
    }

    private void OnThreatUpdateTimerTick(object? sender, EventArgs e)
    {
        if (_accumulatedProcesses.Count == 0 && _accumulatedInjections.Count == 0 && _accumulatedFiles.Count == 0)
            return;

        bool isUnsigned = SignatureStatus.Contains("Unsigned", StringComparison.OrdinalIgnoreCase);

        var summary = ThreatVerdictEvaluator.Evaluate(
            _accumulatedProcesses,
            _accumulatedInjections,
            _accumulatedRegistry,
            _accumulatedNetwork,
            _accumulatedFiles,
            isUnsigned: isUnsigned);

        ThreatScore = summary.Score;
        ThreatLevel = summary.Level;
        ThreatSummaryText = summary.SummaryText;
        ThreatHexColor = summary.HexColor;

        ThreatIndicators.Clear();
        foreach (var ioc in summary.Indicators)
        {
            ThreatIndicators.Add(ioc);
        }
    }

    private bool MatchesFilter(GrpcModel.TelemetryEnvelope env)
    {
        if (_selectedCategory != "All")
        {
            if (!string.Equals(env.Category, _selectedCategory, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        if (string.IsNullOrWhiteSpace(_searchText))
            return true;

        if (_searchPid.HasValue && env.ProcessId == _searchPid.Value)
            return true;

        string query = _searchText.Trim();
        return env.ProcessImage.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               env.Summary.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               env.Category.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               (query.Length > 0 && char.IsDigit(query[0]) && env.ProcessId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase));
    }

    private void ApplyFilter()
    {
        DisplayEvents.Clear();
        var matched = AllEvents.Where(MatchesFilter).ToList();
        DisplayEvents.AddRange(matched);
    }

    private void ExecuteSelectTarget()
    {
        // Dialog triggered by View event
    }

    private async Task ExecuteStartSessionAsync()
    {
        if (!IsAgentConnected)
        {
            bool ok = await _agentService.ConnectAsync(AgentAddress, AuthToken);
            if (!ok)
            {
                StatusMessage = "Cannot connect to ExeScope Agent. Please ensure Agent is running.";
                return;
            }
        }

        try
        {
            ExecuteClearEvents();

            var resp = await _agentService.StartSessionAsync(TargetExePath, OutputDirectory);
            if (resp.Success)
            {
                State = AnalysisSessionState.WaitingForLaunch;
                StatusMessage = $"Awaiting target launch: {Path.GetFileName(TargetExePath)}...";
            }
            else
            {
                StatusMessage = $"Failed to start session: {resp.Message}";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
    }

    private async Task ExecuteStopSessionAsync()
    {
        try
        {
            var resp = await _agentService.StopSessionAsync("User initiated stop");
            State = AnalysisSessionState.Completed;
            StatusMessage = $"Session finished. Report ready: {resp.ReportPath}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Stop error: {ex.Message}";
        }
    }

    private async Task ExecuteExportReportAsync()
    {
        try
        {
            string outDir = string.IsNullOrWhiteSpace(OutputDirectory) ? Directory.GetCurrentDirectory() : OutputDirectory;
            Directory.CreateDirectory(outDir);
            string dest = Path.Combine(outDir, $"exescope_report_{DateTime.UtcNow:yyyyMMdd_HHmmss}.html");

            var resp = await _agentService.ExportReportAsync(dest);
            if (resp.Success)
            {
                StatusMessage = $"Report exported successfully: {resp.ReportPath}";
            }
            else
            {
                StatusMessage = $"Export error: {resp.ErrorMessage}";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Export exception: {ex.Message}";
        }
    }

    private async Task ExecuteConnectAgentAsync()
    {
        StatusMessage = $"Connecting to {AgentAddress}...";
        bool ok = await _agentService.ConnectAsync(AgentAddress, AuthToken);
        StatusMessage = ok ? "Agent connected." : "Agent connection failed.";
    }

    private void ExecuteOpenResultsFolder()
    {
        if (Directory.Exists(OutputDirectory))
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = OutputDirectory,
                    UseShellExecute = true
                });
            }
            catch
            {
                // Ignore
            }
        }
    }

    private void ExecuteCopyHash()
    {
        if (!string.IsNullOrEmpty(TargetSha256))
        {
            SetClipboardText(TargetSha256);
        }
    }

    private void ExecuteCopyPath()
    {
        if (!string.IsNullOrEmpty(TargetExePath))
        {
            SetClipboardText(TargetExePath);
        }
    }

    private void ExecuteCopyIoc(object? param)
    {
        if (param is IndicatorOfCompromise ioc)
        {
            string text = $"[{ioc.Severity}] {ioc.MitreTechniqueId} {ioc.Title}: {ioc.Description} (Evidence: {ioc.Evidence})";
            SetClipboardText(text);
        }
        else if (ThreatIndicators.Count > 0)
        {
            string text = string.Join(Environment.NewLine, ThreatIndicators.Select(i => $"[{i.Severity}] {i.MitreTechniqueId} {i.Title}: {i.Description}"));
            SetClipboardText(text);
        }
    }

    private void ExecuteClearEvents()
    {
        AllEvents.Clear();
        DisplayEvents.Clear();
        ProcessTreeNodes.Clear();
        ThreatIndicators.Clear();
        _accumulatedProcesses.Clear();
        _accumulatedInjections.Clear();
        _accumulatedRegistry.Clear();
        _accumulatedNetwork.Clear();
        _accumulatedFiles.Clear();
        _processMap.Clear();

        TotalEventsCount = 0;
        InjectionsCount = 0;
        FilesCount = 0;
        RegistryCount = 0;
        NetworkCount = 0;
        ThreatScore = 0;
        ThreatLevel = ThreatLevel.Clean;
        ThreatSummaryText = "Clean / Baseline Behavior. Awaiting session telemetry.";
        ThreatHexColor = "#8c9ba5";
    }

    private static void SetClipboardText(string text)
    {
        try
        {
            if (Avalonia.Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop &&
                desktop.MainWindow?.Clipboard != null)
            {
                desktop.MainWindow.Clipboard.SetTextAsync(text);
            }
        }
        catch
        {
            // Ignore clipboard errors
        }
    }
}
