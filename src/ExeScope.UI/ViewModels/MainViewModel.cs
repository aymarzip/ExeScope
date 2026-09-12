using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Core.Utilities;
using ExeScope.Engine.Network;
using ExeScope.Engine.Session;
using ExeScope.UI.Common;
using Microsoft.Win32;

namespace ExeScope.UI.ViewModels;

public class MainViewModel : ViewModelBase
{
    private readonly AnalysisSessionManager _sessionManager;
    private readonly IDiagnosticLogger _logger;
    private readonly Dispatcher _dispatcher;

    private string _targetExePath = string.Empty;
    private string _outputDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "ExeScope_Results");
    private TargetExeInfo? _targetExeInfo;
    private AnalysisSessionState _state = AnalysisSessionState.Ready;

    private string _searchText = string.Empty;
    private string _processFilter = string.Empty;
    private string _pathFilter = string.Empty;
    private string _timeFilter = string.Empty;
    private string _selectedCategoryOption = "Все категории";
    private string? _targetIntegrityWarning;

    private string _cachedSearchText = string.Empty;
    private string _cachedProcessFilter = string.Empty;
    private int? _cachedProcessIdFilter;
    private string _cachedPathFilter = string.Empty;
    private string _cachedTimeFilter = string.Empty;
    private EventCategory? _cachedCategoryFilter;

    private bool _enableArtifactSaving = true;
    private int _maxArtifactSizeMb = 10;
    private int _maxTotalStorageMb = 100;
    private bool _enablePacketCapture = false;

    private long _totalEventsCount;
    private long _droppedEventsCount;
    private long _sessionSizeBytes;

    private ProcessNode? _processTreeRoot;

    private readonly ConcurrentQueue<AnalysisEvent> _pendingEvents = new();
    private readonly ConcurrentQueue<ArtifactRecord> _pendingArtifacts = new();
    private readonly ConcurrentQueue<DiagnosticEntry> _pendingDiagnostics = new();

    private readonly DispatcherTimer _batchTimer;
    private readonly DispatcherTimer _filterDebounceTimer;

    public BulkObservableCollection<AnalysisEvent> Events { get; } = new(20_000);
    public BulkObservableCollection<FileEvent> FileEvents { get; } = new(20_000);
    public BulkObservableCollection<RegistryEvent> RegistryEvents { get; } = new(20_000);
    public BulkObservableCollection<NetworkEvent> NetworkEvents { get; } = new(20_000);
    public BulkObservableCollection<ArtifactRecord> Artifacts { get; } = new(10_000);
    public BulkObservableCollection<DiagnosticEntry> Diagnostics { get; } = new(5_000);

    public ICollectionView FilteredEvents { get; }
    public ICollectionView FilteredFileEvents { get; }
    public ICollectionView FilteredRegistryEvents { get; }
    public ICollectionView FilteredNetworkEvents { get; }

    public IReadOnlyList<string> CategoryOptions { get; } = new[]
    {
        "Все категории",
        "Процессы",
        "Файлы",
        "Реестр",
        "Сеть"
    };

    public string TargetExePath
    {
        get => _targetExePath;
        set
        {
            if (SetProperty(ref _targetExePath, value))
            {
                OnTargetExePathChanged();
            }
        }
    }

    public string OutputDirectory
    {
        get => _outputDirectory;
        set => SetProperty(ref _outputDirectory, value);
    }

    public TargetExeInfo? TargetExeInfo
    {
        get => _targetExeInfo;
        private set => SetProperty(ref _targetExeInfo, value);
    }

    public AnalysisSessionState State
    {
        get => _state;
        private set
        {
            if (SetProperty(ref _state, value))
            {
                OnPropertyChanged(nameof(CanStartWaiting));
                OnPropertyChanged(nameof(CanStopRecording));
                OnPropertyChanged(nameof(CanOpenResults));
                OnPropertyChanged(nameof(CanGenerateReport));
                OnPropertyChanged(nameof(StatusBadgeText));
            }
        }
    }

    public string StatusBadgeText => State switch
    {
        AnalysisSessionState.Ready => "Готов",
        AnalysisSessionState.WaitingForLaunch => "Ожидание запуска",
        AnalysisSessionState.Recording => "Запись событий...",
        AnalysisSessionState.Completed => "Завершено",
        AnalysisSessionState.Error => "Ошибка",
        _ => State.ToString()
    };

    public bool IsElevated => _sessionManager.IsElevated;
    public string ElevationStatusText => IsElevated ? "Администратор (Kernel ETW активен)" : "Обычный пользователь (Базовый сбор)";

    public string? TargetIntegrityWarning
    {
        get => _targetIntegrityWarning;
        set
        {
            if (SetProperty(ref _targetIntegrityWarning, value))
            {
                OnPropertyChanged(nameof(HasTargetIntegrityWarning));
            }
        }
    }

    public bool HasTargetIntegrityWarning => !string.IsNullOrEmpty(_targetIntegrityWarning);

    public bool EnableArtifactSaving
    {
        get => _enableArtifactSaving;
        set => SetProperty(ref _enableArtifactSaving, value);
    }

    public int MaxArtifactSizeMb
    {
        get => _maxArtifactSizeMb;
        set => SetProperty(ref _maxArtifactSizeMb, value);
    }

    public int MaxTotalStorageMb
    {
        get => _maxTotalStorageMb;
        set => SetProperty(ref _maxTotalStorageMb, value);
    }

    public bool EnablePacketCapture
    {
        get => _enablePacketCapture;
        set
        {
            if (value && !_enablePacketCapture)
            {
                MessageBox.Show(
                    RawSocketCapture.CaptureExplanation,
                    "Информация о захвате пакетов PCAPNG",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            SetProperty(ref _enablePacketCapture, value);
        }
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

    public long SessionSizeBytes
    {
        get => _sessionSizeBytes;
        private set => SetProperty(ref _sessionSizeBytes, value);
    }

    private IReadOnlyList<ProcessNode> _processTreeNodes = Array.Empty<ProcessNode>();

    public ProcessNode? ProcessTreeRoot
    {
        get => _processTreeRoot;
        private set
        {
            if (SetProperty(ref _processTreeRoot, value))
            {
                ProcessTreeNodes = value != null ? new[] { value } : Array.Empty<ProcessNode>();
            }
        }
    }

    public IReadOnlyList<ProcessNode> ProcessTreeNodes
    {
        get => _processTreeNodes;
        private set => SetProperty(ref _processTreeNodes, value);
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
                ScheduleFilterRefresh();
        }
    }

    public string ProcessFilter
    {
        get => _processFilter;
        set
        {
            if (SetProperty(ref _processFilter, value))
                ScheduleFilterRefresh();
        }
    }

    public string PathFilter
    {
        get => _pathFilter;
        set
        {
            if (SetProperty(ref _pathFilter, value))
                ScheduleFilterRefresh();
        }
    }

    public string TimeFilter
    {
        get => _timeFilter;
        set
        {
            if (SetProperty(ref _timeFilter, value))
                ScheduleFilterRefresh();
        }
    }

    public string SelectedCategoryOption
    {
        get => _selectedCategoryOption;
        set
        {
            if (SetProperty(ref _selectedCategoryOption, value))
                ScheduleFilterRefresh();
        }
    }

    public bool CanStartWaiting => (State == AnalysisSessionState.Ready || State == AnalysisSessionState.Completed) &&
                                   TargetExeInfo != null && File.Exists(TargetExePath);

    public bool CanStopRecording => State == AnalysisSessionState.Recording || State == AnalysisSessionState.WaitingForLaunch;
    public bool CanOpenResults => !string.IsNullOrEmpty(_sessionManager.CurrentSessionDirectory);
    public bool CanGenerateReport => State == AnalysisSessionState.Completed || State == AnalysisSessionState.Recording;

    public ICommand BrowseExeCommand { get; }
    public ICommand BrowseOutputDirCommand { get; }
    public ICommand StartWaitingCommand { get; }
    public ICommand StopRecordingCommand { get; }
    public ICommand OpenResultsFolderCommand { get; }
    public ICommand GenerateReportCommand { get; }
    public ICommand ClearFilterCommand { get; }

    public MainViewModel()
    {
        _logger = new DiagnosticLogger();
        _sessionManager = new AnalysisSessionManager(_logger);
        _dispatcher = Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher;

        FilteredEvents = CollectionViewSource.GetDefaultView(Events);
        FilteredEvents.Filter = FilterEventPredicate;

        FilteredFileEvents = CollectionViewSource.GetDefaultView(FileEvents);
        FilteredFileEvents.Filter = FilterFileEventPredicate;

        FilteredRegistryEvents = CollectionViewSource.GetDefaultView(RegistryEvents);
        FilteredRegistryEvents.Filter = FilterRegistryEventPredicate;

        FilteredNetworkEvents = CollectionViewSource.GetDefaultView(NetworkEvents);
        FilteredNetworkEvents.Filter = FilterNetworkEventPredicate;

        BrowseExeCommand = new RelayCommand(ExecuteBrowseExe);
        BrowseOutputDirCommand = new RelayCommand(ExecuteBrowseOutputDir);
        StartWaitingCommand = new AsyncRelayCommand(ExecuteStartWaitingAsync, () => CanStartWaiting);
        StopRecordingCommand = new AsyncRelayCommand(ExecuteStopRecordingAsync, () => CanStopRecording);
        OpenResultsFolderCommand = new RelayCommand(ExecuteOpenResultsFolder, () => CanOpenResults);
        GenerateReportCommand = new AsyncRelayCommand(ExecuteGenerateReportAsync, () => CanGenerateReport);
        ClearFilterCommand = new RelayCommand(ExecuteClearFilter);

        _sessionManager.StateChanged += s => _dispatcher.Invoke(() => State = s);
        _sessionManager.EventRecorded += OnEventRecorded;
        _sessionManager.ArtifactSaved += OnArtifactSaved;
        _sessionManager.ProcessTreeUpdated += tree => _dispatcher.Invoke(() => ProcessTreeRoot = tree);
        _sessionManager.TargetIntegrityWarning += msg => _dispatcher.Invoke(() =>
        {
            TargetIntegrityWarning = msg;
            MessageBox.Show(msg, "ВНИМАНИЕ: Изменение целевого файла", MessageBoxButton.OK, MessageBoxImage.Warning);
        });

        _logger.OnLogEntry += entry => _pendingDiagnostics.Enqueue(entry);

        _filterDebounceTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
        _filterDebounceTimer.Tick += (s, e) =>
        {
            _filterDebounceTimer.Stop();
            ApplyFilterCache();
            RefreshFilters();
        };

        _batchTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _batchTimer.Tick += (s, e) => ProcessPendingBatch();
        _batchTimer.Start();

        var metricsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        metricsTimer.Tick += (s, e) =>
        {
            TotalEventsCount = _sessionManager.TotalEventsRecorded;
            DroppedEventsCount = _sessionManager.TotalEventsDropped;
            SessionSizeBytes = _sessionManager.SessionSizeBytes;
        };
        metricsTimer.Start();

        _logger.Info("ExeScope", "Application started. Dynamic sandbox analysis suite ready.");
    }

    private void OnEventRecorded(AnalysisEvent evt)
    {
        _pendingEvents.Enqueue(evt);
    }

    private void OnArtifactSaved(ArtifactRecord record)
    {
        _pendingArtifacts.Enqueue(record);
    }

    private void ProcessPendingBatch()
    {
        if (_pendingEvents.IsEmpty && _pendingArtifacts.IsEmpty && _pendingDiagnostics.IsEmpty)
            return;

        if (!_pendingEvents.IsEmpty)
        {
            var eventBatch = new List<AnalysisEvent>(1000);
            while (eventBatch.Count < 1000 && _pendingEvents.TryDequeue(out var evt))
            {
                eventBatch.Add(evt);
            }

            if (eventBatch.Count > 0)
            {
                Events.PrependRange(eventBatch);

                var fileBatch = new List<FileEvent>();
                var regBatch = new List<RegistryEvent>();
                var netBatch = new List<NetworkEvent>();

                for (int i = 0; i < eventBatch.Count; i++)
                {
                    var item = eventBatch[i];
                    if (item is FileEvent fe) fileBatch.Add(fe);
                    else if (item is RegistryEvent re) regBatch.Add(re);
                    else if (item is NetworkEvent ne) netBatch.Add(ne);
                }

                if (fileBatch.Count > 0) FileEvents.PrependRange(fileBatch);
                if (regBatch.Count > 0) RegistryEvents.PrependRange(regBatch);
                if (netBatch.Count > 0) NetworkEvents.PrependRange(netBatch);
            }
        }

        if (!_pendingArtifacts.IsEmpty)
        {
            var artBatch = new List<ArtifactRecord>(100);
            while (artBatch.Count < 100 && _pendingArtifacts.TryDequeue(out var record))
            {
                artBatch.Add(record);
            }
            if (artBatch.Count > 0)
            {
                Artifacts.PrependRange(artBatch);
            }
        }

        if (!_pendingDiagnostics.IsEmpty)
        {
            var diagBatch = new List<DiagnosticEntry>(100);
            while (diagBatch.Count < 100 && _pendingDiagnostics.TryDequeue(out var entry))
            {
                diagBatch.Add(entry);
            }
            if (diagBatch.Count > 0)
            {
                Diagnostics.PrependRange(diagBatch);
            }
        }
    }

    private void ScheduleFilterRefresh()
    {
        _filterDebounceTimer.Stop();
        _filterDebounceTimer.Start();
    }

    private void ApplyFilterCache()
    {
        _cachedSearchText = _searchText.Trim();
        _cachedProcessFilter = _processFilter.Trim();
        _cachedProcessIdFilter = int.TryParse(_cachedProcessFilter, out int pid) ? pid : null;
        _cachedPathFilter = _pathFilter.Trim();
        _cachedTimeFilter = _timeFilter.Trim();

        _cachedCategoryFilter = _selectedCategoryOption switch
        {
            "Процессы" => EventCategory.Process,
            "Файлы" => EventCategory.File,
            "Реестр" => EventCategory.Registry,
            "Сеть" => EventCategory.Network,
            _ => null
        };
    }

    private void RefreshFilters()
    {
        FilteredEvents.Refresh();
        FilteredFileEvents.Refresh();
        FilteredRegistryEvents.Refresh();
        FilteredNetworkEvents.Refresh();
    }

    private void ExecuteClearFilter()
    {
        SearchText = string.Empty;
        ProcessFilter = string.Empty;
        PathFilter = string.Empty;
        TimeFilter = string.Empty;
        SelectedCategoryOption = "Все категории";
        ApplyFilterCache();
        RefreshFilters();
    }

    private void OnTargetExePathChanged()
    {
        if (File.Exists(_targetExePath))
        {
            try
            {
                _sessionManager.SetTargetExe(_targetExePath);
                TargetExeInfo = _sessionManager.TargetExe;
                TargetIntegrityWarning = null;
            }
            catch (Exception ex)
            {
                _logger.Error("UI", $"Error loading target executable: {ex.Message}", ex);
            }
        }
        else
        {
            TargetExeInfo = null;
            TargetIntegrityWarning = null;
        }

        OnPropertyChanged(nameof(CanStartWaiting));
    }

    private void ExecuteBrowseExe()
    {
        var ofd = new OpenFileDialog
        {
            Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*",
            Title = "Выберите исполняемый файл для анализа"
        };

        if (ofd.ShowDialog() == true)
        {
            TargetExePath = ofd.FileName;
        }
    }

    private void ExecuteBrowseOutputDir()
    {
        var fbd = new OpenFolderDialog
        {
            Title = "Выберите папку для сохранения сессий анализа",
            InitialDirectory = OutputDirectory
        };

        if (fbd.ShowDialog() == true)
        {
            OutputDirectory = fbd.FolderName;
        }
    }

    private async Task ExecuteStartWaitingAsync()
    {
        try
        {
            Events.Clear();
            FileEvents.Clear();
            RegistryEvents.Clear();
            NetworkEvents.Clear();
            Artifacts.Clear();
            TargetIntegrityWarning = null;
            ProcessTreeRoot = null;

            while (_pendingEvents.TryDequeue(out _)) { }
            while (_pendingArtifacts.TryDequeue(out _)) { }
            while (_pendingDiagnostics.TryDequeue(out _)) { }

            var config = new SessionConfig
            {
                TargetExePath = TargetExePath,
                OutputDirectory = OutputDirectory,
                EnableArtifactSaving = EnableArtifactSaving,
                MaxArtifactFileSizeBytes = (long)MaxArtifactSizeMb * 1024 * 1024,
                MaxTotalArtifactStorageBytes = (long)MaxTotalStorageMb * 1024 * 1024,
                EnablePacketCapture = EnablePacketCapture
            };

            _sessionManager.UpdateConfig(config);
            await _sessionManager.StartWaitingAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error("UI", "Failed to start waiting for launch", ex);
            MessageBox.Show($"Ошибка запуска ожидания: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task ExecuteStopRecordingAsync()
    {
        try
        {
            await _sessionManager.StopRecordingAsync("Остановлено пользователем").ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error("UI", "Error stopping recording", ex);
        }
    }

    private void ExecuteOpenResultsFolder()
    {
        _sessionManager.OpenResultsFolder();
    }

    private async Task ExecuteGenerateReportAsync()
    {
        try
        {
            await _sessionManager.GenerateReportAsync().ConfigureAwait(false);
            MessageBox.Show("Автономный HTML-отчёт успешно сформирован!", "Отчёт готов", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _logger.Error("UI", "Failed to generate report", ex);
            MessageBox.Show($"Ошибка формирования отчёта: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private bool PassesCommonFilters(AnalysisEvent evt)
    {
        if (_cachedCategoryFilter.HasValue && evt.Category != _cachedCategoryFilter.Value)
            return false;

        if (_cachedProcessIdFilter.HasValue)
        {
            if (evt.ProcessId != _cachedProcessIdFilter.Value && !evt.ProcessImage.Contains(_cachedProcessFilter, StringComparison.OrdinalIgnoreCase))
                return false;
        }
        else if (!string.IsNullOrEmpty(_cachedProcessFilter))
        {
            if (!evt.ProcessImage.Contains(_cachedProcessFilter, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        if (!string.IsNullOrEmpty(_cachedTimeFilter))
        {
            string timeStr = evt.TimestampUtc.ToString("HH:mm:ss.fff");
            if (!timeStr.Contains(_cachedTimeFilter, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }

    private bool FilterEventPredicate(object item)
    {
        if (item is not AnalysisEvent evt) return false;
        if (!PassesCommonFilters(evt)) return false;

        if (!string.IsNullOrEmpty(_cachedPathFilter))
        {
            bool match = false;
            if (evt is FileEvent fe) match = fe.Path.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase);
            else if (evt is RegistryEvent re) match = re.KeyPath.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase) || (re.ValueName?.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase) ?? false);
            else if (evt is NetworkEvent ne) match = ne.LocalAddress.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase) || ne.RemoteAddress.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase) || (ne.DnsQuery?.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase) ?? false);
            if (!match) return false;
        }

        if (!string.IsNullOrEmpty(_cachedSearchText))
        {
            bool match = evt.Summary.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || evt.ProcessImage.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || (_cachedProcessIdFilter.HasValue && evt.ProcessId == _cachedProcessIdFilter.Value);

            if (!match && evt is FileEvent fe) match = fe.Path.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase);
            else if (!match && evt is RegistryEvent re) match = re.KeyPath.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase) || (re.ValueName?.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase) ?? false);
            else if (!match && evt is NetworkEvent ne) match = ne.LocalAddress.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase) || ne.RemoteAddress.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase) || (ne.DnsQuery?.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase) ?? false);

            if (!match) return false;
        }

        return true;
    }

    private bool FilterFileEventPredicate(object item)
    {
        if (item is not FileEvent fe) return false;
        if (!PassesCommonFilters(fe)) return false;

        if (!string.IsNullOrEmpty(_cachedPathFilter))
        {
            if (!fe.Path.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        if (!string.IsNullOrEmpty(_cachedSearchText))
        {
            bool match = fe.Summary.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || fe.Path.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || fe.ProcessImage.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || (_cachedProcessIdFilter.HasValue && fe.ProcessId == _cachedProcessIdFilter.Value)
                         || fe.Result.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase);
            if (!match) return false;
        }

        return true;
    }

    private bool FilterRegistryEventPredicate(object item)
    {
        if (item is not RegistryEvent re) return false;
        if (!PassesCommonFilters(re)) return false;

        if (!string.IsNullOrEmpty(_cachedPathFilter))
        {
            bool match = re.KeyPath.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase)
                         || (re.ValueName?.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase) ?? false);
            if (!match) return false;
        }

        if (!string.IsNullOrEmpty(_cachedSearchText))
        {
            bool match = re.Summary.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || re.KeyPath.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || (re.ValueName?.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase) ?? false)
                         || re.ProcessImage.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || (_cachedProcessIdFilter.HasValue && re.ProcessId == _cachedProcessIdFilter.Value)
                         || re.Result.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase);
            if (!match) return false;
        }

        return true;
    }

    private bool FilterNetworkEventPredicate(object item)
    {
        if (item is not NetworkEvent ne) return false;
        if (!PassesCommonFilters(ne)) return false;

        if (!string.IsNullOrEmpty(_cachedPathFilter))
        {
            bool match = ne.LocalAddress.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase)
                         || ne.RemoteAddress.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase)
                         || (ne.DnsQuery?.Contains(_cachedPathFilter, StringComparison.OrdinalIgnoreCase) ?? false);
            if (!match) return false;
        }

        if (!string.IsNullOrEmpty(_cachedSearchText))
        {
            bool match = ne.Summary.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || ne.LocalAddress.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || ne.RemoteAddress.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || (ne.DnsQuery?.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase) ?? false)
                         || ne.ProcessImage.Contains(_cachedSearchText, StringComparison.OrdinalIgnoreCase)
                         || (_cachedProcessIdFilter.HasValue && ne.ProcessId == _cachedProcessIdFilter.Value);
            if (!match) return false;
        }

        return true;
    }
}
