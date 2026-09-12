using System.Text.Encodings.Web;
using System.Text.Json;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Core.Utilities;

namespace ExeScope.Engine.Storage;

public class FileSessionStorage : ISessionStorage
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly JsonSerializerOptions CompactJsonOptions = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private readonly string _sessionDirectory;
    private readonly string _eventsFilePath;
    private readonly string _sessionMetadataPath;
    private readonly string _processTreePath;
    private readonly IDiagnosticLogger _logger;
    private readonly BoundedChannelQueue<AnalysisEvent> _queue;

    private readonly CancellationTokenSource _cts = new();
    private readonly Task _consumerTask;
    private bool _isDisposed;
    private long _totalEventsWritten;

    public string SessionDirectory => _sessionDirectory;
    public long TotalEventsWritten => Interlocked.Read(ref _totalEventsWritten);
    public long TotalEventsDropped => _queue.DroppedCount;

    public FileSessionStorage(string baseOutputDir, int rootPid, IDiagnosticLogger logger, int channelCapacity = 50_000)
    {
        _logger = logger;

        string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        string sessionFolderName = $"session_{timestamp}_PID{rootPid}";
        _sessionDirectory = Path.Combine(baseOutputDir, sessionFolderName);

        Directory.CreateDirectory(_sessionDirectory);

        _eventsFilePath = Path.Combine(_sessionDirectory, "events.jsonl");
        _sessionMetadataPath = Path.Combine(_sessionDirectory, "session.json");
        _processTreePath = Path.Combine(_sessionDirectory, "process-tree.json");

        string diagLogPath = Path.Combine(_sessionDirectory, "diagnostics.log");
        if (logger is DiagnosticLogger dl)
        {
            dl.SetLogFile(diagLogPath);
        }

        _queue = new BoundedChannelQueue<AnalysisEvent>(channelCapacity, onDropOccurred: count =>
        {
            _logger.Warn("Storage", $"Queue capacity reached, dropped events count: {count}");
        });

        _consumerTask = Task.Run(() => ProcessQueueAsync(_cts.Token));
    }

    public void EnqueueEvent(AnalysisEvent evt)
    {
        if (_isDisposed)
            return;

        _queue.TryEnqueue(evt);
    }

    private volatile TaskCompletionSource? _pendingFlush;

    private async Task ProcessQueueAsync(CancellationToken ct)
    {
        const int maxBatchSize = 1000;
        var batch = new List<AnalysisEvent>(maxBatchSize);
        var lastFlushTime = DateTime.UtcNow;

        await using var fileStream = new FileStream(
            _eventsFilePath,
            FileMode.Append,
            FileAccess.Write,
            FileShare.Read,
            bufferSize: 262144,
            useAsync: true);
        await using var streamWriter = new StreamWriter(fileStream);

        try
        {
            var reader = _queue.Reader;

            while (!ct.IsCancellationRequested)
            {
                bool hasItems;
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(TimeSpan.FromMilliseconds(150));
                    hasItems = await reader.WaitToReadAsync(cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    hasItems = false;
                }

                while (reader.TryRead(out var evt))
                {
                    batch.Add(evt);
                    if (batch.Count >= maxBatchSize)
                    {
                        await WriteBatchAsync(streamWriter, batch).ConfigureAwait(false);
                        batch.Clear();
                        lastFlushTime = DateTime.UtcNow;
                    }
                }

                if (batch.Count > 0 && (DateTime.UtcNow - lastFlushTime).TotalMilliseconds >= 150)
                {
                    await WriteBatchAsync(streamWriter, batch).ConfigureAwait(false);
                    batch.Clear();
                    lastFlushTime = DateTime.UtcNow;
                }

                await CheckAndCompleteFlushAsync(streamWriter, batch).ConfigureAwait(false);

                if (!hasItems && reader.Completion.IsCompleted)
                {
                    break;
                }
            }

            while (reader.TryRead(out var evt))
            {
                batch.Add(evt);
            }

            if (batch.Count > 0)
            {
                await WriteBatchAsync(streamWriter, batch).ConfigureAwait(false);
                batch.Clear();
            }

            await CheckAndCompleteFlushAsync(streamWriter, batch).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            while (_queue.Reader.TryRead(out var evt))
            {
                batch.Add(evt);
            }
            if (batch.Count > 0)
            {
                await WriteBatchAsync(streamWriter, batch).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.Error("Storage", "Error writing events to events.jsonl", ex);
        }
    }

    private async Task CheckAndCompleteFlushAsync(StreamWriter writer, List<AnalysisEvent> batch)
    {
        var flush = Interlocked.Exchange(ref _pendingFlush, null);
        if (flush != null)
        {
            try
            {
                if (batch.Count > 0)
                {
                    await WriteBatchAsync(writer, batch).ConfigureAwait(false);
                    batch.Clear();
                }
                await writer.FlushAsync().ConfigureAwait(false);
            }
            catch
            {
            }
            flush.TrySetResult();
        }
    }

    private async Task WriteBatchAsync(StreamWriter writer, List<AnalysisEvent> batch)
    {
        for (int i = 0; i < batch.Count; i++)
        {
            string line = JsonSerializer.Serialize(batch[i], CompactJsonOptions);
            writer.WriteLine(line);
        }

        await writer.FlushAsync().ConfigureAwait(false);
        Interlocked.Add(ref _totalEventsWritten, batch.Count);
    }

    public void SaveSessionMetadata(SessionMetadata metadata)
    {
        try
        {
            string json = JsonSerializer.Serialize(metadata, JsonOptions);
            File.WriteAllText(_sessionMetadataPath, json);
        }
        catch (Exception ex)
        {
            _logger.Error("Storage", "Failed to save session.json", ex);
        }
    }

    public void SaveProcessTree(ProcessNode? rootNode)
    {
        try
        {
            string json = JsonSerializer.Serialize(rootNode, JsonOptions);
            File.WriteAllText(_processTreePath, json);
        }
        catch (Exception ex)
        {
            _logger.Error("Storage", "Failed to save process-tree.json", ex);
        }
    }

    public long CalculateSessionSizeBytes()
    {
        try
        {
            if (!Directory.Exists(_sessionDirectory))
                return 0;

            var dirInfo = new DirectoryInfo(_sessionDirectory);
            return dirInfo.EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length);
        }
        catch
        {
            return 0;
        }
    }

    public List<AnalysisEvent> ReadRecordedEvents()
    {
        var result = new List<AnalysisEvent>();
        if (!File.Exists(_eventsFilePath))
            return result;

        try
        {
            using var fileStream = new FileStream(_eventsFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fileStream);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var evt = JsonSerializer.Deserialize<AnalysisEvent>(line);
                if (evt != null)
                    result.Add(evt);
            }
        }
        catch (Exception ex)
        {
            _logger.Error("Storage", "Failed to read events from events.jsonl", ex);
        }

        return result;
    }

    public async Task FlushAsync()
    {
        if (_isDisposed)
            return;

        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingFlush = tcs;

        // Drain any unread items if waiting
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        timeoutCts.Token.Register(() => tcs.TrySetResult());

        await tcs.Task.ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_isDisposed)
            return;

        _isDisposed = true;
        _queue.Complete();

        try
        {
            await _consumerTask.ConfigureAwait(false);
        }
        catch
        {
        }

        _cts.Dispose();
    }
}
