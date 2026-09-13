using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Core.Utilities;

namespace ExeScope.Engine.Collectors;

public class FileArtifactCollector : IAsyncDisposable
{
    private readonly SessionConfig _config;
    private readonly string _artifactsDirectory;
    private readonly string _indexFilePath;
    private readonly IDiagnosticLogger _logger;

    private readonly BlockingCollection<ArtifactTask> _queue = new(new ConcurrentQueue<ArtifactTask>(), 2000);
    private readonly ConcurrentDictionary<string, (string Sha256, DateTime LastWriteUtc)> _processedFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _indexFileLock = new();
    private StreamWriter? _indexWriter;

    private Thread? _workerThread;
    private bool _isRunning;
    private bool _isDisposed;
    private long _totalArtifactBytesWritten;
    private long _totalArtifactsSaved;
    private long _totalArtifactsSkipped;
    private long _artifactIndexSequence;

    public long TotalBytesWritten => Interlocked.Read(ref _totalArtifactBytesWritten);
    public long TotalSaved => Interlocked.Read(ref _totalArtifactsSaved);
    public long TotalSkipped => Interlocked.Read(ref _totalArtifactsSkipped);

    public event Action<ArtifactRecord>? ArtifactPreserved;

    private record ArtifactTask(string OriginalPath, int ProcessId, string ProcessImage);

    public FileArtifactCollector(SessionConfig config, string sessionDirectory, IDiagnosticLogger logger)
    {
        _config = config;
        _logger = logger;
        _artifactsDirectory = Path.Combine(sessionDirectory, "artifacts");
        _indexFilePath = Path.Combine(sessionDirectory, "artifacts-index.jsonl");

        if (!Directory.Exists(_artifactsDirectory))
        {
            Directory.CreateDirectory(_artifactsDirectory);
        }

        var stream = new FileStream(_indexFilePath, FileMode.Append, FileAccess.Write, FileShare.Read, 4096);
        _indexWriter = new StreamWriter(stream);
    }

    public void Start()
    {
        if (_isRunning || !_config.EnableArtifactSaving)
            return;

        _isRunning = true;
        _workerThread = new Thread(WorkerLoop)
        {
            IsBackground = true,
            Name = "ExeScope_ArtifactCollector"
        };
        _workerThread.Start();
        _logger.Info("ArtifactCollector", $"Artifact collector initialized. Destination: {_artifactsDirectory}");
    }

    public void QueueFile(string originalPath, int pid, string processImage, bool bypassDirectoryFilter = false)
    {
        if (!_config.EnableArtifactSaving || !_isRunning)
            return;

        if (string.IsNullOrWhiteSpace(originalPath))
            return;

        if (!bypassDirectoryFilter && !PathSanitizer.IsPathWithinMonitoredDirectories(originalPath, _config.ArtifactMonitoredDirectories))
            return;

        _queue.TryAdd(new ArtifactTask(originalPath, pid, processImage));
    }

    private void WorkerLoop()
    {
        while (_isRunning && !_queue.IsCompleted)
        {
            try
            {
                if (_queue.TryTake(out var task, 200))
                {
                    ProcessArtifactTask(task);
                }
            }
            catch (Exception ex)
            {
                _logger.Error("ArtifactCollector", "Error in artifact processing worker", ex);
            }
        }
    }

    private void ProcessArtifactTask(ArtifactTask task)
    {
        string filePath = task.OriginalPath;
        var record = new ArtifactRecord
        {
            OriginalPath = filePath,
            OriginatingProcessId = task.ProcessId,
            OriginatingProcessImage = task.ProcessImage,
            TimestampUtc = DateTime.UtcNow
        };

        if (!File.Exists(filePath))
        {
            record.CopyStatus = ArtifactCopyStatus.DeletedBeforeCopy;
            record.FailureReason = "File was deleted or does not exist at time of artifact copy attempt.";
            Interlocked.Increment(ref _totalArtifactsSkipped);
            WriteIndexRecord(record);
            return;
        }

        FileInfo fileInfo;
        try
        {
            fileInfo = new FileInfo(filePath);
        }
        catch (Exception ex)
        {
            record.CopyStatus = ArtifactCopyStatus.Error;
            record.FailureReason = $"Failed to inspect file: {ex.Message}";
            Interlocked.Increment(ref _totalArtifactsSkipped);
            WriteIndexRecord(record);
            return;
        }

        if (fileInfo.Length > _config.MaxArtifactFileSizeBytes)
        {
            record.CopyStatus = ArtifactCopyStatus.SizeLimitExceeded;
            record.SizeBytes = fileInfo.Length;
            record.FailureReason = $"File size ({fileInfo.Length} bytes) exceeds limit of {_config.MaxArtifactFileSizeBytes} bytes.";
            Interlocked.Increment(ref _totalArtifactsSkipped);
            WriteIndexRecord(record);
            return;
        }

        if (Interlocked.Read(ref _totalArtifactBytesWritten) + fileInfo.Length > _config.MaxTotalArtifactStorageBytes)
        {
            record.CopyStatus = ArtifactCopyStatus.QuotaExceeded;
            record.SizeBytes = fileInfo.Length;
            record.FailureReason = "Total session artifact storage quota exceeded.";
            Interlocked.Increment(ref _totalArtifactsSkipped);
            WriteIndexRecord(record);
            return;
        }

        long index = Interlocked.Increment(ref _artifactIndexSequence);
        string tempDestination = Path.Combine(_artifactsDirectory, $".tmp_{index}_{Guid.NewGuid():N}");

        try
        {
            DateTime initialWriteTime = fileInfo.LastWriteTimeUtc;
            long initialLength = fileInfo.Length;
            string computedHash;

            using (var sourceStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, bufferSize: 65536))
            using (var destStream = new FileStream(tempDestination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var sha = SHA256.Create())
            {
                byte[] buffer = new byte[65536];
                int bytesRead;
                while ((bytesRead = sourceStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    destStream.Write(buffer, 0, bytesRead);
                    sha.TransformBlock(buffer, 0, bytesRead, null, 0);
                }
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                computedHash = Convert.ToHexString(sha.Hash!).ToLowerInvariant();
            }

            var postCopyInfo = new FileInfo(filePath);
            if (postCopyInfo.Exists)
            {
                if (postCopyInfo.LastWriteTimeUtc != initialWriteTime || postCopyInfo.Length != initialLength)
                {
                    record.MightHaveChangedDuringCopy = true;
                    _logger.Warn("ArtifactCollector", $"File modified during copy: {filePath}");
                }
            }

            if (_processedFiles.TryGetValue(filePath, out var prev) && prev.Sha256 == computedHash)
            {
                try { File.Delete(tempDestination); } catch { }
                return;
            }

            string safeDestPath = PathSanitizer.CreateSafeArtifactDestination(_artifactsDirectory, index, filePath, computedHash);
            if (File.Exists(safeDestPath))
            {
                File.Delete(safeDestPath);
            }
            File.Move(tempDestination, safeDestPath);

            var savedInfo = new FileInfo(safeDestPath);
            record.CopyStatus = ArtifactCopyStatus.Success;
            record.ArtifactFileName = Path.GetFileName(safeDestPath);
            record.RelativeStoragePath = Path.Combine("artifacts", record.ArtifactFileName);
            record.Sha256 = computedHash;
            record.SizeBytes = savedInfo.Length;

            Interlocked.Add(ref _totalArtifactBytesWritten, savedInfo.Length);
            Interlocked.Increment(ref _totalArtifactsSaved);
            _processedFiles[filePath] = (computedHash, initialWriteTime);

            _logger.Info("ArtifactCollector", $"Preserved artifact: {record.ArtifactFileName} ({record.SizeBytes} bytes) from {filePath}");
            WriteIndexRecord(record);
            ArtifactPreserved?.Invoke(record);
        }
        catch (IOException ioEx)
        {
            try { if (File.Exists(tempDestination)) File.Delete(tempDestination); } catch { }

            record.CopyStatus = ArtifactCopyStatus.Locked;
            record.FailureReason = $"File locked by process: {ioEx.Message}";
            Interlocked.Increment(ref _totalArtifactsSkipped);
            WriteIndexRecord(record);
        }
        catch (UnauthorizedAccessException uEx)
        {
            try { if (File.Exists(tempDestination)) File.Delete(tempDestination); } catch { }

            record.CopyStatus = ArtifactCopyStatus.AccessDenied;
            record.FailureReason = $"Access denied: {uEx.Message}";
            Interlocked.Increment(ref _totalArtifactsSkipped);
            WriteIndexRecord(record);
        }
        catch (Exception ex)
        {
            try { if (File.Exists(tempDestination)) File.Delete(tempDestination); } catch { }

            record.CopyStatus = ArtifactCopyStatus.Error;
            record.FailureReason = $"Copy failed: {ex.Message}";
            Interlocked.Increment(ref _totalArtifactsSkipped);
            WriteIndexRecord(record);
        }
    }

    private void WriteIndexRecord(ArtifactRecord record)
    {
        lock (_indexFileLock)
        {
            try
            {
                if (_indexWriter != null)
                {
                    string jsonLine = JsonSerializer.Serialize(record);
                    _indexWriter.WriteLine(jsonLine);
                    _indexWriter.Flush();
                }
            }
            catch (Exception ex)
            {
                _logger.Error("ArtifactCollector", "Failed to write artifact index entry", ex);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_isDisposed)
            return;

        _isDisposed = true;
        _isRunning = false;
        _queue.CompleteAdding();

        if (_workerThread != null && _workerThread.IsAlive)
        {
            _workerThread.Join(1500);
        }

        lock (_indexFileLock)
        {
            try
            {
                _indexWriter?.Flush();
                _indexWriter?.Dispose();
                _indexWriter = null;
            }
            catch
            {
            }
        }

        _queue.Dispose();
        await Task.CompletedTask;
    }
}
