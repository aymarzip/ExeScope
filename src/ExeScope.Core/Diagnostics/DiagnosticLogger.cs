using System.Threading.Channels;
using ExeScope.Core.Utilities;

namespace ExeScope.Core.Diagnostics;

public sealed class DiagnosticLogger : IDiagnosticLogger, IDisposable
{
    private readonly RollingBuffer<DiagnosticEntry> _entries = new(10_000);
    private readonly Channel<string> _logChannel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
    {
        SingleWriter = false,
        SingleReader = true
    });
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _writerTask;
    private readonly object _fileLock = new();

    private string? _logFilePath;
    private bool _isDisposed;

    public IReadOnlyCollection<DiagnosticEntry> Entries => _entries.ToArray();

    public event Action<DiagnosticEntry>? OnLogEntry;

    public DiagnosticLogger()
    {
        _writerTask = Task.Run(ProcessLogChannelAsync);
    }

    public void SetLogFile(string path)
    {
        lock (_fileLock)
        {
            _logFilePath = path;
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
        }
    }

    public void Log(LogLevel level, string source, string message, Exception? ex = null)
    {
        var entry = new DiagnosticEntry
        {
            TimestampUtc = DateTime.UtcNow,
            Level = level,
            Source = source,
            Message = message,
            ExceptionDetails = ex?.ToString()
        };

        _entries.Add(entry);

        try
        {
            OnLogEntry?.Invoke(entry);
        }
        catch
        {
            // Ignore subscriber exceptions to keep logging resilient
        }

        if (_logFilePath != null)
        {
            _logChannel.Writer.TryWrite(entry.ToString());
        }
    }

    private async Task ProcessLogChannelAsync()
    {
        var reader = _logChannel.Reader;
        var batch = new List<string>(64);

        try
        {
            while (await reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
            {
                while (reader.TryRead(out var line))
                {
                    batch.Add(line);
                    if (batch.Count >= 64)
                        break;
                }

                if (batch.Count > 0 && _logFilePath != null)
                {
                    await WriteBatchAsync(batch).ConfigureAwait(false);
                    batch.Clear();
                }
            }
        }
        catch (OperationCanceledException)
        {
        }

        while (reader.TryRead(out var line))
        {
            batch.Add(line);
        }

        if (batch.Count > 0 && _logFilePath != null)
        {
            await WriteBatchAsync(batch).ConfigureAwait(false);
        }
    }

    private async Task WriteBatchAsync(List<string> lines)
    {
        string? targetPath;
        lock (_fileLock)
        {
            targetPath = _logFilePath;
        }

        if (string.IsNullOrEmpty(targetPath))
            return;

        try
        {
            await using var stream = new FileStream(targetPath, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, useAsync: true);
            await using var writer = new StreamWriter(stream);
            foreach (var line in lines)
            {
                await writer.WriteLineAsync(line).ConfigureAwait(false);
            }
        }
        catch
        {
        }
    }

    public void Info(string source, string message) => Log(LogLevel.Info, source, message);
    public void Warn(string source, string message) => Log(LogLevel.Warning, source, message);
    public void Error(string source, string message, Exception? ex = null) => Log(LogLevel.Error, source, message, ex);

    public IReadOnlyList<DiagnosticEntry> GetEntries() => _entries.ToList();

    public void Dispose()
    {
        if (_isDisposed)
            return;

        _isDisposed = true;
        _logChannel.Writer.TryComplete();

        try
        {
            if (!_writerTask.Wait(1500))
            {
                _cts.Cancel();
            }
        }
        catch
        {
        }

        _cts.Dispose();
    }
}
