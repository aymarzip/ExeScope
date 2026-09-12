namespace ExeScope.Core.Diagnostics;

public enum LogLevel
{
    Debug,
    Info,
    Warning,
    Error,
    Fatal
}

public class DiagnosticEntry
{
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public LogLevel Level { get; set; }
    public string Source { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string? ExceptionDetails { get; set; }

    public override string ToString()
    {
        return $"[{TimestampUtc:yyyy-MM-dd HH:mm:ss.fff}Z] [{Level.ToString().ToUpperInvariant()}] [{Source}] {Message}" +
               (string.IsNullOrEmpty(ExceptionDetails) ? "" : $"{Environment.NewLine}  {ExceptionDetails}");
    }
}

public interface IDiagnosticLogger
{
    void Log(LogLevel level, string source, string message, Exception? ex = null);
    void Info(string source, string message);
    void Warn(string source, string message);
    void Error(string source, string message, Exception? ex = null);
    IReadOnlyList<DiagnosticEntry> GetEntries();
    event Action<DiagnosticEntry>? OnLogEntry;
}
