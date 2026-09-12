using ExeScope.Core.Diagnostics;
using Xunit;

namespace ExeScope.Tests;

public class DiagnosticLoggerTests
{
    [Fact]
    public void DiagnosticLogger_RecordsEntriesInMemory()
    {
        using var logger = new DiagnosticLogger();

        logger.Info("TestModule", "Informational message");
        logger.Warn("TestModule", "Warning message");
        logger.Error("TestModule", "Error message");

        var entries = logger.GetEntries();
        Assert.Equal(3, entries.Count);
        Assert.Equal(LogLevel.Info, entries[0].Level);
        Assert.Equal(LogLevel.Warning, entries[1].Level);
        Assert.Equal(LogLevel.Error, entries[2].Level);
    }

    [Fact]
    public void DiagnosticLogger_FiresOnLogEntryEvent()
    {
        using var logger = new DiagnosticLogger();
        var captured = new List<DiagnosticEntry>();
        logger.OnLogEntry += e => captured.Add(e);

        logger.Info("Sub", "Msg 1");
        logger.Warn("Sub", "Msg 2");

        Assert.Equal(2, captured.Count);
        Assert.Equal("Msg 1", captured[0].Message);
    }

    [Fact]
    public async Task DiagnosticLogger_WritesToFileAndDrainsOnDispose()
    {
        string tempLog = Path.Combine(Path.GetTempPath(), $"diag_{Guid.NewGuid():N}.log");

        try
        {
            var logger = new DiagnosticLogger();
            logger.SetLogFile(tempLog);

            for (int i = 0; i < 20; i++)
            {
                logger.Info("DrainTest", $"Message {i}");
            }

            // Dispose should cleanly drain the channel without throwing TaskCanceledException
            logger.Dispose();

            Assert.True(File.Exists(tempLog));
            string[] lines = await File.ReadAllLinesAsync(tempLog);
            Assert.Equal(20, lines.Length);
        }
        finally
        {
            try { if (File.Exists(tempLog)) File.Delete(tempLog); } catch { }
        }
    }
}
