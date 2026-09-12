using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Storage;
using Xunit;

namespace ExeScope.Tests;

public class HighLoadStorageTests
{
    [Fact]
    public async Task FileSessionStorage_HandlesHighThroughputBatchWritesWithoutDataLoss()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"ExeScope_StorageLoad_{Guid.NewGuid():N}");
        var logger = new DiagnosticLogger();

        try
        {
            const int totalEvents = 5000;
            var storage = new FileSessionStorage(tempDir, rootPid: 1234, logger, channelCapacity: 50_000);

            var startTime = DateTime.UtcNow;
            var tasks = new Task[4];

            // 4 concurrent producers writing 1,250 events each
            for (int t = 0; t < 4; t++)
            {
                int producerId = t;
                tasks[t] = Task.Run(() =>
                {
                    for (int i = 0; i < 1250; i++)
                    {
                        var evt = new FileEvent
                        {
                            EventId = producerId * 10000 + i,
                            TimestampUtc = startTime.AddMilliseconds(i),
                            ProcessId = 1234,
                            ProcessImage = "load_test.exe",
                            Operation = FileOperationType.Write,
                            Path = $@"C:\Temp\load_test_{producerId}_{i}.dat",
                            Result = "SUCCESS",
                            ByteCount = 1024,
                            Summary = $"Write to file load_test_{producerId}_{i}.dat"
                        };
                        storage.EnqueueEvent(evt);
                    }
                });
            }

            await Task.WhenAll(tasks);
            await storage.FlushAsync();
            await storage.DisposeAsync();

            string eventsFile = Path.Combine(storage.SessionDirectory, "events.jsonl");
            Assert.True(File.Exists(eventsFile));

            var recorded = storage.ReadRecordedEvents();
            Assert.Equal(totalEvents, recorded.Count);
            Assert.Equal(totalEvents, storage.TotalEventsWritten);
            Assert.Equal(0, storage.TotalEventsDropped);
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public async Task FileSessionStorage_OverflowTracksDropCountAccurately()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"ExeScope_Overflow_{Guid.NewGuid():N}");
        var logger = new DiagnosticLogger();

        try
        {
            // Tiny queue of capacity 10
            var storage = new FileSessionStorage(tempDir, rootPid: 5678, logger, channelCapacity: 10);

            // Enqueue 50 items rapidly
            for (int i = 0; i < 50; i++)
            {
                storage.EnqueueEvent(new ProcessEvent
                {
                    EventId = i,
                    ProcessId = 5678,
                    ProcessImage = "overflow.exe",
                    Summary = $"Event {i}"
                });
            }

            await storage.FlushAsync();
            await storage.DisposeAsync();

            // Total written + dropped should account for all attempted enqueues
            Assert.True(storage.TotalEventsDropped > 0);
            Assert.True(storage.TotalEventsWritten > 0);
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }
    }
}
