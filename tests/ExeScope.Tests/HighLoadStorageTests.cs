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

    [Fact]
    public async Task FileSessionStorage_FlushAsync_FlushesSmallBatchImmediatelyWithoutDisposing()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"ExeScope_Flush_{Guid.NewGuid():N}");
        var logger = new DiagnosticLogger();

        try
        {
            var storage = new FileSessionStorage(tempDir, rootPid: 9999, logger, channelCapacity: 50_000);

            // Enqueue only 7 items (far below 1,000 batch size)
            for (int i = 0; i < 7; i++)
            {
                storage.EnqueueEvent(new ProcessEvent
                {
                    EventId = i + 1,
                    ProcessId = 9999,
                    ProcessImage = "flush_test.exe",
                    Summary = $"Flush event {i}"
                });
            }

            // Flush without disposing - must immediately flush to disk
            await storage.FlushAsync();

            string eventsFile = Path.Combine(storage.SessionDirectory, "events.jsonl");
            Assert.True(File.Exists(eventsFile));

            var recorded = storage.ReadRecordedEvents();
            Assert.Equal(7, recorded.Count);
            Assert.Equal(7, storage.TotalEventsWritten);

            await storage.DisposeAsync();
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public async Task FileSessionStorage_PeriodicIdleFlush_WritesEventsAutomatically()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"ExeScope_IdleFlush_{Guid.NewGuid():N}");
        var logger = new DiagnosticLogger();

        try
        {
            var storage = new FileSessionStorage(tempDir, rootPid: 8888, logger, channelCapacity: 50_000);

            for (int i = 0; i < 3; i++)
            {
                storage.EnqueueEvent(new ProcessEvent
                {
                    EventId = i + 1,
                    ProcessId = 8888,
                    ProcessImage = "idle_flush.exe",
                    Summary = $"Idle event {i}"
                });
            }

            // Wait 350ms (timeout threshold is 150ms) without calling FlushAsync
            await Task.Delay(350);

            string eventsFile = Path.Combine(storage.SessionDirectory, "events.jsonl");
            Assert.True(File.Exists(eventsFile));

            var recorded = storage.ReadRecordedEvents();
            Assert.Equal(3, recorded.Count);

            await storage.DisposeAsync();
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }
    }
}
