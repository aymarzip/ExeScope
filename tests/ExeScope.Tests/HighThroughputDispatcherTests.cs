using System.Collections.Concurrent;
using ExeScope.Contracts.Grpc;
using ExeScope.Core.Utilities;
using Xunit;

namespace ExeScope.Tests;

public class HighThroughputDispatcherTests
{
    [Fact]
    public void HighThroughputQueue_Handles50000EventsWithoutBlocking()
    {
        var incomingQueue = new ConcurrentQueue<TelemetryEnvelope>();
        var storageCollection = new BulkObservableCollection<TelemetryEnvelope>(50_000);

        // Simulate 50,000 events burst generated in 1 second
        for (int i = 0; i < 50_000; i++)
        {
            incomingQueue.Enqueue(new TelemetryEnvelope
            {
                EventId = i,
                TimestampUtc = DateTime.UtcNow.ToString("o"),
                Category = (i % 4) switch
                {
                    0 => "File",
                    1 => "Registry",
                    2 => "Network",
                    _ => "Process"
                },
                ProcessId = 1000 + (i % 5),
                ProcessImage = "virus.exe",
                Summary = $"High frequency event {i}"
            });
        }

        Assert.Equal(50_000, incomingQueue.Count);

        // Simulate throttled batch drainer (e.g. 2000 per tick)
        int drainedTotal = 0;
        var batch = new List<TelemetryEnvelope>(2000);

        while (!incomingQueue.IsEmpty)
        {
            batch.Clear();
            while (batch.Count < 2000 && incomingQueue.TryDequeue(out var env))
            {
                batch.Add(env);
            }

            drainedTotal += batch.Count;
            storageCollection.AddRange(batch);
        }

        Assert.Equal(50_000, drainedTotal);
        // BulkObservableCollection capped at max items (50,000)
        Assert.True(storageCollection.Count <= 50_000);
    }
}
