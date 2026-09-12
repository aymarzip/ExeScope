using ExeScope.Core.Utilities;
using Xunit;

namespace ExeScope.Tests;

public class RollingBufferTests
{
    [Fact]
    public void Add_WhenBelowCapacity_MaintainsCountAndOrder()
    {
        var buffer = new RollingBuffer<int>(5);
        Assert.Equal(5, buffer.Capacity);
        Assert.Equal(0, buffer.Count);

        buffer.Add(10);
        buffer.Add(20);
        buffer.Add(30);

        Assert.Equal(3, buffer.Count);
        Assert.Equal(3, buffer.TotalAdded);
        Assert.Equal(new[] { 10, 20, 30 }, buffer.ToArray());
    }

    [Fact]
    public void Add_WhenExceedingCapacity_OverwritesOldestAndPreservesChronologicalOrder()
    {
        var buffer = new RollingBuffer<int>(3);

        buffer.Add(1);
        buffer.Add(2);
        buffer.Add(3);
        Assert.Equal(new[] { 1, 2, 3 }, buffer.ToArray());

        buffer.Add(4); // Overwrites 1
        Assert.Equal(3, buffer.Count);
        Assert.Equal(4, buffer.TotalAdded);
        Assert.Equal(new[] { 2, 3, 4 }, buffer.ToArray());

        buffer.Add(5); // Overwrites 2
        Assert.Equal(new[] { 3, 4, 5 }, buffer.ToArray());

        buffer.Add(6); // Overwrites 3
        Assert.Equal(new[] { 4, 5, 6 }, buffer.ToArray());
    }

    [Fact]
    public void AddRange_CorrectlyHandlesBatch()
    {
        var buffer = new RollingBuffer<string>(4);
        buffer.AddRange(new[] { "A", "B", "C", "D", "E", "F" });

        Assert.Equal(4, buffer.Count);
        Assert.Equal(6, buffer.TotalAdded);
        Assert.Equal(new[] { "C", "D", "E", "F" }, buffer.ToArray());
    }

    [Fact]
    public void Clear_ResetsCountAndTotalAddedPreserved()
    {
        var buffer = new RollingBuffer<int>(5);
        buffer.Add(1);
        buffer.Add(2);

        buffer.Clear();
        Assert.Equal(0, buffer.Count);
        Assert.Empty(buffer.ToArray());
    }

    [Fact]
    public void CapacityOne_HandlesRepeatedAdds()
    {
        var buffer = new RollingBuffer<int>(1);
        buffer.Add(100);
        Assert.Equal(new[] { 100 }, buffer.ToArray());

        buffer.Add(200);
        Assert.Equal(new[] { 200 }, buffer.ToArray());
        Assert.Equal(1, buffer.Count);
        Assert.Equal(2, buffer.TotalAdded);
    }

    [Fact]
    public async Task ConcurrentWrites_DoNotCorruptBuffer()
    {
        const int capacity = 1000;
        const int numThreads = 8;
        const int itemsPerThread = 5000;

        var buffer = new RollingBuffer<int>(capacity);
        var tasks = new Task[numThreads];

        for (int t = 0; t < numThreads; t++)
        {
            int threadId = t;
            tasks[t] = Task.Run(() =>
            {
                for (int i = 0; i < itemsPerThread; i++)
                {
                    buffer.Add(threadId * 10_000 + i);
                }
            });
        }

        await Task.WhenAll(tasks);

        Assert.Equal(capacity, buffer.Count);
        Assert.Equal(numThreads * itemsPerThread, buffer.TotalAdded);

        var snapshot = buffer.ToArray();
        Assert.Equal(capacity, snapshot.Length);
    }
}
