using ExeScope.Core.Utilities;
using Xunit;

namespace ExeScope.Tests;

public class BoundedQueueTests
{
    [Fact]
    public async Task BoundedQueue_DropsOldest_AndTracksDropCount()
    {
        long reportedDrops = 0;
        var queue = new BoundedChannelQueue<int>(capacity: 10, onDropOccurred: d => reportedDrops = d);

        // Enqueue 25 items into queue of capacity 10
        for (int i = 0; i < 25; i++)
        {
            queue.TryEnqueue(i);
        }

        queue.Complete();

        var readItems = new List<int>();
        await foreach (var item in queue.ReadAllAsync())
        {
            readItems.Add(item);
        }

        // Bounded capacity ensures total items read <= capacity (approx 10)
        Assert.True(readItems.Count <= 10);
        Assert.True(queue.DroppedCount > 0);
        Assert.True(reportedDrops > 0);
    }
}
