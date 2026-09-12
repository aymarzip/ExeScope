using System.Collections.Specialized;
using ExeScope.Core.Utilities;
using Xunit;

namespace ExeScope.Tests;

public class BulkObservableCollectionTests
{
    [Fact]
    public void AddRange_FiresSingleResetNotification()
    {
        var collection = new BulkObservableCollection<string>(maxCapacity: 100);
        int notificationCount = 0;
        NotifyCollectionChangedAction? lastAction = null;

        collection.CollectionChanged += (s, e) =>
        {
            notificationCount++;
            lastAction = e.Action;
        };

        collection.AddRange(new[] { "item1", "item2", "item3", "item4", "item5" });

        Assert.Equal(1, notificationCount);
        Assert.Equal(NotifyCollectionChangedAction.Reset, lastAction);
        Assert.Equal(5, collection.Count);
    }

    [Fact]
    public void PrependRange_InsertsAtBeginningAndTrimsAtCapacity()
    {
        var collection = new BulkObservableCollection<int>(maxCapacity: 4);

        collection.PrependRange(new[] { 1, 2 });
        Assert.Equal(new[] { 1, 2 }, collection.ToArray());

        // Prepend [3, 4, 5] -> should be [3, 4, 5, 1, 2] -> trimmed to 4 items -> [3, 4, 5, 1]
        collection.PrependRange(new[] { 3, 4, 5 });

        Assert.Equal(4, collection.Count);
        Assert.Equal(new[] { 3, 4, 5, 1 }, collection.ToArray());
    }

    [Fact]
    public void AddRange_EmptyCollection_DoesNotFireNotification()
    {
        var collection = new BulkObservableCollection<int>(maxCapacity: 10);
        bool fired = false;
        collection.CollectionChanged += (s, e) => fired = true;

        collection.AddRange(Array.Empty<int>());

        Assert.False(fired);
        Assert.Empty(collection);
    }

    [Fact]
    public void AddRange_TrimsOldestAtHead_PreservesNewestItemsAtTail()
    {
        var collection = new BulkObservableCollection<int>(maxCapacity: 4);

        collection.AddRange(new[] { 1, 2, 3, 4 });
        Assert.Equal(new[] { 1, 2, 3, 4 }, collection.ToArray());

        collection.AddRange(new[] { 5, 6 });
        Assert.Equal(4, collection.Count);
        Assert.Equal(new[] { 3, 4, 5, 6 }, collection.ToArray());
    }

    [Fact]
    public void AddRange_BatchLargerThanCapacity_RetainsLatestItems()
    {
        var collection = new BulkObservableCollection<int>(maxCapacity: 3);

        collection.AddRange(new[] { 10, 20, 30, 40, 50 });
        Assert.Equal(3, collection.Count);
        Assert.Equal(new[] { 30, 40, 50 }, collection.ToArray());
    }

    [Fact]
    public void PrependRange_BatchLargerThanCapacity_RetainsPrependedHeadItems()
    {
        var collection = new BulkObservableCollection<int>(maxCapacity: 3);

        collection.PrependRange(new[] { 100, 200, 300, 400 });
        Assert.Equal(3, collection.Count);
        Assert.Equal(new[] { 100, 200, 300 }, collection.ToArray());
    }
}
