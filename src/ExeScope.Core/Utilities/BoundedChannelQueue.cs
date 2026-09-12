using System.Threading.Channels;

namespace ExeScope.Core.Utilities;

public class BoundedChannelQueue<T>
{
    private readonly Channel<T> _channel;
    private long _droppedCount;
    private long _totalEnqueued;
    private readonly int _capacity;
    private readonly Action<long>? _onDropOccurred;

    public int Capacity => _capacity;
    public long DroppedCount => Interlocked.Read(ref _droppedCount);
    public long TotalEnqueued => Interlocked.Read(ref _totalEnqueued);
    public ChannelReader<T> Reader => _channel.Reader;

    public BoundedChannelQueue(int capacity, Action<long>? onDropOccurred = null)
    {
        _capacity = Math.Max(1, capacity);
        _onDropOccurred = onDropOccurred;

        var options = new BoundedChannelOptions(_capacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleWriter = false,
            SingleReader = true
        };

        _channel = Channel.CreateBounded<T>(options);
    }

    public bool TryEnqueue(T item)
    {
        Interlocked.Increment(ref _totalEnqueued);

        // If the channel is at capacity, an item will be dropped due to DropOldest
        if (_channel.Reader.Count >= _capacity)
        {
            long newDropCount = Interlocked.Increment(ref _droppedCount);
            _onDropOccurred?.Invoke(newDropCount);
        }

        return _channel.Writer.TryWrite(item);
    }

    public void Complete()
    {
        _channel.Writer.TryComplete();
    }

    public IAsyncEnumerable<T> ReadAllAsync(CancellationToken cancellationToken = default)
    {
        return _channel.Reader.ReadAllAsync(cancellationToken);
    }
}
