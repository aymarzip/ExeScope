using System.Collections;

namespace ExeScope.Core.Utilities;

/// <summary>
/// Thread-safe circular ring buffer with fixed capacity.
/// Drops the oldest entries when capacity is reached with O(1) insertions and no reallocations.
/// </summary>
public class RollingBuffer<T> : IEnumerable<T>
{
    private readonly T[] _buffer;
    private readonly object _syncRoot = new();
    private int _head;
    private int _count;
    private long _totalAdded;

    public int Capacity => _buffer.Length;
    public int Count { get { lock (_syncRoot) return _count; } }
    public long TotalAdded => Interlocked.Read(ref _totalAdded);

    public RollingBuffer(int capacity)
    {
        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(nameof(capacity), "Capacity must be greater than zero.");

        _buffer = new T[capacity];
    }

    public void Add(T item)
    {
        lock (_syncRoot)
        {
            _buffer[_head] = item;
            if (++_head == _buffer.Length)
            {
                _head = 0;
            }
            if (_count < _buffer.Length)
            {
                _count++;
            }
        }
        Interlocked.Increment(ref _totalAdded);
    }

    public void AddRange(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        int added = 0;
        lock (_syncRoot)
        {
            foreach (var item in items)
            {
                _buffer[_head] = item;
                if (++_head == _buffer.Length)
                {
                    _head = 0;
                }
                if (_count < _buffer.Length)
                {
                    _count++;
                }
                added++;
            }
        }
        if (added > 0)
        {
            Interlocked.Add(ref _totalAdded, added);
        }
    }

    public List<T> ToList()
    {
        return new List<T>(ToArray());
    }

    public T[] ToArray()
    {
        lock (_syncRoot)
        {
            if (_count == 0)
                return Array.Empty<T>();

            var result = new T[_count];
            if (_count < _buffer.Length)
            {
                Array.Copy(_buffer, 0, result, 0, _count);
            }
            else
            {
                int tailLen = _buffer.Length - _head;
                Array.Copy(_buffer, _head, result, 0, tailLen);
                if (_head > 0)
                {
                    Array.Copy(_buffer, 0, result, tailLen, _head);
                }
            }
            return result;
        }
    }

    public void Clear()
    {
        lock (_syncRoot)
        {
            Array.Clear(_buffer, 0, _buffer.Length);
            _head = 0;
            _count = 0;
        }
        Interlocked.Exchange(ref _totalAdded, 0);
    }

    public IEnumerator<T> GetEnumerator()
    {
        return ToList().GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
