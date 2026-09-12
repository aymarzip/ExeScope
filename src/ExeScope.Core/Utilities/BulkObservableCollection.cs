using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace ExeScope.Core.Utilities;

/// <summary>
/// ObservableCollection supporting bulk inserts and bounded trimming
/// to prevent UI stutter when processing high-volume event streams.
/// </summary>
public class BulkObservableCollection<T> : ObservableCollection<T>
{
    private bool _suppressNotification;
    private readonly int _maxCapacity;

    public int MaxCapacity => _maxCapacity;

    public BulkObservableCollection(int maxCapacity = 20_000)
    {
        _maxCapacity = maxCapacity > 0 ? maxCapacity : int.MaxValue;
    }

    protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
    {
        if (!_suppressNotification)
        {
            base.OnCollectionChanged(e);
        }
    }

    protected override void OnPropertyChanged(PropertyChangedEventArgs e)
    {
        if (!_suppressNotification)
        {
            base.OnPropertyChanged(e);
        }
    }

    public void AddRange(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        var list = items as IList<T> ?? items.ToList();
        if (list.Count == 0)
            return;

        _suppressNotification = true;
        try
        {
            foreach (var item in list)
            {
                Items.Add(item);
            }

            TrimExcess();
        }
        finally
        {
            _suppressNotification = false;
        }

        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }

    public void PrependRange(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        var list = items as IList<T> ?? items.ToList();
        if (list.Count == 0)
            return;

        _suppressNotification = true;
        try
        {
            for (int i = list.Count - 1; i >= 0; i--)
            {
                Items.Insert(0, list[i]);
            }

            TrimExcess();
        }
        finally
        {
            _suppressNotification = false;
        }

        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }

    private void TrimExcess()
    {
        while (Items.Count > _maxCapacity)
        {
            Items.RemoveAt(Items.Count - 1);
        }
    }
}
