using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using ExeScope.Engine.Session;

namespace ExeScope.UI.Converters;

public class StateToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is AnalysisSessionState state)
        {
            return state switch
            {
                AnalysisSessionState.Ready => new SolidColorBrush(Color.FromRgb(88, 166, 255)),            // Blue
                AnalysisSessionState.WaitingForLaunch => new SolidColorBrush(Color.FromRgb(210, 153, 34)),  // Yellow/Orange
                AnalysisSessionState.Recording => new SolidColorBrush(Color.FromRgb(248, 81, 73)),         // Red (Active Recording)
                AnalysisSessionState.Completed => new SolidColorBrush(Color.FromRgb(63, 185, 80)),         // Green
                AnalysisSessionState.Error => new SolidColorBrush(Color.FromRgb(218, 54, 51)),            // Crimson
                _ => Brushes.Gray
            };
        }
        return Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw freshNotSupportedException();
    private static NotSupportedException freshNotSupportedException() => new();
}

public class StateToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is AnalysisSessionState state)
        {
            return state switch
            {
                AnalysisSessionState.Ready => "Готов",
                AnalysisSessionState.WaitingForLaunch => "Ожидание",
                AnalysisSessionState.Recording => "Запись",
                AnalysisSessionState.Completed => "Завершено",
                AnalysisSessionState.Error => "Ошибка",
                _ => state.ToString()
            };
        }
        return "Неизвестно";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public class ByteSizeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        long bytes = 0;
        if (value is long l) bytes = l;
        else if (value is int i) bytes = i;
        else if (value is ulong ul) bytes = (long)ul;

        string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
        int order = 0;
        double len = bytes;
        while (len >= 1024 && order < suffixes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {suffixes[order]}";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool isNull = value == null || (value is string s && string.IsNullOrWhiteSpace(s));
        bool invert = parameter?.ToString()?.Equals("invert", StringComparison.OrdinalIgnoreCase) ?? false;
        if (invert)
            return isNull ? Visibility.Visible : Visibility.Collapsed;
        return isNull ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public class ProcessStatusConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool isAlive)
        {
            return isAlive ? "Активен" : "Завершён";
        }
        return "Неизвестно";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public class ProcessStatusColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool isAlive)
        {
            return isAlive ? new SolidColorBrush(Color.FromRgb(63, 185, 80)) : new SolidColorBrush(Color.FromRgb(139, 148, 158));
        }
        return Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

