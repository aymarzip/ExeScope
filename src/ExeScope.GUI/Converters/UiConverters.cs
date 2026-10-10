using System.Globalization;
using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media;
using ExeScope.Contracts.Threat;

namespace ExeScope.GUI.Converters;

public static class UiConverters
{
    public static readonly IValueConverter ThreatLevelToBrush =
        new FuncValueConverter<ThreatLevel, IBrush>(level => level switch
        {
            ThreatLevel.Malicious => Brush.Parse("#ff2a55"),
            ThreatLevel.Suspicious => Brush.Parse("#ff9800"),
            ThreatLevel.Clean => Brush.Parse("#8c9ba5"),
            _ => Brush.Parse("#8c9ba5")
        });

    public static readonly IValueConverter BoolToConnectionBrush =
        new FuncValueConverter<bool, IBrush>(connected => connected
            ? Brush.Parse("#00ff88")
            : Brush.Parse("#8c9ba5"));

    public static readonly IValueConverter BoolToDangerBrush =
        new FuncValueConverter<bool, IBrush>(danger => danger
            ? Brush.Parse("#ff2a55")
            : Brush.Parse("#23324d"));

    public static readonly IValueConverter BoolToDangerThickness =
        new FuncValueConverter<bool, Thickness>(danger => danger
            ? new Thickness(2)
            : new Thickness(1));

    public static readonly IValueConverter BoolToRunningBrush =
        new FuncValueConverter<bool, IBrush>(running => running
            ? Brush.Parse("#00ff88")
            : Brush.Parse("#8c9ba5"));

    public static readonly IValueConverter CategoryToBrush =
        new FuncValueConverter<string, IBrush>(cat => (cat ?? string.Empty).ToLowerInvariant() switch
        {
            "injection" => Brush.Parse("#ff2a55"),
            "file" => Brush.Parse("#00e5ff"),
            "registry" => Brush.Parse("#ff9800"),
            "network" => Brush.Parse("#00ff88"),
            "process" => Brush.Parse("#bb86fc"),
            _ => Brush.Parse("#8c9ba5")
        });

    public static readonly IValueConverter BytesToReadable =
        new FuncValueConverter<long, string>(bytes =>
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{(bytes / 1024.0):F1} KB";
            return $"{(bytes / (1024.0 * 1024.0)):F2} MB";
        });

    public static readonly IValueConverter BooleanToVisibility =
        new FuncValueConverter<bool, bool>(b => b);

    public static readonly IValueConverter InverseBoolean =
        new FuncValueConverter<bool, bool>(b => !b);
}
