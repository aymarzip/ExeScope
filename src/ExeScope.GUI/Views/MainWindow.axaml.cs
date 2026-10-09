using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using ExeScope.GUI.ViewModels;

namespace ExeScope.GUI.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private async void OnSelectTargetClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel vm) return;

        var storageProvider = StorageProvider;
        var files = await storageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select Executable to Analyze",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Windows Executables (*.exe; *.dll)")
                {
                    Patterns = new[] { "*.exe", "*.dll" }
                },
                new FilePickerFileType("All Files (*.*)")
                {
                    Patterns = new[] { "*.*" }
                }
            }
        });

        if (files.Count > 0)
        {
            var selectedPath = files[0].Path.LocalPath;
            vm.TargetExePath = selectedPath;
        }
    }

    private void OnCategoryFilterClick(object? sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string category && DataContext is MainViewModel vm)
        {
            vm.SelectedCategory = category;
        }
    }
}
