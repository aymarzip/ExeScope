using Avalonia;
using Avalonia.Media;
using ExeScope.Contracts.Threat;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Collectors;
using ExeScope.Engine.Session;
using ExeScope.Engine.Tracking;
using ExeScope.GUI.Converters;
using ExeScope.GUI.Models;
using Xunit;

namespace ExeScope.Tests;

public class SanitizerRegressionTests : IDisposable
{
    private readonly string _tempDir;
    private readonly DiagnosticLogger _logger = new();

    public SanitizerRegressionTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"ExeScope_SanitizerTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, true);
            }
        }
        catch
        {
        }
    }

    [Fact]
    public void ProcessTreeItem_NotifiesPropertyChangesDynamically()
    {
        var item = new ProcessTreeItem
        {
            ProcessId = 1234,
            ImageName = "target.exe"
        };

        var changedProps = new List<string>();
        item.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName != null)
                changedProps.Add(e.PropertyName);
        };

        Assert.True(item.IsRunning);
        Assert.Equal("RUNNING", item.StatusText);

        item.IsInjectionTarget = true;
        Assert.Contains(nameof(ProcessTreeItem.IsInjectionTarget), changedProps);

        item.InjectedByPid = 999;
        Assert.Contains(nameof(ProcessTreeItem.InjectedByPid), changedProps);

        item.AddInjectedModule("C:\\temp\\evil.dll");
        Assert.Contains(nameof(ProcessTreeItem.InjectedModulesSummary), changedProps);
        Assert.Equal("C:\\temp\\evil.dll", item.InjectedModulesSummary);

        item.ExitTimeUtc = DateTime.UtcNow;
        Assert.Contains(nameof(ProcessTreeItem.ExitTimeUtc), changedProps);
        Assert.Contains(nameof(ProcessTreeItem.IsRunning), changedProps);
        Assert.False(item.IsRunning);

        item.ExitCode = 1;
        Assert.Contains(nameof(ProcessTreeItem.ExitCode), changedProps);
        Assert.Contains(nameof(ProcessTreeItem.StatusText), changedProps);
        Assert.Equal("EXITED (1)", item.StatusText);
    }

    [Fact]
    public void UiConverters_BooleanConverters_ProduceExpectedValues()
    {
        var connTrue = UiConverters.BoolToConnectionBrush.Convert(true, typeof(IBrush), null, System.Globalization.CultureInfo.InvariantCulture);
        var connFalse = UiConverters.BoolToConnectionBrush.Convert(false, typeof(IBrush), null, System.Globalization.CultureInfo.InvariantCulture);

        Assert.NotNull(connTrue);
        Assert.NotNull(connFalse);
        Assert.NotEqual(connTrue, connFalse);

        var dangerTrue = UiConverters.BoolToDangerBrush.Convert(true, typeof(IBrush), null, System.Globalization.CultureInfo.InvariantCulture);
        var dangerFalse = UiConverters.BoolToDangerBrush.Convert(false, typeof(IBrush), null, System.Globalization.CultureInfo.InvariantCulture);

        Assert.NotNull(dangerTrue);
        Assert.NotNull(dangerFalse);
        Assert.NotEqual(dangerTrue, dangerFalse);

        var thickTrue = (Thickness)UiConverters.BoolToDangerThickness.Convert(true, typeof(Thickness), null, System.Globalization.CultureInfo.InvariantCulture)!;
        var thickFalse = (Thickness)UiConverters.BoolToDangerThickness.Convert(false, typeof(Thickness), null, System.Globalization.CultureInfo.InvariantCulture)!;

        Assert.True(thickTrue.Left > thickFalse.Left);

        var runTrue = UiConverters.BoolToRunningBrush.Convert(true, typeof(IBrush), null, System.Globalization.CultureInfo.InvariantCulture);
        var runFalse = UiConverters.BoolToRunningBrush.Convert(false, typeof(IBrush), null, System.Globalization.CultureInfo.InvariantCulture);

        Assert.NotNull(runTrue);
        Assert.NotNull(runFalse);
        Assert.NotEqual(runTrue, runFalse);
    }

    [Fact]
    public void ProcessCorrelationEngine_HandlesCircularHierarchyGracefully()
    {
        var targetExe = new TargetExeInfo
        {
            OriginalPath = @"C:\Sandbox\root.exe",
            CanonicalPath = @"C:\Sandbox\root.exe",
            FileName = "root.exe",
            Sha256 = "dummy"
        };
        var engine = new ProcessCorrelationEngine(targetExe, _logger);
        var now = DateTime.UtcNow;

        engine.TryRegisterProcess(1000, 500, @"C:\Sandbox\root.exe", "root.exe", now, out _);
        engine.TryRegisterProcess(2000, 1000, @"C:\Sandbox\child1.exe", "child1.exe", now.AddSeconds(1), out _);
        engine.TryRegisterProcess(3000, 2000, @"C:\Sandbox\child2.exe", "child2.exe", now.AddSeconds(2), out _);

        var root = engine.GetAllTrackedProcesses().First(p => p.ProcessId == 1000);
        var child2 = engine.GetAllTrackedProcesses().First(p => p.ProcessId == 3000);

        // Artificially inject an adversarial circular reference
        child2.Children.Add(root);

        // BuildProcessTree must not throw StackOverflowException
        var tree = engine.BuildProcessTree();
        Assert.NotNull(tree);
        Assert.Equal(1000, tree.ProcessId);
    }

    [Fact]
    public async Task FileArtifactCollector_DrainsQueueOnDisposal()
    {
        var config = new SessionConfig
        {
            EnableArtifactSaving = true,
            MaxArtifactFileSizeBytes = 1024 * 1024,
            MaxTotalArtifactStorageBytes = 10 * 1024 * 1024
        };

        var testFile1 = Path.Combine(_tempDir, "sample1.txt");
        var testFile2 = Path.Combine(_tempDir, "sample2.txt");
        File.WriteAllText(testFile1, "Data 1 content");
        File.WriteAllText(testFile2, "Data 2 content");

        var collector = new FileArtifactCollector(config, _tempDir, _logger);
        collector.Start();

        collector.QueueFile(testFile1, 100, "test.exe", bypassDirectoryFilter: true);
        collector.QueueFile(testFile2, 100, "test.exe", bypassDirectoryFilter: true);

        await collector.DisposeAsync();

        Assert.Equal(2, collector.TotalSaved);
        Assert.True(collector.TotalBytesWritten > 0);
    }

    [Fact]
    public async Task AnalysisSessionManager_PreservesArtifactStatsUponStop()
    {
        var testExe = Path.Combine(_tempDir, "sample.exe");
        await File.WriteAllBytesAsync(testExe, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });

        var manager = new AnalysisSessionManager(_logger);
        manager.SetTargetExe(testExe);

        var config = new SessionConfig
        {
            TargetExePath = testExe,
            OutputDirectory = _tempDir,
            EnableArtifactSaving = true,
            EnablePacketCapture = false,
            AutoCompleteOnAllProcessesExit = false
        };
        manager.UpdateConfig(config);

        await manager.StartWaitingAsync();

        // Trigger root process launch
        bool registered = manager.CorrelationEngine!.TryRegisterProcess(5555, 1000, testExe, "sample.exe", DateTime.UtcNow, out var rootProc);
        Assert.True(registered);
        Assert.NotNull(rootProc);
        Assert.Equal(AnalysisSessionState.Recording, manager.State);

        var sampleFile = Path.Combine(_tempDir, "dropped.dll");
        await File.WriteAllTextAsync(sampleFile, "PAYLOAD");

        Assert.NotNull(manager.ArtifactCollector);
        manager.ArtifactCollector.QueueFile(sampleFile, 5555, "sample.exe", bypassDirectoryFilter: true);

        // Stop session cleanly
        await manager.StopRecordingAsync("Test finished");

        var metadata = manager.CurrentMetadata;
        Assert.NotNull(metadata);
        Assert.Equal(1, metadata.TotalArtifactsSaved);
        Assert.True(metadata.TotalArtifactBytesWritten > 0);

        await manager.DisposeAsync();
    }
}
