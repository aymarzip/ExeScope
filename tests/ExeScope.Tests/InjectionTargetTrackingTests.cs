using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Tracking;
using Xunit;

namespace ExeScope.Tests;

public class InjectionTargetTrackingTests
{
    private readonly TargetExeInfo _targetExe = new()
    {
        OriginalPath = @"C:\Sandbox\sample.exe",
        CanonicalPath = @"C:\Sandbox\sample.exe",
        FileName = "sample.exe",
        Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };

    private readonly DiagnosticLogger _logger = new();

    [Fact]
    public void RegisterInjectionTarget_AddsToTracking()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", DateTime.UtcNow, out _);

        engine.RegisterInjectionTarget(5000, @"C:\Java\java.exe", 1001, @"C:\Temp\hook.dll", DateTime.UtcNow);

        Assert.True(engine.IsInjectionTarget(5000));
        var targets = engine.GetInjectionTargets();
        Assert.Single(targets);
        Assert.Equal(5000, targets[0].ProcessId);
        Assert.True(targets[0].IsInjectionTarget);
        Assert.Equal(1001, targets[0].InjectedByPid);
        Assert.Contains(@"C:\Temp\hook.dll", targets[0].InjectedModules);
    }

    [Fact]
    public void RegisterInjectionTarget_DuplicatePid_AddsModule()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", DateTime.UtcNow, out _);

        engine.RegisterInjectionTarget(5000, @"C:\Java\java.exe", 1001, @"C:\Temp\hook1.dll", DateTime.UtcNow);
        engine.RegisterInjectionTarget(5000, @"C:\Java\java.exe", 1001, @"C:\Temp\hook2.dll", DateTime.UtcNow);

        var targets = engine.GetInjectionTargets();
        Assert.Single(targets);
        Assert.Equal(2, targets[0].InjectedModules.Count);
    }

    [Fact]
    public void IsProcessTrackedOrInjectionTarget_FindsInjectionTarget()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", DateTime.UtcNow, out _);

        engine.RegisterInjectionTarget(5000, @"C:\Java\java.exe", 1001, null, DateTime.UtcNow);

        bool found = engine.IsProcessTrackedOrInjectionTarget(5000, DateTime.UtcNow, out var tracked);
        Assert.True(found);
        Assert.NotNull(tracked);
        Assert.True(tracked.IsInjectionTarget);
    }

    [Fact]
    public void IsProcessTrackedOrInjectionTarget_FindsTrackedProcess()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", DateTime.UtcNow, out _);

        bool found = engine.IsProcessTrackedOrInjectionTarget(1001, DateTime.UtcNow, out var tracked);
        Assert.True(found);
        Assert.NotNull(tracked);
        Assert.True(tracked.IsRoot);
    }

    [Fact]
    public void IsProcessTrackedOrInjectionTarget_UnknownPid_ReturnsFalse()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", DateTime.UtcNow, out _);

        bool found = engine.IsProcessTrackedOrInjectionTarget(9999, DateTime.UtcNow, out var tracked);
        Assert.False(found);
        Assert.Null(tracked);
    }

    [Fact]
    public void BuildProcessTree_IncludesInjectionTargetFields()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", DateTime.UtcNow, out _);

        var tree = engine.BuildProcessTree();
        Assert.NotNull(tree);
        Assert.False(tree.IsInjectionTarget);
        Assert.Null(tree.InjectedByPid);
        Assert.Empty(tree.InjectedModules);
    }

    [Fact]
    public void OnInjectionTargetRegistered_EventFires()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", DateTime.UtcNow, out _);

        TrackedProcess? fired = null;
        engine.OnInjectionTargetRegistered += proc => fired = proc;

        engine.RegisterInjectionTarget(5000, @"C:\Java\java.exe", 1001, null, DateTime.UtcNow);

        Assert.NotNull(fired);
        Assert.Equal(5000, fired.ProcessId);
    }

    [Fact]
    public void RegisterInjectionTarget_NullModule_NoModulesAdded()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", DateTime.UtcNow, out _);

        engine.RegisterInjectionTarget(5000, @"C:\Java\java.exe", 1001, null, DateTime.UtcNow);

        var targets = engine.GetInjectionTargets();
        Assert.Empty(targets[0].InjectedModules);
    }
}
