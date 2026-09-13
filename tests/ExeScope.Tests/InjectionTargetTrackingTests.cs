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

    [Fact]
    public void BuildProcessTree_WithRegisteredInjectionTarget_IncludesTargetInTree()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", DateTime.UtcNow, out _);
        engine.RegisterInjectionTarget(5000, @"C:\Java\javaw.exe", 1001, @"C:\Temp\cheat.dll", DateTime.UtcNow);

        var tree = engine.BuildProcessTree();
        Assert.NotNull(tree);
        Assert.Single(tree.Children);
        var targetNode = tree.Children[0];
        Assert.Equal(5000, targetNode.ProcessId);
        Assert.True(targetNode.IsInjectionTarget);
        Assert.Equal(1001, targetNode.InjectedByPid);
        Assert.Contains(@"C:\Temp\cheat.dll", targetNode.InjectedModules);
    }

    [Fact]
    public void BuildProcessTree_WithChildProcessAsInjector_AttachesTargetUnderChild()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", t0, out _);
        engine.TryRegisterProcess(2002, 1001, @"C:\Sandbox\loader.exe", "loader.exe", t0.AddSeconds(1), out _);

        engine.RegisterInjectionTarget(5000, @"C:\Java\javaw.exe", 2002, @"C:\Temp\cheat.dll", t0.AddSeconds(2));

        var tree = engine.BuildProcessTree();
        Assert.NotNull(tree);
        Assert.Single(tree.Children);
        var childNode = tree.Children[0];
        Assert.Equal(2002, childNode.ProcessId);
        Assert.Single(childNode.Children);
        var targetNode = childNode.Children[0];
        Assert.Equal(5000, targetNode.ProcessId);
        Assert.True(targetNode.IsInjectionTarget);
        Assert.Equal(2002, targetNode.InjectedByPid);
    }

    [Fact]
    public void HasActiveTrackedProcesses_WithInjectionTargetRunning_ReturnsFalseWhenRootExits()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", t0, out _);
        engine.RegisterInjectionTarget(5000, @"C:\Java\javaw.exe", 1001, @"C:\Temp\cheat.dll", t0.AddSeconds(1));

        Assert.True(engine.HasActiveTrackedProcesses());

        // Root process exits
        engine.RegisterProcessExit(1001, t0.AddSeconds(5), 0);

        // Injection target (victim) is still running in background, but tracked analyzed processes exited
        Assert.False(engine.HasActiveTrackedProcesses());
    }

    [Fact]
    public void IsProcessTracked_RespectsTrackInjectionTargetEventsFlag()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger) { TrackInjectionTargetEvents = true };
        var t0 = DateTime.UtcNow;
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", t0, out _);
        engine.RegisterInjectionTarget(5000, @"C:\Java\javaw.exe", 1001, null, t0);

        // When enabled, victim process events are tracked
        Assert.True(engine.IsProcessTracked(5000, t0, out var tracked1));
        Assert.NotNull(tracked1);
        Assert.True(tracked1.IsInjectionTarget);

        // When disabled, victim process events are ignored
        engine.TrackInjectionTargetEvents = false;
        Assert.False(engine.IsProcessTracked(5000, t0, out _));

        // Primary root process is always tracked regardless
        Assert.True(engine.IsProcessTracked(1001, t0, out _));
    }
}
