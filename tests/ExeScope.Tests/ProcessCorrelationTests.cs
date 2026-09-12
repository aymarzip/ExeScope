using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Tracking;
using Xunit;

namespace ExeScope.Tests;

public class ProcessCorrelationTests
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
    public void RegisterRootProcess_MatchesCanonicalPath_BecomesRoot()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var startTime = DateTime.UtcNow;

        bool registered = engine.TryRegisterProcess(1001, 500, @"c:\sandbox\SAMPLE.EXE", "sample.exe --arg", startTime, out var proc);

        Assert.True(registered);
        Assert.NotNull(proc);
        Assert.True(proc.IsRoot);
        Assert.Equal(1001, proc.ProcessId);
        Assert.True(engine.HasRootLaunched);
    }

    [Fact]
    public void RegisterChildProcess_WhenParentIsTracked_TracksChild()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", t0, out _);

        var t1 = t0.AddSeconds(1);
        bool childRegistered = engine.TryRegisterProcess(2002, 1001, @"C:\Windows\System32\cmd.exe", "cmd.exe /c echo hi", t1, out var child);

        Assert.True(childRegistered);
        Assert.NotNull(child);
        Assert.False(child.IsRoot);
        Assert.Equal(2002, child.ProcessId);
        Assert.Equal(1001, child.ParentProcessId);

        // Verify grandchild
        var t2 = t1.AddSeconds(1);
        bool grandChildRegistered = engine.TryRegisterProcess(3003, 2002, @"C:\Windows\System32\conhost.exe", "conhost.exe", t2, out var grandChild);

        Assert.True(grandChildRegistered);
        Assert.NotNull(grandChild);
        Assert.Equal(3003, grandChild.ProcessId);
        Assert.Equal(2002, grandChild.ParentProcessId);
    }

    [Fact]
    public void RepeatedLaunch_DetectedSeparately_DoesNotOverwriteActiveSession()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", t0, out _);

        bool repeatedFired = false;
        engine.OnRepeatedLaunchDetected += p =>
        {
            repeatedFired = true;
            Assert.Equal(4004, p.ProcessId);
        };

        var t1 = t0.AddSeconds(5);
        bool secondaryRegistered = engine.TryRegisterProcess(4004, 500, @"C:\Sandbox\sample.exe", "sample.exe", t1, out var secondary);

        Assert.False(secondaryRegistered); // Handled as separate launch
        Assert.Null(secondary);
        Assert.True(repeatedFired);
    }

    [Fact]
    public void PidRecyclingProtection_EventAfterExit_DoesNotMatchDeadProcess()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", t0, out _);

        var tExit = t0.AddSeconds(2);
        engine.RegisterProcessExit(1001, tExit, exitCode: 0);

        // At t0 + 10s, another process reuses PID 1001
        var tLater = t0.AddSeconds(10);
        bool isTracked = engine.IsProcessTracked(1001, tLater, out var proc);

        Assert.False(isTracked);
        Assert.Null(proc);
    }

    [Fact]
    public void AllTrackedProcessesExited_OnlyFiresWhenChildrenAlsoExit()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", t0, out _);

        var t1 = t0.AddSeconds(1);
        engine.TryRegisterProcess(2002, 1001, @"C:\Windows\System32\cmd.exe", "cmd.exe", t1, out _);

        bool allExitedFired = false;
        engine.OnAllTrackedProcessesExited += () => allExitedFired = true;

        // Root exits first
        engine.RegisterProcessExit(1001, t0.AddSeconds(2), 0);
        Assert.False(allExitedFired);
        Assert.True(engine.HasActiveTrackedProcesses()); // Child is still alive!

        // Child exits
        engine.RegisterProcessExit(2002, t0.AddSeconds(4), 0);
        Assert.True(allExitedFired);
        Assert.False(engine.HasActiveTrackedProcesses());
    }

    [Fact]
    public void RegisterChildProcess_WhenChildIsSameExecutable_TracksAsChildNotRepeatedLaunch()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;
        engine.TryRegisterProcess(1001, 500, @"C:\Sandbox\sample.exe", "sample.exe", t0, out var root);

        bool repeatedFired = false;
        engine.OnRepeatedLaunchDetected += _ => repeatedFired = true;

        var t1 = t0.AddSeconds(1);
        // Child process launched by root (parent 1001), running same EXE with arguments
        bool childRegistered = engine.TryRegisterProcess(2002, 1001, @"C:\Sandbox\sample.exe", "sample.exe --child", t1, out var child);

        Assert.True(childRegistered);
        Assert.NotNull(child);
        Assert.False(child.IsRoot);
        Assert.Equal(2002, child.ProcessId);
        Assert.Equal(1001, child.ParentProcessId);
        Assert.False(repeatedFired);

        var tree = engine.BuildProcessTree();
        Assert.NotNull(tree);
        Assert.Single(tree.Children);
        Assert.Equal(2002, tree.Children[0].ProcessId);
    }
}

