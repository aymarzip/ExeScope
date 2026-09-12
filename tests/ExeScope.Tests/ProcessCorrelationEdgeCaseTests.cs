using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Tracking;
using Xunit;

namespace ExeScope.Tests;

public class ProcessCorrelationEdgeCaseTests
{
    private readonly TargetExeInfo _targetExe = new()
    {
        OriginalPath = @"C:\Sandbox\app.exe",
        CanonicalPath = @"C:\Sandbox\app.exe",
        FileName = "app.exe",
        Sha256 = "1234567890abcdef"
    };

    private readonly DiagnosticLogger _logger = new();

    [Fact]
    public void ProcessCorrelation_HandlesDeepProcessHierarchy()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;

        // Root
        Assert.True(engine.TryRegisterProcess(1000, 500, @"C:\Sandbox\app.exe", "app.exe", t0, out var root));
        Assert.NotNull(root);

        // Spawn 8 levels of descendants: 1001 spawned by 1000, 1002 spawned by 1001, etc.
        int currentParent = 1000;
        for (int depth = 1; depth <= 8; depth++)
        {
            int currentPid = 1000 + depth;
            var tSpawn = t0.AddMilliseconds(depth * 50);

            bool ok = engine.TryRegisterProcess(currentPid, currentParent, $@"C:\Tools\sub_{depth}.exe", $"sub_{depth}.exe", tSpawn, out var child);
            Assert.True(ok);
            Assert.NotNull(child);
            Assert.Equal(currentParent, child.ParentProcessId);
            Assert.Equal(currentPid, child.ProcessId);

            currentParent = currentPid;
        }

        var tree = engine.BuildProcessTree();
        Assert.NotNull(tree);

        // Walk tree to verify 8 levels of depth
        int verifiedDepth = 0;
        var node = tree;
        while (node.Children.Count > 0)
        {
            verifiedDepth++;
            node = node.Children[0];
        }

        Assert.Equal(8, verifiedDepth);
    }

    [Fact]
    public void ProcessCorrelation_ChildSpawnsDescendant_EvenAfterRootExited()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;

        // Root starts
        engine.TryRegisterProcess(1000, 500, @"C:\Sandbox\app.exe", "app.exe", t0, out _);

        // Child starts
        var t1 = t0.AddSeconds(1);
        engine.TryRegisterProcess(2000, 1000, @"C:\Sandbox\worker.exe", "worker.exe", t1, out _);

        // Root exits at t0 + 2s
        engine.RegisterProcessExit(1000, t0.AddSeconds(2), exitCode: 0);

        // Worker (child) is still alive and spawns grandchild at t0 + 3s
        var t3 = t0.AddSeconds(3);
        bool grandchildRegistered = engine.TryRegisterProcess(3000, 2000, @"C:\Sandbox\subworker.exe", "subworker.exe", t3, out var grandchild);

        Assert.True(grandchildRegistered);
        Assert.NotNull(grandchild);
        Assert.Equal(3000, grandchild.ProcessId);
        Assert.Equal(2000, grandchild.ParentProcessId);

        // Both child and grandchild are tracked
        Assert.True(engine.IsProcessTracked(2000, t3, out _));
        Assert.True(engine.IsProcessTracked(3000, t3, out _));
    }

    [Fact]
    public void ProcessCorrelation_RegisterModuleLoaded_TracksModulesPerProcess()
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        var t0 = DateTime.UtcNow;

        engine.TryRegisterProcess(1000, 500, @"C:\Sandbox\app.exe", "app.exe", t0, out _);

        engine.RegisterModuleLoaded(1000, @"C:\Windows\System32\kernel32.dll", t0.AddMilliseconds(10));
        engine.RegisterModuleLoaded(1000, @"C:\Windows\System32\ntdll.dll", t0.AddMilliseconds(20));

        var tree = engine.BuildProcessTree();
        Assert.NotNull(tree);
        Assert.Contains(@"C:\Windows\System32\kernel32.dll", tree.LoadedModules);
        Assert.Contains(@"C:\Windows\System32\ntdll.dll", tree.LoadedModules);
    }
}
