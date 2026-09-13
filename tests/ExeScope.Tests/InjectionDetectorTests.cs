using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Detection;
using ExeScope.Engine.Tracking;
using Xunit;

namespace ExeScope.Tests;

public class InjectionDetectorTests
{
    private readonly TargetExeInfo _targetExe = new()
    {
        OriginalPath = @"C:\Sandbox\cheat.exe",
        CanonicalPath = @"C:\Sandbox\cheat.exe",
        FileName = "cheat.exe",
        Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    };

    private readonly DiagnosticLogger _logger = new();

    private ProcessCorrelationEngine CreateEngineWithRoot(out int rootPid)
    {
        var engine = new ProcessCorrelationEngine(_targetExe, _logger);
        rootPid = 1001;
        engine.TryRegisterProcess(rootPid, 500, @"C:\Sandbox\cheat.exe", "cheat.exe", DateTime.UtcNow, out _);
        return engine;
    }

    [Fact]
    public void DllWrittenByTarget_LoadedInExternalProcess_DetectsInjection()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: true);

        var events = new List<InjectionEvent>();
        detector.InjectionDetected += evt => events.Add(evt);

        var t0 = DateTime.UtcNow;
        string dllPath = @"C:\Users\test\AppData\Local\Temp\payload.dll";

        detector.OnFileWriteByTrackedProcess(rootPid, dllPath, t0);
        detector.OnImageLoadInAnyProcess(5000, dllPath, 0x7FF00000, 65536, t0.AddMilliseconds(200));

        Assert.Single(events);
        Assert.Equal(InjectionTechnique.DllInjection, events[0].Technique);
        Assert.Equal(rootPid, events[0].SourceProcessId);
        Assert.Equal(5000, events[0].TargetProcessId);
        Assert.Equal(dllPath, events[0].InjectedModulePath);

        detector.Dispose();
    }

    [Fact]
    public void DllWrittenLongAgo_NotCorrelated()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: false);

        var events = new List<InjectionEvent>();
        detector.InjectionDetected += evt => events.Add(evt);

        var t0 = DateTime.UtcNow.AddMinutes(-5);
        string dllPath = @"C:\Users\test\old_payload.dll";

        detector.OnFileWriteByTrackedProcess(rootPid, dllPath, t0);
        detector.OnImageLoadInAnyProcess(5000, dllPath, 0x7FF00000, 65536, DateTime.UtcNow);

        Assert.Empty(events);

        detector.Dispose();
    }

    [Fact]
    public void SystemDll_NotFlagged()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: false);

        var events = new List<InjectionEvent>();
        detector.InjectionDetected += evt => events.Add(evt);

        detector.OnImageLoadInAnyProcess(5000, @"C:\Windows\System32\ntdll.dll", 0x7FF00000, 65536, DateTime.UtcNow);
        detector.OnImageLoadInAnyProcess(5000, @"C:\Windows\SysWOW64\kernel32.dll", 0x7FF10000, 65536, DateTime.UtcNow);

        Assert.Empty(events);

        detector.Dispose();
    }

    [Fact]
    public void NonDllFileWrite_Ignored()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: false);

        var events = new List<InjectionEvent>();
        detector.InjectionDetected += evt => events.Add(evt);

        var t0 = DateTime.UtcNow;
        detector.OnFileWriteByTrackedProcess(rootPid, @"C:\Temp\readme.txt", t0);
        detector.OnImageLoadInAnyProcess(5000, @"C:\Temp\readme.txt", 0x7FF00000, 65536, t0.AddMilliseconds(100));

        Assert.Empty(events);

        detector.Dispose();
    }

    [Fact]
    public void ImageLoadInTrackedProcess_NotTreatedAsInjection()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: false);

        var events = new List<InjectionEvent>();
        detector.InjectionDetected += evt => events.Add(evt);

        var t0 = DateTime.UtcNow;
        string dllPath = @"C:\Sandbox\helper.dll";

        detector.OnFileWriteByTrackedProcess(rootPid, dllPath, t0);
        detector.OnImageLoadInAnyProcess(rootPid, dllPath, 0x7FF00000, 65536, t0.AddMilliseconds(100));

        Assert.Empty(events);

        detector.Dispose();
    }

    [Fact]
    public void TrackTargetEvents_RegistersInjectionTarget()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: true);

        TrackedProcess? registered = null;
        engine.OnInjectionTargetRegistered += proc => registered = proc;

        var t0 = DateTime.UtcNow;
        string dllPath = @"C:\Users\test\payload.dll";

        detector.OnFileWriteByTrackedProcess(rootPid, dllPath, t0);
        detector.OnImageLoadInAnyProcess(5000, dllPath, 0x7FF00000, 65536, t0.AddMilliseconds(100));

        Assert.NotNull(registered);
        Assert.Equal(5000, registered.ProcessId);
        Assert.True(registered.IsInjectionTarget);
        Assert.Equal(rootPid, registered.InjectedByPid);
        Assert.Contains(dllPath, registered.InjectedModules);

        Assert.True(engine.IsInjectionTarget(5000));

        detector.Dispose();
    }

    [Fact]
    public void TrackTargetEvents_Disabled_NoInjectionTargetRegistered()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: false);

        TrackedProcess? registered = null;
        engine.OnInjectionTargetRegistered += proc => registered = proc;

        var t0 = DateTime.UtcNow;
        string dllPath = @"C:\Users\test\payload.dll";

        detector.OnFileWriteByTrackedProcess(rootPid, dllPath, t0);
        detector.OnImageLoadInAnyProcess(5000, dllPath, 0x7FF00000, 65536, t0.AddMilliseconds(100));

        Assert.Null(registered);
        Assert.False(engine.IsInjectionTarget(5000));

        detector.Dispose();
    }

    [Fact]
    public void ProcessHandleOpened_FromTrackedToExternal_MarksTarget()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: true);

        TrackedProcess? registered = null;
        engine.OnInjectionTargetRegistered += proc => registered = proc;

        detector.OnProcessHandleOpened(rootPid, 5000, DateTime.UtcNow);

        Assert.NotNull(registered);
        Assert.True(engine.IsInjectionTarget(5000));

        detector.Dispose();
    }

    [Fact]
    public void ProcessHandleOpened_BetweenTrackedProcesses_Ignored()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var t0 = DateTime.UtcNow;
        engine.TryRegisterProcess(2002, rootPid, @"C:\Sandbox\helper.exe", "helper.exe", t0.AddSeconds(1), out _);

        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: true);

        TrackedProcess? registered = null;
        engine.OnInjectionTargetRegistered += proc => registered = proc;

        detector.OnProcessHandleOpened(rootPid, 2002, t0.AddSeconds(2));

        Assert.Null(registered);

        detector.Dispose();
    }

    [Fact]
    public void MultipleDllInjections_AllDetected()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: true);

        var events = new List<InjectionEvent>();
        detector.InjectionDetected += evt => events.Add(evt);

        var t0 = DateTime.UtcNow;

        detector.OnFileWriteByTrackedProcess(rootPid, @"C:\Temp\first.dll", t0);
        detector.OnImageLoadInAnyProcess(5000, @"C:\Temp\first.dll", 0x7FF00000, 65536, t0.AddMilliseconds(100));

        detector.OnFileWriteByTrackedProcess(rootPid, @"C:\Temp\second.dll", t0.AddSeconds(1));
        detector.OnImageLoadInAnyProcess(6000, @"C:\Temp\second.dll", 0x7FF00000, 65536, t0.AddSeconds(1).AddMilliseconds(200));

        Assert.Equal(2, events.Count);
        Assert.Equal(5000, events[0].TargetProcessId);
        Assert.Equal(6000, events[1].TargetProcessId);

        detector.Dispose();
    }

    [Fact]
    public void SubsequentModuleLoadInConfirmedTarget_Detected()
    {
        var engine = CreateEngineWithRoot(out int rootPid);
        var detector = new InjectionDetector(engine, _logger, trackTargetEvents: false);

        var events = new List<InjectionEvent>();
        detector.InjectionDetected += evt => events.Add(evt);

        var t0 = DateTime.UtcNow;
        string dllPath = @"C:\Temp\payload.dll";

        detector.OnFileWriteByTrackedProcess(rootPid, dllPath, t0);
        detector.OnImageLoadInAnyProcess(5000, dllPath, 0x7FF00000, 65536, t0.AddMilliseconds(100));

        detector.OnImageLoadInAnyProcess(5000, @"C:\Temp\extra_module.dll", 0x7FF20000, 32768, t0.AddSeconds(2));

        Assert.Equal(2, events.Count);
        Assert.Equal(InjectionTechnique.DllInjection, events[0].Technique);
        Assert.Equal(InjectionTechnique.Unknown, events[1].Technique);

        detector.Dispose();
    }
}
