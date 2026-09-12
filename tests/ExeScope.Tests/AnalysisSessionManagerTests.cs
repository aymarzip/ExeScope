using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Session;
using ExeScope.Engine.Storage;
using Xunit;

namespace ExeScope.Tests;

public class AnalysisSessionManagerTests
{
    [Fact]
    public async Task SessionManager_ConsecutiveSessions_ResetBuffersAndStorage()
    {
        string outputBase = Path.Combine(Path.GetTempPath(), $"ExeScope_Consecutive_{Guid.NewGuid():N}");
        string dummyExe = Path.Combine(outputBase, "sample.exe");

        try
        {
            Directory.CreateDirectory(outputBase);
            await File.WriteAllBytesAsync(dummyExe, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });

            var logger = new DiagnosticLogger();
            var manager = new AnalysisSessionManager(logger);

            manager.SetTargetExe(dummyExe);

            var config = new SessionConfig
            {
                TargetExePath = dummyExe,
                OutputDirectory = outputBase,
                EnableArtifactSaving = false,
                EnablePacketCapture = false,
                AutoCompleteOnAllProcessesExit = false
            };
            manager.UpdateConfig(config);

            // Session 1: Start and stop
            await manager.StartWaitingAsync();
            Assert.Equal(AnalysisSessionState.WaitingForLaunch, manager.State);

            await manager.StopRecordingAsync("Test finished session 1");
            Assert.Equal(AnalysisSessionState.Completed, manager.State);

            // Session 2: Start waiting again
            await manager.StartWaitingAsync();
            Assert.Equal(AnalysisSessionState.WaitingForLaunch, manager.State);
            Assert.Equal(0, manager.TotalEventsRecorded);

            await manager.StopRecordingAsync("Test finished session 2");
            Assert.Equal(AnalysisSessionState.Completed, manager.State);

            await manager.DisposeAsync();
        }
        finally
        {
            try { if (Directory.Exists(outputBase)) Directory.Delete(outputBase, true); } catch { }
        }
    }
}
