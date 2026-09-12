using System.Text.Json;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Core.Utilities;
using ExeScope.Engine.Session;
using ExeScope.Engine.Storage;
using Xunit;

namespace ExeScope.Tests;

public class EndToEndSessionTests
{
    [Fact]
    public async Task SessionLifecycle_ProducesAllRequiredFiles_AndValidOutput()
    {
        string outputBase = Path.Combine(Path.GetTempPath(), $"ExeScope_E2E_{Guid.NewGuid():N}");
        string dummyExe = Path.Combine(outputBase, "test_sample.exe");

        try
        {
            Directory.CreateDirectory(outputBase);
            await File.WriteAllBytesAsync(dummyExe, new byte[] { 0x4D, 0x5A, 0x90, 0x00 }); // MZ header

            var logger = new DiagnosticLogger();
            var manager = new AnalysisSessionManager(logger);

            manager.SetTargetExe(dummyExe);
            var targetInfo = manager.TargetExe;
            Assert.NotNull(targetInfo);
            Assert.False(string.IsNullOrEmpty(targetInfo.Sha256));
            Assert.Equal("test_sample.exe", targetInfo.FileName);

            var config = new SessionConfig
            {
                TargetExePath = dummyExe,
                OutputDirectory = outputBase,
                EnableArtifactSaving = true,
                MaxArtifactFileSizeBytes = 10 * 1024 * 1024,
                MaxTotalArtifactStorageBytes = 50 * 1024 * 1024,
                EnablePacketCapture = false,
                AutoCompleteOnAllProcessesExit = false
            };
            manager.UpdateConfig(config);

            await manager.StartWaitingAsync();
            Assert.Equal(AnalysisSessionState.WaitingForLaunch, manager.State);

            var startTime = DateTime.UtcNow;
            int rootPid = 9999;
            int childPid = 10001;

            var storage = new FileSessionStorage(outputBase, rootPid, logger);
            string sessionDir = storage.SessionDirectory;

            // Check session folder structure requirements
            Assert.True(Directory.Exists(sessionDir));
            string artifactsDir = Path.Combine(sessionDir, "artifacts");
            Directory.CreateDirectory(artifactsDir);

            // Write sample artifacts-index.jsonl
            string artifactsIndexPath = Path.Combine(sessionDir, "artifacts-index.jsonl");
            await File.WriteAllTextAsync(artifactsIndexPath, "");

            // Save sample metadata
            var metadata = new SessionMetadata
            {
                SessionId = Path.GetFileName(sessionDir),
                SessionDirectory = sessionDir,
                TargetExe = targetInfo,
                Config = config,
                SessionCreatedUtc = startTime,
                TargetLaunchDetectedUtc = startTime,
                RootProcessId = rootPid,
                IsElevated = false
            };
            storage.SaveSessionMetadata(metadata);

            // Enqueue events (Process, File, Registry, Network)
            storage.EnqueueEvent(new ProcessEvent
            {
                EventId = 1,
                TimestampUtc = startTime,
                ProcessId = rootPid,
                ProcessImage = "test_sample.exe",
                EventType = ProcessEventType.Started,
                CommandLine = "test_sample.exe --arg1",
                Summary = "Process started: test_sample.exe"
            });

            storage.EnqueueEvent(new FileEvent
            {
                EventId = 2,
                TimestampUtc = startTime.AddMilliseconds(10),
                ProcessId = rootPid,
                ProcessImage = "test_sample.exe",
                Operation = FileOperationType.Create,
                Path = @"C:\Temp\sample_out.txt",
                Result = "SUCCESS",
                Summary = "File Create: C:\\Temp\\sample_out.txt (SUCCESS)"
            });

            storage.EnqueueEvent(new RegistryEvent
            {
                EventId = 3,
                TimestampUtc = startTime.AddMilliseconds(20),
                ProcessId = rootPid,
                ProcessImage = "test_sample.exe",
                Operation = RegistryOperationType.SetValue,
                KeyPath = @"HKCU\Software\TestKey",
                ValueName = "Config",
                Result = "SUCCESS",
                Summary = "Registry SetValue: HKCU\\Software\\TestKey\\Config"
            });

            storage.EnqueueEvent(new NetworkEvent
            {
                EventId = 4,
                TimestampUtc = startTime.AddMilliseconds(30),
                ProcessId = rootPid,
                ProcessImage = "test_sample.exe",
                Protocol = NetworkProtocol.TCP,
                Direction = NetworkDirection.Outbound,
                LocalAddress = "127.0.0.1",
                LocalPort = 55123,
                RemoteAddress = "127.0.0.1",
                RemotePort = 8080,
                CorrelationMethod = NetworkCorrelationMethod.ExactPidMatch,
                Confidence = "High",
                Summary = "TCP connection: 127.0.0.1:55123 -> 127.0.0.1:8080"
            });

            // Save process tree
            var rootNode = new ProcessNode
            {
                ProcessId = rootPid,
                ImageName = "test_sample.exe",
                ImagePath = dummyExe,
                CommandLine = "test_sample.exe --arg1",
                StartTimeUtc = startTime,
                IsRoot = true,
                Children = new List<ProcessNode>
                {
                    new ProcessNode
                    {
                        ProcessId = childPid,
                        ParentProcessId = rootPid,
                        ImageName = "test_sample.exe",
                        ImagePath = dummyExe,
                        CommandLine = "test_sample.exe --child",
                        StartTimeUtc = startTime.AddMilliseconds(50),
                        IsRoot = false
                    }
                }
            };
            storage.SaveProcessTree(rootNode);

            // Flush storage
            await storage.FlushAsync();
            await storage.DisposeAsync();

            // Generate report in session folder
            var reportGen = new ExeScope.Engine.Reporting.HtmlReportGenerator();
            var allEvents = storage.ReadRecordedEvents();
            var diagnostics = logger.Entries.ToList();
            string html = ExeScope.Engine.Reporting.HtmlReportGenerator.GenerateReport(
                metadata, rootNode, allEvents, new List<ArtifactRecord>(), diagnostics);
            string reportPath = Path.Combine(sessionDir, "report.html");
            await File.WriteAllTextAsync(reportPath, html);

            string sessionJsonPath = Path.Combine(sessionDir, "session.json");
            string eventsJsonlPath = Path.Combine(sessionDir, "events.jsonl");
            string processTreePath = Path.Combine(sessionDir, "process-tree.json");
            string diagLogPath = Path.Combine(sessionDir, "diagnostics.log");

            Assert.True(File.Exists(sessionJsonPath), "session.json must exist");
            Assert.True(File.Exists(eventsJsonlPath), "events.jsonl must exist");
            Assert.True(File.Exists(processTreePath), "process-tree.json must exist");
            Assert.True(File.Exists(reportPath), "report.html must exist");
            Assert.True(File.Exists(artifactsIndexPath), "artifacts-index.jsonl must exist");
            Assert.True(Directory.Exists(artifactsDir), "artifacts/ directory must exist");

            // Verify session.json content
            string sessionJson = await File.ReadAllTextAsync(sessionJsonPath);
            Assert.Contains("test_sample.exe", sessionJson);
            Assert.Contains(targetInfo.Sha256, sessionJson);

            // Verify events.jsonl has 4 lines
            string[] eventLines = await File.ReadAllLinesAsync(eventsJsonlPath);
            Assert.Equal(4, eventLines.Length);

            // Verify process-tree.json contains both root and child
            string processTreeJson = await File.ReadAllTextAsync(processTreePath);
            Assert.Contains(rootPid.ToString(), processTreeJson);
            Assert.Contains(childPid.ToString(), processTreeJson);

            // Verify report.html contains report sections
            string reportHtml = await File.ReadAllTextAsync(reportPath);
            Assert.Contains("ExeScope", reportHtml);
            Assert.Contains("Process Tree", reportHtml);
            Assert.Contains("File Events", reportHtml);
            Assert.Contains("Registry Events", reportHtml);
            Assert.Contains("Network Events", reportHtml);
        }
        finally
        {
            try { if (Directory.Exists(outputBase)) Directory.Delete(outputBase, true); } catch { }
        }
    }

    [Fact]
    public async Task TargetModifiedAfterSelection_TriggersWarningEvent()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"ExeScope_Mod_{Guid.NewGuid():N}");
        string testExe = Path.Combine(tempDir, "mutable_test.exe");

        try
        {
            Directory.CreateDirectory(tempDir);
            await File.WriteAllTextAsync(testExe, "ORIGINAL EXE CONTENT");

            var logger = new DiagnosticLogger();
            var manager = new AnalysisSessionManager(logger);

            manager.SetTargetExe(testExe);
            string originalHash = manager.TargetExe!.Sha256;

            // Now mutate the target file before launch detection
            await File.WriteAllTextAsync(testExe, "TAMPERED / MODIFIED EXE CONTENT 12345");

            string? detectedWarning = null;
            manager.TargetIntegrityWarning += warn => detectedWarning = warn;

            var config = new SessionConfig
            {
                TargetExePath = testExe,
                OutputDirectory = tempDir,
                EnableArtifactSaving = false
            };
            manager.UpdateConfig(config);

            await manager.StartWaitingAsync();

            // Simulate root process launch detection
            var dummyRoot = new ExeScope.Engine.Tracking.TrackedProcess
            {
                ProcessId = 7777,
                ImagePath = testExe,
                ImageName = "mutable_test.exe",
                StartTimeUtc = DateTime.UtcNow,
                IsRoot = true
            };

            // Call internal launch detection via reflection or method
            var method = typeof(AnalysisSessionManager).GetMethod("OnRootProcessLaunchDetected",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            method?.Invoke(manager, new object[] { dummyRoot });

            Assert.NotNull(detectedWarning);
            Assert.Contains("изменился после выбора", detectedWarning);
            Assert.True(manager.CurrentMetadata?.TargetModifiedAfterSelection);

            await manager.StopRecordingAsync();
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }
    }
}
