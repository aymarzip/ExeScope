using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Collectors;
using Xunit;

namespace ExeScope.Tests;

public class ArtifactCollectorTests
{
    [Fact]
    public async Task ArtifactCollector_EnforcesSingleFileSizeLimit()
    {
        string sessionDir = Path.Combine(Path.GetTempPath(), $"ExeScope_Test_Session_{Guid.NewGuid():N}");
        string sampleFile = Path.Combine(Path.GetTempPath(), $"sample_large_{Guid.NewGuid():N}.dat");

        try
        {
            Directory.CreateDirectory(sessionDir);

            // Write 500 KB test file
            byte[] data = new byte[500 * 1024];
            new Random(42).NextBytes(data);
            await File.WriteAllBytesAsync(sampleFile, data);

            var config = new SessionConfig
            {
                EnableArtifactSaving = true,
                MaxArtifactFileSizeBytes = 100 * 1024, // 100 KB limit (file is 500 KB)
                ArtifactMonitoredDirectories = new List<string> { Path.GetTempPath() }
            };

            var logger = new DiagnosticLogger();
            await using (var collector = new FileArtifactCollector(config, sessionDir, logger))
            {
                collector.Start();
                collector.QueueFile(sampleFile, 1234, "sample.exe");

                // Wait for worker
                await Task.Delay(500);

                Assert.Equal(0, collector.TotalSaved);
                Assert.Equal(1, collector.TotalSkipped);
            }

            // Verify entry in artifacts-index.jsonl
            string indexPath = Path.Combine(sessionDir, "artifacts-index.jsonl");
            Assert.True(File.Exists(indexPath));
            string indexContent = await File.ReadAllTextAsync(indexPath);
            Assert.Contains("SizeLimitExceeded", indexContent);
        }
        finally
        {
            try { if (File.Exists(sampleFile)) File.Delete(sampleFile); } catch { }
            try { if (Directory.Exists(sessionDir)) Directory.Delete(sessionDir, true); } catch { }
        }
    }

    [Fact]
    public async Task ArtifactCollector_SavesAllowedFile_AndComputesSha256()
    {
        string sessionDir = Path.Combine(Path.GetTempPath(), $"ExeScope_Test_Session_{Guid.NewGuid():N}");
        string sampleFile = Path.Combine(Path.GetTempPath(), $"sample_ok_{Guid.NewGuid():N}.txt");

        try
        {
            Directory.CreateDirectory(sessionDir);
            await File.WriteAllTextAsync(sampleFile, "ExeScope dynamic test payload 12345");

            var config = new SessionConfig
            {
                EnableArtifactSaving = true,
                MaxArtifactFileSizeBytes = 10 * 1024 * 1024,
                MaxTotalArtifactStorageBytes = 50 * 1024 * 1024,
                ArtifactMonitoredDirectories = new List<string> { Path.GetTempPath() }
            };

            var logger = new DiagnosticLogger();
            ArtifactRecord? savedRecord = null;

            await using (var collector = new FileArtifactCollector(config, sessionDir, logger))
            {
                collector.ArtifactPreserved += r => savedRecord = r;
                collector.Start();
                collector.QueueFile(sampleFile, 5678, "sample.exe");

                await Task.Delay(500);

                Assert.Equal(1, collector.TotalSaved);
                Assert.NotNull(savedRecord);
                Assert.Equal(ArtifactCopyStatus.Success, savedRecord.CopyStatus);
                Assert.False(string.IsNullOrEmpty(savedRecord.Sha256));

                // Verify file exists in artifacts/
                string artifactPath = Path.Combine(sessionDir, "artifacts", savedRecord.ArtifactFileName);
                Assert.True(File.Exists(artifactPath));
            }
        }
        finally
        {
            try { if (File.Exists(sampleFile)) File.Delete(sampleFile); } catch { }
            try { if (Directory.Exists(sessionDir)) Directory.Delete(sessionDir, true); } catch { }
        }
    }
}
