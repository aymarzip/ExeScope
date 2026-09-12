using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Collectors;
using Xunit;

namespace ExeScope.Tests;

public class FileLockAndArtifactEdgeCaseTests
{
    [Fact]
    public async Task ArtifactCollector_HandlesExclusivelyLockedFile_WithoutCrashing()
    {
        string sessionDir = Path.Combine(Path.GetTempPath(), $"ExeScope_Locked_{Guid.NewGuid():N}");
        string lockedFile = Path.Combine(Path.GetTempPath(), $"locked_file_{Guid.NewGuid():N}.dat");

        try
        {
            Directory.CreateDirectory(sessionDir);
            await File.WriteAllTextAsync(lockedFile, "secret locked data");

            var config = new SessionConfig
            {
                EnableArtifactSaving = true,
                MaxArtifactFileSizeBytes = 10 * 1024 * 1024,
                MaxTotalArtifactStorageBytes = 50 * 1024 * 1024,
                ArtifactMonitoredDirectories = new List<string> { Path.GetTempPath() }
            };

            var logger = new DiagnosticLogger();

            // Lock file exclusively with FileShare.None
            using var lockStream = new FileStream(lockedFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

            await using (var collector = new FileArtifactCollector(config, sessionDir, logger))
            {
                collector.Start();
                collector.QueueFile(lockedFile, 9999, "target.exe");

                // Give worker time to attempt read and encounter lock
                await Task.Delay(400);

                Assert.Equal(0, collector.TotalSaved);
                Assert.Equal(1, collector.TotalSkipped);
            }

            string indexPath = Path.Combine(sessionDir, "artifacts-index.jsonl");
            Assert.True(File.Exists(indexPath));
            string content = await File.ReadAllTextAsync(indexPath);
            Assert.Contains("Locked", content);
        }
        finally
        {
            try { if (File.Exists(lockedFile)) File.Delete(lockedFile); } catch { }
            try { if (Directory.Exists(sessionDir)) Directory.Delete(sessionDir, true); } catch { }
        }
    }

    [Fact]
    public async Task ArtifactCollector_HandlesDeletedBeforeCopy_Gracefully()
    {
        string sessionDir = Path.Combine(Path.GetTempPath(), $"ExeScope_Deleted_{Guid.NewGuid():N}");
        string ephemeralFile = Path.Combine(Path.GetTempPath(), $"ephemeral_{Guid.NewGuid():N}.tmp");

        try
        {
            Directory.CreateDirectory(sessionDir);
            await File.WriteAllTextAsync(ephemeralFile, "ephemeral payload");

            var config = new SessionConfig
            {
                EnableArtifactSaving = true,
                ArtifactMonitoredDirectories = new List<string> { Path.GetTempPath() }
            };

            var logger = new DiagnosticLogger();

            await using (var collector = new FileArtifactCollector(config, sessionDir, logger))
            {
                collector.Start();

                // Delete the file immediately before the worker takes it
                File.Delete(ephemeralFile);

                collector.QueueFile(ephemeralFile, 8888, "target.exe");

                await Task.Delay(400);

                Assert.Equal(0, collector.TotalSaved);
                Assert.Equal(1, collector.TotalSkipped);
            }

            string indexPath = Path.Combine(sessionDir, "artifacts-index.jsonl");
            string content = await File.ReadAllTextAsync(indexPath);
            Assert.Contains("DeletedBeforeCopy", content);
        }
        finally
        {
            try { if (Directory.Exists(sessionDir)) Directory.Delete(sessionDir, true); } catch { }
        }
    }

    [Fact]
    public async Task ArtifactCollector_PreservesZeroByteFile_WithCorrectSha256()
    {
        string sessionDir = Path.Combine(Path.GetTempPath(), $"ExeScope_Zero_{Guid.NewGuid():N}");
        string zeroFile = Path.Combine(Path.GetTempPath(), $"zero_len_{Guid.NewGuid():N}.dat");

        try
        {
            Directory.CreateDirectory(sessionDir);
            await File.WriteAllBytesAsync(zeroFile, Array.Empty<byte>());

            var config = new SessionConfig
            {
                EnableArtifactSaving = true,
                ArtifactMonitoredDirectories = new List<string> { Path.GetTempPath() }
            };

            var logger = new DiagnosticLogger();
            ArtifactRecord? preserved = null;

            await using (var collector = new FileArtifactCollector(config, sessionDir, logger))
            {
                collector.ArtifactPreserved += r => preserved = r;
                collector.Start();
                collector.QueueFile(zeroFile, 7777, "target.exe");

                await Task.Delay(400);

                Assert.Equal(1, collector.TotalSaved);
                Assert.NotNull(preserved);
                Assert.Equal(0, preserved.SizeBytes);
                // Standard empty string SHA-256
                Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", preserved.Sha256);
            }
        }
        finally
        {
            try { if (File.Exists(zeroFile)) File.Delete(zeroFile); } catch { }
            try { if (Directory.Exists(sessionDir)) Directory.Delete(sessionDir, true); } catch { }
        }
    }

    [Fact]
    public async Task ArtifactCollector_EnforcesTotalStorageQuota()
    {
        string sessionDir = Path.Combine(Path.GetTempPath(), $"ExeScope_Quota_{Guid.NewGuid():N}");
        string file1 = Path.Combine(Path.GetTempPath(), $"qfile1_{Guid.NewGuid():N}.dat");
        string file2 = Path.Combine(Path.GetTempPath(), $"qfile2_{Guid.NewGuid():N}.dat");

        try
        {
            Directory.CreateDirectory(sessionDir);

            // Write two 300KB files
            byte[] bytes = new byte[300 * 1024];
            new Random(1).NextBytes(bytes);
            await File.WriteAllBytesAsync(file1, bytes);

            byte[] bytes2 = new byte[300 * 1024];
            new Random(2).NextBytes(bytes2);
            await File.WriteAllBytesAsync(file2, bytes2);

            var config = new SessionConfig
            {
                EnableArtifactSaving = true,
                MaxArtifactFileSizeBytes = 500 * 1024,       // 500KB per file (passes)
                MaxTotalArtifactStorageBytes = 400 * 1024,   // 400KB total budget (second file exceeds)
                ArtifactMonitoredDirectories = new List<string> { Path.GetTempPath() }
            };

            var logger = new DiagnosticLogger();

            await using (var collector = new FileArtifactCollector(config, sessionDir, logger))
            {
                collector.Start();
                collector.QueueFile(file1, 1111, "app.exe");
                await Task.Delay(300);

                collector.QueueFile(file2, 1111, "app.exe");
                await Task.Delay(300);

                Assert.Equal(1, collector.TotalSaved);
                Assert.Equal(1, collector.TotalSkipped);
            }

            string content = await File.ReadAllTextAsync(Path.Combine(sessionDir, "artifacts-index.jsonl"));
            Assert.Contains("QuotaExceeded", content);
        }
        finally
        {
            try { if (File.Exists(file1)) File.Delete(file1); } catch { }
            try { if (File.Exists(file2)) File.Delete(file2); } catch { }
            try { if (Directory.Exists(sessionDir)) Directory.Delete(sessionDir, true); } catch { }
        }
    }
}
