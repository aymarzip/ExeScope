using ExeScope.Core.Utilities;
using Xunit;

namespace ExeScope.Tests;

public class PathSanitizerTests
{
    [Theory]
    [InlineData(@"../../etc/passwd", "passwd")]
    [InlineData(@"..\..\Windows\System32\cmd.exe", "cmd.exe")]
    [InlineData(@"CON", "_CON")]
    [InlineData(@"NUL.txt", "_NUL.txt")]
    [InlineData(@"COM1.log", "_COM1.log")]
    [InlineData(@"bad:stream.txt", "bad")]
    [InlineData(@"test|file*name?.txt", "test_file_name_.txt")]
    public void SanitizeFileName_StripsDangerousTokens(string input, string expected)
    {
        string actual = PathSanitizer.SanitizeFileName(input);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CreateSafeArtifactDestination_AlwaysStaysInsideBaseDirectory()
    {
        string tempDir = Path.GetTempPath();
        string baseDir = Path.Combine(tempDir, "ExeScope_Test_Artifacts");

        string destination = PathSanitizer.CreateSafeArtifactDestination(
            baseDir,
            artifactIndex: 1,
            originalPath: @"C:\Users\Admin\..\..\Secret\passwords.txt",
            sha256: "abcdef1234567890");

        Assert.StartsWith(Path.GetFullPath(baseDir), destination, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("artifact_0001_abcdef12_passwords.txt", destination);
    }

    [Fact]
    public void IsPathWithinMonitoredDirectories_MatchesCorrectly()
    {
        string tempDir = Path.GetTempPath();
        var monitored = new List<string> { tempDir, @"C:\AppData\Local" };

        string insideFile = Path.Combine(tempDir, "sample_out.dat");
        string outsideFile = @"C:\Windows\System32\kernel32.dll";

        Assert.True(PathSanitizer.IsPathWithinMonitoredDirectories(insideFile, monitored));
        Assert.False(PathSanitizer.IsPathWithinMonitoredDirectories(outsideFile, monitored));
    }
}
