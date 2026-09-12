using ExeScope.Core.Utilities;
using Xunit;

namespace ExeScope.Tests;

public class PathSanitizerEdgeCasesTests
{
    [Theory]
    [InlineData("payload.exe:hidden_stream", "payload.exe")]
    [InlineData("data.txt:evil:$DATA", "data.txt")]
    [InlineData("nul", "_nul")]
    [InlineData("aux.txt", "_aux.txt")]
    [InlineData("com9.bin", "_com9.bin")]
    [InlineData("lpt1.tar.gz", "_lpt1.tar.gz")]
    [InlineData("file\nwith\rnewlines\t.txt", "file_with_newlines_.txt")]
    [InlineData("    spaces_and_dots....   ", "spaces_and_dots")]
    [InlineData("", "unnamed_artifact")]
    [InlineData("   ", "unnamed_artifact")]
    public void SanitizeFileName_HandlesEdgeCases(string input, string expected)
    {
        string actual = PathSanitizer.SanitizeFileName(input);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void SanitizeFileName_LimitsLengthWhilePreservingExtension()
    {
        string veryLongName = new string('a', 150) + ".payload.exe";
        string sanitized = PathSanitizer.SanitizeFileName(veryLongName);

        Assert.True(sanitized.Length <= 110);
        Assert.EndsWith(".exe", sanitized);
    }

    [Theory]
    [InlineData(@"\\?\C:\Windows\System32\cmd.exe", @"C:\Windows\System32\cmd.exe")]
    [InlineData(@"\??\C:\Windows\System32\cmd.exe", @"C:\Windows\System32\cmd.exe")]
    [InlineData(@"C:/Sandbox/Sub/../app.exe", @"C:\Sandbox\app.exe")]
    public void NormalizeCanonicalPath_StripsPrefixesAndResolvesRelatives(string input, string expected)
    {
        string actual = PathSanitizer.NormalizeCanonicalPath(input);
        Assert.Equal(expected, actual, ignoreCase: true);
    }

    [Fact]
    public void ArePathsEquivalent_MatchesDifferentSlashStylesAndPrefixes()
    {
        string p1 = @"\\?\C:\Sandbox\App\sample.exe";
        string p2 = @"c:/sandbox/app/SAMPLE.EXE";

        Assert.True(PathSanitizer.ArePathsEquivalent(p1, p2));
    }
}
