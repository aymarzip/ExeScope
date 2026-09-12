using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Reporting;
using Xunit;

namespace ExeScope.Tests;

public class HtmlReportGeneratorTests
{
    [Fact]
    public void GenerateReport_ProperlyEscapesMaliciousInput()
    {
        var metadata = new SessionMetadata
        {
            TargetExe = new TargetExeInfo
            {
                FileName = "<script>alert('pwn')</script>.exe",
                OriginalPath = "C:\\evil\\<script>alert('pwn')</script>.exe",
                Sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                SignatureStatus = "<b>Injected</b>"
            },
            IsElevated = false,
            TargetLaunchDetectedUtc = DateTime.UtcNow
        };

        var processTree = new ProcessNode
        {
            ImageName = "<img src=x onerror=alert(1)>",
            ImagePath = "C:\\bad\\<img src=x onerror=alert(1)>",
            CommandLine = "cmd.exe /c \"<svg onload=alert(2)>\"",
            ProcessId = 1234,
            StartTimeUtc = DateTime.UtcNow
        };

        var events = new List<AnalysisEvent>
        {
            new FileEvent
            {
                ProcessImage = "<script>xss()</script>",
                ProcessId = 1234,
                Operation = FileOperationType.Write,
                Path = "C:\\secret\\<b style='color:red'>danger</b>.txt",
                Result = "SUCCESS"
            }
        };

        var artifacts = new List<ArtifactRecord>
        {
            new ArtifactRecord
            {
                OriginalPath = "C:\\evil\\<script>evil()</script>",
                ArtifactFileName = "artifact_0001_safe.txt",
                Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                SizeBytes = 100,
                CopyStatus = ArtifactCopyStatus.Success
            }
        };

        var diagnostics = new List<DiagnosticEntry>
        {
            new DiagnosticEntry
            {
                Level = LogLevel.Warning,
                Source = "<iframe src='evil.com'>",
                Message = "<script>alert(3)</script>"
            }
        };

        string html = HtmlReportGenerator.GenerateReport(metadata, processTree, events, artifacts, diagnostics);

        // Verify HTML is self-contained and valid
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("</html>", html);

        // Strictly verify raw script/img/iframe tags are NOT present unescaped
        Assert.DoesNotContain("<script>alert('pwn')</script>", html);
        Assert.DoesNotContain("<img src=x onerror=alert(1)>", html);
        Assert.DoesNotContain("<svg onload=alert(2)>", html);
        Assert.DoesNotContain("<iframe src='evil.com'>", html);

        // Verify properly escaped versions ARE present
        Assert.Contains("&lt;script&gt;alert(&#39;pwn&#39;)&lt;/script&gt;", html);
        Assert.Contains("&lt;img src=x onerror=alert(1)&gt;", html);
    }
}
