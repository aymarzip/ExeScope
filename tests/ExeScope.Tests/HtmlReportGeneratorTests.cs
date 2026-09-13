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

    [Fact]
    public void GenerateReport_WithInjectionEvents_RendersInjectionSectionAndBadges()
    {
        var metadata = new SessionMetadata
        {
            TargetExe = new TargetExeInfo
            {
                FileName = "injector.exe",
                OriginalPath = @"C:\Cheats\injector.exe",
                Sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                SignatureStatus = "Unsigned"
            },
            IsElevated = true,
            TargetLaunchDetectedUtc = DateTime.UtcNow
        };

        var rootProcess = new ProcessNode
        {
            ImageName = "injector.exe",
            ImagePath = @"C:\Cheats\injector.exe",
            CommandLine = "injector.exe --inject",
            ProcessId = 1000,
            StartTimeUtc = DateTime.UtcNow,
            Children = new List<ProcessNode>
            {
                new ProcessNode
                {
                    ImageName = "javaw.exe",
                    ImagePath = @"C:\Program Files\Java\bin\javaw.exe",
                    CommandLine = "javaw.exe -Xmx4G -jar minecraft.jar",
                    ProcessId = 5000,
                    StartTimeUtc = DateTime.UtcNow,
                    IsInjectionTarget = true,
                    InjectedByPid = 1000,
                    InjectedModules = new List<string> { @"C:\Cheats\payload.dll" }
                }
            }
        };

        var events = new List<AnalysisEvent>
        {
            new InjectionEvent
            {
                Technique = InjectionTechnique.DllInjection,
                SourceProcessId = 1000,
                SourceProcessImage = "injector.exe",
                TargetProcessId = 5000,
                TargetProcessImage = "javaw.exe",
                InjectedModulePath = @"C:\Cheats\payload.dll",
                Details = "Injected payload.dll into Minecraft JVM",
                TimestampUtc = DateTime.UtcNow
            }
        };

        string html = HtmlReportGenerator.GenerateReport(
            metadata,
            rootProcess,
            events,
            Array.Empty<ArtifactRecord>(),
            Array.Empty<DiagnosticEntry>());

        // Warning banner and stats card
        Assert.Contains("ОБНАРУЖЕНЫ ИНЪЕКЦИИ (INJECTIONS DETECTED)", html);
        Assert.Contains("Injections / Инъекции", html);
        Assert.Contains("Обнаруженные инъекции (1)", html);

        // Injection table content
        Assert.Contains("DllInjection", html);
        Assert.Contains("injector.exe (1000)", html);
        Assert.Contains("javaw.exe (5000)", html);
        Assert.Contains(@"C:\Cheats\payload.dll", html);
        Assert.Contains("Injected payload.dll into Minecraft JVM", html);

        // Process tree visual badges
        Assert.Contains("INJECTION TARGET", html);
        Assert.Contains("Injected Process (Target of DLL / Code Injection)", html);
        Assert.Contains("Injected by PID: 1000", html);
        Assert.Contains(@"Injected Modules: C:\Cheats\payload.dll", html);
    }

    [Fact]
    public void GenerateReport_WithNoInjections_ShowsZeroCountAndNoWarningBanner()
    {
        var metadata = new SessionMetadata
        {
            TargetExe = new TargetExeInfo
            {
                FileName = "benign.exe",
                OriginalPath = @"C:\App\benign.exe",
                Sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                SignatureStatus = "Valid"
            },
            IsElevated = false,
            TargetLaunchDetectedUtc = DateTime.UtcNow
        };

        string html = HtmlReportGenerator.GenerateReport(
            metadata,
            processTree: null,
            events: Array.Empty<AnalysisEvent>(),
            artifacts: Array.Empty<ArtifactRecord>(),
            diagnostics: Array.Empty<DiagnosticEntry>());

        Assert.DoesNotContain("ОБНАРУЖЕНЫ ИНЪЕКЦИИ", html);
        Assert.Contains("Обнаруженные инъекции (0)", html);
        Assert.Contains("Injections / Инъекции", html);
    }

    [Fact]
    public void GenerateReport_InjectionEvents_EscapesMaliciousPayloadInInjectionEvent()
    {
        var metadata = new SessionMetadata
        {
            TargetExe = new TargetExeInfo { FileName = "safe.exe" },
            IsElevated = false
        };

        var events = new List<AnalysisEvent>
        {
            new InjectionEvent
            {
                Technique = InjectionTechnique.DllInjection,
                SourceProcessId = 1111,
                SourceProcessImage = "<script>bad()</script>.exe",
                TargetProcessId = 2222,
                TargetProcessImage = "<iframe src=attacker.com>",
                InjectedModulePath = @"C:\Temp\<img src=x onerror=1>.dll",
                Details = "<b>danger</b> & <alert>",
                TimestampUtc = DateTime.UtcNow
            }
        };

        string html = HtmlReportGenerator.GenerateReport(
            metadata,
            processTree: null,
            events: events,
            artifacts: Array.Empty<ArtifactRecord>(),
            diagnostics: Array.Empty<DiagnosticEntry>());

        // Must not contain raw unescaped XSS
        Assert.DoesNotContain("<script>bad()</script>", html);
        Assert.DoesNotContain("<iframe src=attacker.com>", html);
        Assert.DoesNotContain("<img src=x onerror=1>", html);
        Assert.DoesNotContain("<b>danger</b>", html);

        // Must contain escaped versions
        Assert.Contains("&lt;script&gt;bad()&lt;/script&gt;", html);
        Assert.Contains("&lt;iframe src=attacker.com&gt;", html);
        Assert.Contains("&lt;img src=x onerror=1&gt;", html);
        Assert.Contains("&lt;b&gt;danger&lt;/b&gt; &amp; &lt;alert&gt;", html);
    }
}
