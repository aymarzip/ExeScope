using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Reporting;
using Xunit;

namespace ExeScope.Tests;

public class ReportGenerationEdgeCaseTests
{
    [Fact]
    public void GenerateReport_HandlesCompletelyEmptySession_WithoutExceptions()
    {
        var metadata = new SessionMetadata
        {
            SessionId = "empty_session_test",
            SessionDirectory = @"C:\Sandbox\empty",
            IsElevated = false
        };

        string html = HtmlReportGenerator.GenerateReport(
            metadata,
            processTree: null,
            events: Array.Empty<AnalysisEvent>(),
            artifacts: Array.Empty<ArtifactRecord>(),
            diagnostics: Array.Empty<DiagnosticEntry>());

        Assert.NotNull(html);
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("No process tree recorded", html);
        Assert.Contains("File Events (0)", html);
        Assert.Contains("Registry Events (0)", html);
        Assert.Contains("Network Events (0)", html);
    }

    [Fact]
    public void GenerateReport_CapsTableRows_WhenExceedingLimit()
    {
        var metadata = new SessionMetadata
        {
            SessionId = "large_session_test",
            IsElevated = true,
            TotalEventsRecorded = 12000
        };

        var events = new List<AnalysisEvent>();
        for (int i = 0; i < 7000; i++)
        {
            events.Add(new FileEvent
            {
                EventId = i,
                ProcessId = 1000,
                ProcessImage = "sample.exe",
                Operation = FileOperationType.Write,
                Path = $@"C:\Temp\file_{i}.txt",
                Result = "SUCCESS"
            });
        }

        string html = HtmlReportGenerator.GenerateReport(
            metadata,
            processTree: null,
            events: events,
            artifacts: Array.Empty<ArtifactRecord>(),
            diagnostics: Array.Empty<DiagnosticEntry>(),
            maxTableRows: 2000);

        Assert.Contains("Showing first 2,000 of 7,000 file events", html);
        Assert.Contains("The full dataset is saved in events.jsonl", html);
    }

    [Fact]
    public void GenerateReport_HandlesUnicodeAndSpecialCharacters_Safely()
    {
        var metadata = new SessionMetadata
        {
            TargetExe = new TargetExeInfo
            {
                FileName = "тест_программа_日本語_🚀.exe",
                OriginalPath = @"C:\Песочница\тест_программа_日本語_🚀.exe",
                Sha256 = "deadbeef1234",
                SignatureStatus = "Подписано (Trusted)"
            },
            IsElevated = true
        };

        var events = new List<AnalysisEvent>
        {
            new RegistryEvent
            {
                ProcessImage = "тест.exe",
                ProcessId = 4444,
                KeyPath = @"HKCU\Software\ТестовыйКлюч\Настройка",
                ValueName = "Параметр_Спец_Символы_&_<>_'\"",
                Operation = RegistryOperationType.SetValue,
                Result = "SUCCESS"
            }
        };

        string html = HtmlReportGenerator.GenerateReport(
            metadata,
            processTree: null,
            events: events,
            artifacts: Array.Empty<ArtifactRecord>(),
            diagnostics: Array.Empty<DiagnosticEntry>());

        Assert.Contains("тест_программа_日本語", html);
        Assert.Contains("ТестовыйКлюч", html);
        // Special symbols escaped
        Assert.DoesNotContain("<_'\">", html);
        Assert.Contains("&amp;", html);
    }
}
