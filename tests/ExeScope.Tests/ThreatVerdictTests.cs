using ExeScope.Contracts.Events;
using ExeScope.Contracts.Threat;
using Xunit;

namespace ExeScope.Tests;

public class ThreatVerdictTests
{
    [Fact]
    public void ThreatVerdictEvaluator_CleanBaseline_ReturnsCleanVerdict()
    {
        var processes = new List<ProcessStartedEvent>
        {
            new(1, DateTime.UtcNow, 100, 50, "notepad.exe", "explorer.exe", @"C:\Windows\notepad.exe", "notepad.exe")
        };

        var files = new List<FileModifiedEvent>
        {
            new(2, DateTime.UtcNow, 100, "notepad.exe", "ReadFile", @"C:\Users\test\doc.txt", "SUCCESS")
        };

        var verdict = ThreatVerdictEvaluator.Evaluate(
            processes: processes,
            injections: Array.Empty<DllInjectedEvent>(),
            registry: Array.Empty<RegistryModifiedEvent>(),
            network: Array.Empty<NetworkConnectionEvent>(),
            files: files,
            isUnsigned: false,
            targetModifiedOnDisk: false
        );

        Assert.Equal(ThreatLevel.Clean, verdict.Level);
        Assert.True(verdict.Score < 30);
        Assert.Empty(verdict.Indicators);
        Assert.Equal("#8c9ba5", verdict.HexColor);
    }

    [Fact]
    public void ThreatVerdictEvaluator_InjectionDetected_ReturnsMaliciousVerdict()
    {
        var injections = new List<DllInjectedEvent>
        {
            new(1, DateTime.UtcNow, 1000, "malware.exe", 2000, "explorer.exe", @"C:\temp\payload.dll", "CreateRemoteThread", "Remote thread created", 0x12345678)
        };

        var verdict = ThreatVerdictEvaluator.Evaluate(
            processes: Array.Empty<ProcessStartedEvent>(),
            injections: injections,
            registry: Array.Empty<RegistryModifiedEvent>(),
            network: Array.Empty<NetworkConnectionEvent>(),
            files: Array.Empty<FileModifiedEvent>()
        );

        Assert.True(verdict.Score >= 25);
        Assert.Contains(verdict.Indicators, i => i.RuleId == "T1055-INJECTION" && i.Severity == IocSeverity.Critical);
    }

    [Fact]
    public void ThreatVerdictEvaluator_MultipleAdversarialActions_CalculatesHighRiskScore()
    {
        var processes = new List<ProcessStartedEvent>
        {
            new(1, DateTime.UtcNow, 101, 100, "powershell.exe", "malware.exe", @"C:\Windows\powershell.exe", "powershell.exe -enc AAAA -windowstyle hidden")
        };

        var injections = new List<DllInjectedEvent>
        {
            new(2, DateTime.UtcNow, 100, "malware.exe", 500, "lsass.exe", @"C:\temp\mimikatz.dll", "QueueUserAPC", "APC injection", null),
            new(3, DateTime.UtcNow, 100, "malware.exe", 600, "svchost.exe", @"C:\temp\mimikatz.dll", "QueueUserAPC", "APC injection", null)
        };

        var registry = new List<RegistryModifiedEvent>
        {
            new(4, DateTime.UtcNow, 100, "malware.exe", "SetValue", @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "AutoStart", "REG_SZ", "malware.exe", "SUCCESS")
        };

        var files = new List<FileModifiedEvent>
        {
            new(5, DateTime.UtcNow, 100, "malware.exe", "CreateFile", @"C:\Users\User\AppData\Local\Temp\payload.exe", "SUCCESS")
        };

        var network = new List<NetworkConnectionEvent>
        {
            new(6, DateTime.UtcNow, 100, "malware.exe", "TCP", "Outbound", "192.168.1.100:5555", "185.220.101.5:443", 50000, null, null, "EtwExactPid", "High", null)
        };

        var verdict = ThreatVerdictEvaluator.Evaluate(
            processes: processes,
            injections: injections,
            registry: registry,
            network: network,
            files: files,
            isUnsigned: true,
            targetModifiedOnDisk: true
        );

        Assert.Equal(ThreatLevel.Malicious, verdict.Level);
        Assert.True(verdict.Score >= 80);
        Assert.True(verdict.Score <= 100);
        Assert.Equal("#f5222d", verdict.HexColor);
        Assert.Contains(verdict.Indicators, i => i.RuleId == "T1055-INJECTION");
        Assert.Contains(verdict.Indicators, i => i.RuleId == "T1059-SPAWN");
        Assert.Contains(verdict.Indicators, i => i.RuleId == "T1547-PERSISTENCE-REG");
        Assert.Contains(verdict.Indicators, i => i.RuleId == "T1105-DROPPED-PAYLOAD");
        Assert.Contains(verdict.Indicators, i => i.RuleId == "T1027-BINARY-TAMPERING");
    }

    [Fact]
    public void ThreatVerdictEvaluator_ScoreClampedTo100()
    {
        var injections = Enumerable.Range(1, 10).Select(i =>
            new DllInjectedEvent(i, DateTime.UtcNow, 100, "m.exe", 200 + i, "t.exe", "p.dll", "Technique", null, null)
        );

        var processes = new List<ProcessStartedEvent>
        {
            new(100, DateTime.UtcNow, 999, 100, "powershell.exe", "m.exe", @"C:\Windows\powershell.exe", "powershell.exe -enc AAAA")
        };

        var verdict = ThreatVerdictEvaluator.Evaluate(
            processes: processes,
            injections: injections,
            registry: Array.Empty<RegistryModifiedEvent>(),
            network: Array.Empty<NetworkConnectionEvent>(),
            files: Array.Empty<FileModifiedEvent>(),
            isUnsigned: true,
            targetModifiedOnDisk: true
        );

        Assert.Equal(100, verdict.Score);
        Assert.Equal(ThreatLevel.Malicious, verdict.Level);
    }
}
