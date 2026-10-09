using ExeScope.Contracts.Events;

namespace ExeScope.Contracts.Threat;

public static class ThreatVerdictEvaluator
{
    private static readonly HashSet<string> SuspiciousProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "schtasks.exe",
        "bitsadmin.exe",
        "mshta.exe"
    };

    private static readonly string[] PersistenceRegistryPaths = new[]
    {
        @"CurrentVersion\Run",
        @"CurrentVersion\RunOnce",
        @"CurrentVersion\Policies\Explorer\Run",
        @"Windows\CurrentVersion\RunServices",
        @"Image File Execution Options",
        @"Software\Policies\Microsoft\Windows Defender"
    };

    public static ThreatVerdictSummary Evaluate(
        IEnumerable<ProcessStartedEvent> processes,
        IEnumerable<DllInjectedEvent> injections,
        IEnumerable<RegistryModifiedEvent> registry,
        IEnumerable<NetworkConnectionEvent> network,
        IEnumerable<FileModifiedEvent> files,
        bool isUnsigned = false,
        bool targetModifiedOnDisk = false)
    {
        var iocs = new List<IndicatorOfCompromise>();
        int score = 0;

        // 1. Injections (Critical severity)
        var injList = injections.ToList();
        if (injList.Count > 0)
        {
            score += Math.Min(50, injList.Count * 25);
            foreach (var inj in injList)
            {
                iocs.Add(new IndicatorOfCompromise(
                    RuleId: "T1055-INJECTION",
                    Title: $"Process Injection Detected ({inj.Technique})",
                    Description: $"Source PID {inj.SourceProcessId} ({inj.SourceProcessImage ?? "unknown"}) injected into Target PID {inj.TargetProcessId} ({inj.TargetProcessImage ?? "unknown"}). Module: {inj.InjectedModulePath ?? "N/A"}",
                    Severity: IocSeverity.Critical,
                    MitreTechniqueId: "T1055",
                    Evidence: inj.Details ?? $"Technique: {inj.Technique}"
                ));
            }
        }

        // 2. Suspicious process spawns
        foreach (var proc in processes)
        {
            if (SuspiciousProcessNames.Contains(proc.ProcessImage))
            {
                score += 15;
                iocs.Add(new IndicatorOfCompromise(
                    RuleId: "T1059-SPAWN",
                    Title: $"Suspicious Living-off-the-Land Binary Executed ({proc.ProcessImage})",
                    Description: $"Process PID {proc.ProcessId} spawned '{proc.ProcessImage}' with cmdline: {proc.CommandLine ?? "N/A"}",
                    Severity: IocSeverity.High,
                    MitreTechniqueId: "T1059",
                    Evidence: proc.CommandLine
                ));
            }

            if (!string.IsNullOrEmpty(proc.CommandLine) &&
                (proc.CommandLine.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
                 proc.CommandLine.Contains("-windowstyle hidden", StringComparison.OrdinalIgnoreCase) ||
                 proc.CommandLine.Contains("bypass", StringComparison.OrdinalIgnoreCase)))
            {
                score += 15;
                iocs.Add(new IndicatorOfCompromise(
                    RuleId: "T1059-ENCODED-CMD",
                    Title: "Obfuscated / Encoded Command-Line Execution",
                    Description: $"Process PID {proc.ProcessId} invoked obfuscated parameters: {proc.CommandLine}",
                    Severity: IocSeverity.High,
                    MitreTechniqueId: "T1059.001",
                    Evidence: proc.CommandLine
                ));
            }
        }

        // 3. Registry Persistence
        foreach (var reg in registry)
        {
            foreach (var path in PersistenceRegistryPaths)
            {
                if (reg.KeyPath.Contains(path, StringComparison.OrdinalIgnoreCase))
                {
                    score += 20;
                    iocs.Add(new IndicatorOfCompromise(
                        RuleId: "T1547-PERSISTENCE-REG",
                        Title: $"Autostart / Persistence Registry Key Modified",
                        Description: $"Key '{reg.KeyPath}' (Value: {reg.ValueName ?? ""}) was modified with operation {reg.Operation}",
                        Severity: IocSeverity.High,
                        MitreTechniqueId: "T1547.001",
                        Evidence: $"{reg.KeyPath} -> {reg.ValueDataSummary ?? ""}"
                    ));
                    break;
                }
            }
        }

        // 4. File system drops in temp / startup / appdata
        foreach (var f in files)
        {
            if (f.Operation.Contains("Create", StringComparison.OrdinalIgnoreCase) ||
                f.Operation.Contains("Write", StringComparison.OrdinalIgnoreCase))
            {
                string ext = Path.GetExtension(f.FilePath);
                if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase))
                {
                    if (f.FilePath.Contains("Temp", StringComparison.OrdinalIgnoreCase) ||
                        f.FilePath.Contains("AppData", StringComparison.OrdinalIgnoreCase) ||
                        f.FilePath.Contains("Startup", StringComparison.OrdinalIgnoreCase))
                    {
                        score += 15;
                        iocs.Add(new IndicatorOfCompromise(
                            RuleId: "T1105-DROPPED-PAYLOAD",
                            Title: "Executable Binary Dropped into User Directory",
                            Description: $"Target process created or modified executable '{f.FilePath}' in user directory",
                            Severity: IocSeverity.Medium,
                            MitreTechniqueId: "T1105",
                            Evidence: f.FilePath
                        ));
                    }
                }
            }
        }

        // 5. Network activity to non-standard remote ports
        foreach (var net in network)
        {
            if (net.RemoteEndpoint != null && !net.RemoteEndpoint.StartsWith("127.0.0.1") && !net.RemoteEndpoint.StartsWith("localhost"))
            {
                if (net.BytesTransferred > 1024 * 10)
                {
                    score += 10;
                    iocs.Add(new IndicatorOfCompromise(
                        RuleId: "T1071-EXTERNAL-C2",
                        Title: "External Network Connection Established",
                        Description: $"Outbound connection to {net.RemoteEndpoint} via {net.Protocol} (Transferred: {net.BytesTransferred} bytes)",
                        Severity: IocSeverity.Medium,
                        MitreTechniqueId: "T1071",
                        Evidence: net.RemoteEndpoint
                    ));
                }
            }
        }

        // 6. Binary integrity and certificate status
        if (targetModifiedOnDisk)
        {
            score += 35;
            iocs.Add(new IndicatorOfCompromise(
                RuleId: "T1027-BINARY-TAMPERING",
                Title: "Self-Modifying / Binary Mutated On Disk",
                Description: "The executable file hash changed on disk after initial analysis startup, indicating self-tampering or polymorphic behavior.",
                Severity: IocSeverity.Critical,
                MitreTechniqueId: "T1027",
                Evidence: "File hash mutated on disk"
            ));
        }

        if (isUnsigned)
        {
            score += 10;
            iocs.Add(new IndicatorOfCompromise(
                RuleId: "T1553-UNSIGNED",
                Title: "Unsigned Executable Binary",
                Description: "The target binary does not possess a valid Microsoft Authenticode digital signature.",
                Severity: IocSeverity.Low,
                MitreTechniqueId: "T1553.002",
                Evidence: "No valid digital signature found"
            ));
        }

        // Final score capping and level determination
        score = Math.Clamp(score, 0, 100);

        ThreatLevel level = score switch
        {
            >= 70 => ThreatLevel.Malicious,
            >= 30 => ThreatLevel.Suspicious,
            _ => ThreatLevel.Clean
        };

        string summary = level switch
        {
            ThreatLevel.Malicious => $"MALICIOUS VERDICT (Score: {score}/100) — Multiple high-risk adversarial indicators detected, including injection, persistence, or tampering.",
            ThreatLevel.Suspicious => $"SUSPICIOUS VERDICT (Score: {score}/100) — Anomalous system operations, external network traffic, or unverified execution patterns detected.",
            _ => $"CLEAN / LOW RISK (Score: {score}/100) — No malicious or aggressive adversarial activities identified during the session."
        };

        return new ThreatVerdictSummary
        {
            Score = score,
            Level = level,
            SummaryText = summary,
            Indicators = iocs
        };
    }
}
