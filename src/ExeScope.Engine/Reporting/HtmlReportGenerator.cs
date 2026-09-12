using System.Globalization;
using System.Net;
using System.Text;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;

namespace ExeScope.Engine.Reporting;

public class HtmlReportGenerator
{
    public static string GenerateReport(
        SessionMetadata metadata,
        ProcessNode? processTree,
        IReadOnlyList<AnalysisEvent> events,
        IReadOnlyList<ArtifactRecord> artifacts,
        IReadOnlyList<DiagnosticEntry> diagnostics,
        int maxTableRows = 5000)
    {
        var sb = new StringBuilder();

        string exeName = Escape(metadata.TargetExe?.FileName ?? "Unknown");
        string exePath = Escape(metadata.TargetExe?.OriginalPath ?? "Unknown");
        string exeHash = Escape(metadata.TargetExe?.Sha256 ?? "N/A");
        string signatureStatus = Escape(metadata.TargetExe?.SignatureStatus ?? "Unknown");
        string startTime = metadata.TargetLaunchDetectedUtc?.ToString("yyyy-MM-dd HH:mm:ss.fff") ?? "N/A";
        string endTime = metadata.RecordingEndedUtc?.ToString("yyyy-MM-dd HH:mm:ss.fff") ?? "N/A";

        sb.Append($@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>ExeScope Dynamic Analysis Report: {exeName}</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-color: #c9d1d9;
            --text-muted: #8b949e;
            --accent-color: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-purple: #bc8cff;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        header {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        h1 {{ font-size: 24px; margin-bottom: 8px; color: #fff; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-success {{ background-color: rgba(63, 185, 80, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .badge-warn {{ background-color: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
        .badge-danger {{ background-color: rgba(248, 81, 73, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge-info {{ background-color: rgba(88, 166, 255, 0.2); color: var(--accent-color); border: 1px solid var(--accent-color); }}
        
        .grid-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-top: 20px;
        }}
        .stat-card {{
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border-color);
            padding: 16px;
            border-radius: 6px;
        }}
        .stat-card .label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px; }}
        .stat-card .value {{ font-size: 18px; font-weight: 600; word-break: break-all; color: #fff; }}

        .tabs {{
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }}
        .tab-btn {{
            background: none;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--text-muted);
            padding: 10px 16px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
        }}
        .tab-btn.active {{
            color: var(--accent-color);
            border-bottom-color: var(--accent-color);
        }}
        .tab-panel {{ display: none; }}
        .tab-panel.active {{ display: block; }}

        .search-box {{
            width: 100%;
            padding: 10px 14px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: #fff;
            margin-bottom: 16px;
            font-size: 14px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            overflow: hidden;
            font-size: 13px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: rgba(255,255,255,0.02);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
        }}
        tr:hover {{ background-color: rgba(255,255,255,0.02); }}
        .mono {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }}

        .tree-node {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 14px;
            margin-bottom: 10px;
        }}
        .tree-node .children {{
            margin-left: 24px;
            margin-top: 10px;
            border-left: 2px solid var(--border-color);
            padding-left: 14px;
        }}
        .warning-banner {{
            background: rgba(248, 81, 73, 0.15);
            border: 1px solid var(--accent-red);
            border-radius: 6px;
            padding: 14px;
            color: #ff7b72;
            margin-bottom: 20px;
            font-weight: 600;
        }}
        .info-banner {{
            background: rgba(88, 166, 255, 0.1);
            border: 1px solid var(--accent-color);
            border-radius: 6px;
            padding: 10px 14px;
            margin-bottom: 14px;
            font-size: 13px;
            color: var(--accent-color);
        }}
    </style>
</head>
<body>
<div class=""container"">

    <header>
        <div style=""display: flex; justify-content: space-between; align-items: flex-start;"">
            <div>
                <h1>ExeScope Dynamic Sandbox Report</h1>
                <div style=""color: var(--text-muted); font-size: 13px;"">
                    Autonomous behavioral analysis artifact. Generated UTC: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}
                </div>
            </div>
            <div>
                <span class=""badge {(metadata.IsElevated ? "badge-danger" : "badge-warn")}"">
                    {(metadata.IsElevated ? "Elevated (Kernel ETW)" : "Standard User")}
                </span>
            </div>
        </div>

        {(metadata.TargetModifiedAfterSelection ? $@"
        <div class=""warning-banner"" style=""margin-top: 16px;"">
            ⚠ WARNING: Target executable on disk changed after initial selection! {Escape(metadata.TargetModifiedWarning ?? "")}
        </div>" : "")}

        <div class=""grid-summary"">
            <div class=""stat-card"">
                <div class=""label"">Target File</div>
                <div class=""value mono"">{exeName}</div>
            </div>
            <div class=""stat-card"">
                <div class=""label"">Authenticode Signature</div>
                <div class=""value"">{signatureStatus}</div>
            </div>
            <div class=""stat-card"">
                <div class=""label"">SHA-256</div>
                <div class=""value mono"" style=""font-size: 13px;"">{exeHash}</div>
            </div>
            <div class=""stat-card"">
                <div class=""label"">Target Launch (UTC)</div>
                <div class=""value mono"">{startTime}</div>
            </div>
            <div class=""stat-card"">
                <div class=""label"">Events Recorded / Dropped</div>
                <div class=""value"">{metadata.TotalEventsRecorded.ToString("N0", CultureInfo.InvariantCulture)} / {metadata.TotalEventsDropped.ToString("N0", CultureInfo.InvariantCulture)}</div>
            </div>
            <div class=""stat-card"">
                <div class=""label"">Artifacts Preserved</div>
                <div class=""value"">{metadata.TotalArtifactsSaved.ToString("N0", CultureInfo.InvariantCulture)} ({(metadata.TotalArtifactBytesWritten / 1024).ToString("N0", CultureInfo.InvariantCulture)} KB)</div>
            </div>
        </div>
    </header>

    <div class=""tabs"">
        <button class=""tab-btn active"" onclick=""showTab('tab-tree')"">Process Tree</button>
        <button class=""tab-btn"" onclick=""showTab('tab-files')"">File Events ({events.Count(e => e.Category == EventCategory.File)})</button>
        <button class=""tab-btn"" onclick=""showTab('tab-registry')"">Registry Events ({events.Count(e => e.Category == EventCategory.Registry)})</button>
        <button class=""tab-btn"" onclick=""showTab('tab-network')"">Network Events ({events.Count(e => e.Category == EventCategory.Network)})</button>
        <button class=""tab-btn"" onclick=""showTab('tab-artifacts')"">Saved Artifacts ({artifacts.Count})</button>
        <button class=""tab-btn"" onclick=""showTab('tab-diagnostics')"">Diagnostics ({diagnostics.Count})</button>
    </div>

    <!-- Process Tree Tab -->
    <div id=""tab-tree"" class=""tab-panel active"">");

        if (processTree != null)
        {
            RenderProcessNodeHtml(sb, processTree);
        }
        else
        {
            sb.Append("<p style='color: var(--text-muted);'>No process tree recorded.</p>");
        }

        sb.Append(@"
    </div>

    <!-- File Events Tab -->
    <div id=""tab-files"" class=""tab-panel"">
        <input type=""text"" class=""search-box"" placeholder=""Search file operations or paths..."" onkeyup=""filterTable('files-table', this.value)"">");

        var fileEvents = events.OfType<FileEvent>().ToList();
        if (fileEvents.Count > maxTableRows)
        {
            sb.Append($@"<div class=""info-banner"">Showing first {maxTableRows.ToString("N0", CultureInfo.InvariantCulture)} of {fileEvents.Count.ToString("N0", CultureInfo.InvariantCulture)} file events. The full dataset is saved in events.jsonl.</div>");
        }

        sb.Append(@"
        <table id=""files-table"">
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>Process</th>
                    <th>Operation</th>
                    <th>Path</th>
                    <th>Result</th>
                    <th>Offset/Size</th>
                </tr>
            </thead>
            <tbody>");

        int renderedFiles = 0;
        foreach (var fe in fileEvents)
        {
            if (++renderedFiles > maxTableRows) break;
            string offsetSize = (fe.ByteOffset.HasValue || fe.ByteCount.HasValue) ? $"Off:{fe.ByteOffset} Len:{fe.ByteCount}" : "-";
            sb.Append($@"
                <tr>
                    <td class=""mono"">{fe.TimestampUtc:HH:mm:ss.fff}</td>
                    <td>{Escape(fe.ProcessImage)} ({fe.ProcessId})</td>
                    <td><span class=""badge badge-info"">{fe.Operation}</span></td>
                    <td class=""mono"">{Escape(fe.Path)}</td>
                    <td>{Escape(fe.Result)}</td>
                    <td class=""mono"">{offsetSize}</td>
                </tr>");
        }

        sb.Append(@"
            </tbody>
        </table>
    </div>

    <!-- Registry Events Tab -->
    <div id=""tab-registry"" class=""tab-panel"">
        <input type=""text"" class=""search-box"" placeholder=""Search registry keys or values..."" onkeyup=""filterTable('reg-table', this.value)"">");

        var regEvents = events.OfType<RegistryEvent>().ToList();
        if (regEvents.Count > maxTableRows)
        {
            sb.Append($@"<div class=""info-banner"">Showing first {maxTableRows.ToString("N0", CultureInfo.InvariantCulture)} of {regEvents.Count.ToString("N0", CultureInfo.InvariantCulture)} registry events. The full dataset is saved in events.jsonl.</div>");
        }

        sb.Append(@"
        <table id=""reg-table"">
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>Process</th>
                    <th>Operation</th>
                    <th>Key / Value</th>
                    <th>Result</th>
                </tr>
            </thead>
            <tbody>");

        int renderedReg = 0;
        foreach (var re in regEvents)
        {
            if (++renderedReg > maxTableRows) break;
            string target = Escape(re.KeyPath) + (string.IsNullOrEmpty(re.ValueName) ? "" : $" \\ {Escape(re.ValueName)}");
            sb.Append($@"
                <tr>
                    <td class=""mono"">{re.TimestampUtc:HH:mm:ss.fff}</td>
                    <td>{Escape(re.ProcessImage)} ({re.ProcessId})</td>
                    <td><span class=""badge badge-warn"">{re.Operation}</span></td>
                    <td class=""mono"">{target}</td>
                    <td>{Escape(re.Result)}</td>
                </tr>");
        }

        sb.Append(@"
            </tbody>
        </table>
    </div>

    <!-- Network Events Tab -->
    <div id=""tab-network"" class=""tab-panel"">
        <input type=""text"" class=""search-box"" placeholder=""Search addresses, ports, or DNS..."" onkeyup=""filterTable('net-table', this.value)"">");

        var netEvents = events.OfType<NetworkEvent>().ToList();
        if (netEvents.Count > maxTableRows)
        {
            sb.Append($@"<div class=""info-banner"">Showing first {maxTableRows.ToString("N0", CultureInfo.InvariantCulture)} of {netEvents.Count.ToString("N0", CultureInfo.InvariantCulture)} network events. The full dataset is saved in events.jsonl.</div>");
        }

        sb.Append(@"
        <table id=""net-table"">
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>Process</th>
                    <th>Protocol</th>
                    <th>Local Endpoint</th>
                    <th>Remote Endpoint / DNS</th>
                    <th>Correlation</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>");

        int renderedNet = 0;
        foreach (var ne in netEvents)
        {
            if (++renderedNet > maxTableRows) break;
            string remoteDesc = ne.Protocol == NetworkProtocol.DNS ? $"DNS: {Escape(ne.DnsQuery ?? "")} -> {Escape(ne.DnsResponse ?? "")}" : $"{Escape(ne.RemoteAddress)}:{ne.RemotePort}";
            sb.Append($@"
                <tr>
                    <td class=""mono"">{ne.TimestampUtc:HH:mm:ss.fff}</td>
                    <td>{Escape(ne.ProcessImage)} ({ne.ProcessId})</td>
                    <td><span class=""badge badge-success"">{ne.Protocol}</span></td>
                    <td class=""mono"">{Escape(ne.LocalAddress)}:{ne.LocalPort}</td>
                    <td class=""mono"">{remoteDesc}</td>
                    <td>{ne.CorrelationMethod}</td>
                    <td><span class=""badge {(ne.Confidence == "High" ? "badge-success" : "badge-warn")}"">{ne.Confidence}</span></td>
                </tr>");
        }

        sb.Append(@"
            </tbody>
        </table>
    </div>

    <!-- Artifacts Tab -->
    <div id=""tab-artifacts"" class=""tab-panel"">
        <input type=""text"" class=""search-box"" placeholder=""Search saved artifacts..."" onkeyup=""filterTable('art-table', this.value)"">
        <table id=""art-table"">
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>Original Path</th>
                    <th>Artifact Name</th>
                    <th>SHA-256</th>
                    <th>Size (Bytes)</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>");

        foreach (var art in artifacts)
        {
            sb.Append($@"
                <tr>
                    <td class=""mono"">{art.TimestampUtc:HH:mm:ss.fff}</td>
                    <td class=""mono"">{Escape(art.OriginalPath)}</td>
                    <td class=""mono"">{Escape(art.ArtifactFileName)}</td>
                    <td class=""mono"">{Escape(art.Sha256)}</td>
                    <td>{art.SizeBytes.ToString("N0", CultureInfo.InvariantCulture)}</td>
                    <td><span class=""badge {(art.CopyStatus == ArtifactCopyStatus.Success ? "badge-success" : "badge-danger")}"">{art.CopyStatus}</span></td>
                </tr>");
        }

        sb.Append(@"
            </tbody>
        </table>
    </div>

    <!-- Diagnostics Tab -->
    <div id=""tab-diagnostics"" class=""tab-panel"">
        <table id=""diag-table"">
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>Level</th>
                    <th>Source</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>");

        foreach (var d in diagnostics)
        {
            string badgeClass = d.Level switch
            {
                LogLevel.Error or LogLevel.Fatal => "badge-danger",
                LogLevel.Warning => "badge-warn",
                _ => "badge-info"
            };
            sb.Append($@"
                <tr>
                    <td class=""mono"">{d.TimestampUtc:HH:mm:ss.fff}</td>
                    <td><span class=""badge {badgeClass}"">{d.Level}</span></td>
                    <td>{Escape(d.Source)}</td>
                    <td>{Escape(d.Message)}</td>
                </tr>");
        }

        sb.Append(@"
            </tbody>
        </table>
    </div>

</div>

<script>
    function showTab(tabId) {
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(tabId).classList.add('active');
        event.target.classList.add('active');
    }

    function filterTable(tableId, query) {
        query = query.toLowerCase();
        const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
        rows.forEach(row => {
            const text = row.innerText.toLowerCase();
            row.style.display = text.includes(query) ? '' : 'none';
        });
    }
</script>
</body>
</html>");

        return sb.ToString();
    }

    private static void RenderProcessNodeHtml(StringBuilder sb, ProcessNode node)
    {
        sb.Append($@"
        <div class=""tree-node"">
            <div style=""display: flex; justify-content: space-between;"">
                <strong>{Escape(node.ImageName)}</strong>
                <span class=""mono"">PID: {node.ProcessId} | Parent: {node.ParentProcessId}</span>
            </div>
            <div style=""font-size: 12px; color: var(--text-muted); margin-top: 4px;"" class=""mono"">
                Path: {Escape(node.ImagePath)}<br>
                Cmd: {Escape(node.CommandLine)}<br>
                Start (UTC): {node.StartTimeUtc:yyyy-MM-dd HH:mm:ss.fff}" +
                (node.ExitTimeUtc.HasValue ? $" | Exit (UTC): {node.ExitTimeUtc:yyyy-MM-dd HH:mm:ss.fff} (ExitCode: {node.ExitCode})" : " | Running") + @"
            </div>");

        if (node.Children.Count > 0)
        {
            sb.Append(@"<div class=""children"">");
            foreach (var child in node.Children)
            {
                RenderProcessNodeHtml(sb, child);
            }
            sb.Append(@"</div>");
        }

        sb.Append("</div>");
    }

    private static string Escape(string text)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;
        return WebUtility.HtmlEncode(text);
    }
}
