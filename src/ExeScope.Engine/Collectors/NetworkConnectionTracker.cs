using System.Net;
using System.Runtime.InteropServices;
using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Tracking;

namespace ExeScope.Engine.Collectors;

public class NetworkConnectionTracker : IEventCollector
{
    #region Win32 IP Helper P/Invoke

    private const int AF_INET = 2; // IPv4
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved = 0);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    #endregion

    private readonly ProcessCorrelationEngine _correlationEngine;
    private readonly IDiagnosticLogger _logger;
    private readonly HashSet<string> _seenConnections = new();
    private CancellationTokenSource? _cts;
    private Task? _pollTask;
    private bool _isRunning;
    private long _nextEventId = 2000;

    public string Name => "IP Helper Network Socket Monitor";
    public bool IsSupported => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
    public string StatusDescription { get; private set; } = "Ready";

    public event Action<AnalysisEvent>? EventEmitted;

    public NetworkConnectionTracker(ProcessCorrelationEngine correlationEngine, IDiagnosticLogger logger)
    {
        _correlationEngine = correlationEngine;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (_isRunning)
            return Task.CompletedTask;

        _isRunning = true;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _pollTask = Task.Run(() => PollLoopAsync(_cts.Token), _cts.Token);
        StatusDescription = "Active (Monitoring TCP/UDP endpoints)";
        _logger.Info("NetworkTracker", "Socket monitor started via GetExtendedTcpTable/GetExtendedUdpTable.");
        return Task.CompletedTask;
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _isRunning)
        {
            try
            {
                PollTcpSockets();
                PollUdpSockets();
                await Task.Delay(250, ct); // 250ms polling interval
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error("NetworkTracker", "Error polling network sockets", ex);
                await Task.Delay(1000, ct);
            }
        }
    }

    private void PollTcpSockets()
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (size == 0) return;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL) == 0)
            {
                int numEntries = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, 4);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                var nowUtc = DateTime.UtcNow;

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    int pid = (int)row.owningPid;

                    // Verify if this process is tracked during this time window
                    if (_correlationEngine.IsProcessTracked(pid, nowUtc, out var tracked))
                    {
                        string localIp = new IPAddress(BitConverter.GetBytes(row.localAddr)).ToString();
                        int localPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort);
                        string remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();
                        int remotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.remotePort);

                        string stateName = GetTcpStateName(row.state);
                        string connKey = $"TCP_{pid}_{localIp}:{localPort}_{remoteIp}:{remotePort}_{stateName}";

                        if (_seenConnections.Add(connKey))
                        {
                            bool isOutbound = remotePort != 0 && remoteIp != "0.0.0.0";
                            string? secNote = remotePort == 443 ? "HTTPS/TLS encrypted endpoint. Payload not decrypted." : null;

                            var evt = new NetworkEvent
                            {
                                EventId = Interlocked.Increment(ref _nextEventId),
                                TimestampUtc = nowUtc,
                                ProcessId = pid,
                                ProcessImage = tracked?.ImageName ?? string.Empty,
                                Protocol = NetworkProtocol.TCP,
                                Direction = isOutbound ? NetworkDirection.Outbound : NetworkDirection.Inbound,
                                LocalAddress = localIp,
                                LocalPort = localPort,
                                RemoteAddress = remoteIp,
                                RemotePort = remotePort,
                                CorrelationMethod = NetworkCorrelationMethod.ExactPidMatch,
                                Confidence = "High",
                                SecurityNotes = secNote,
                                Summary = $"TCP connection: {localIp}:{localPort} -> {remoteIp}:{remotePort} [{stateName}]"
                            };

                            EventEmitted?.Invoke(evt);
                        }
                    }
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private void PollUdpSockets()
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, AF_INET, UDP_TABLE_OWNER_PID);
        if (size == 0) return;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buffer, ref size, true, AF_INET, UDP_TABLE_OWNER_PID) == 0)
            {
                int numEntries = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, 4);
                int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

                var nowUtc = DateTime.UtcNow;

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    int pid = (int)row.owningPid;

                    if (_correlationEngine.IsProcessTracked(pid, nowUtc, out var tracked))
                    {
                        string localIp = new IPAddress(BitConverter.GetBytes(row.localAddr)).ToString();
                        int localPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort);

                        string connKey = $"UDP_{pid}_{localIp}:{localPort}";
                        if (_seenConnections.Add(connKey))
                        {
                            var evt = new NetworkEvent
                            {
                                EventId = Interlocked.Increment(ref _nextEventId),
                                TimestampUtc = nowUtc,
                                ProcessId = pid,
                                ProcessImage = tracked?.ImageName ?? string.Empty,
                                Protocol = NetworkProtocol.UDP,
                                Direction = NetworkDirection.Outbound,
                                LocalAddress = localIp,
                                LocalPort = localPort,
                                RemoteAddress = "0.0.0.0",
                                RemotePort = 0,
                                CorrelationMethod = NetworkCorrelationMethod.ExactPidMatch,
                                Confidence = "High",
                                Summary = $"UDP endpoint opened: {localIp}:{localPort} by {tracked?.ImageName}"
                            };

                            EventEmitted?.Invoke(evt);
                        }
                    }
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string GetTcpStateName(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => $"STATE_{state}"
    };

    public async Task StopAsync()
    {
        if (!_isRunning)
            return;

        _isRunning = false;
        StatusDescription = "Stopped";

        try
        {
            _cts?.Cancel();
            if (_pollTask != null)
            {
                await Task.WhenAny(_pollTask, Task.Delay(1000));
            }
        }
        catch (Exception ex)
        {
            _logger.Error("NetworkTracker", "Error stopping network tracker", ex);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts?.Dispose();
    }
}
