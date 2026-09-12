using System.Net;
using System.Net.Sockets;
using ExeScope.Core.Diagnostics;
using ExeScope.Engine.Tracking;

namespace ExeScope.Engine.Network;

public class RawSocketCapture : IAsyncDisposable
{
    private readonly ProcessCorrelationEngine _correlationEngine;
    private readonly PcapngWriter _pcapWriter;
    private readonly IDiagnosticLogger _logger;
    private readonly HashSet<int> _monitoredPorts = new();
    private readonly object _portLock = new();

    private Socket? _socket;
    private Thread? _captureThread;
    private bool _isRunning;
    private bool _isDisposed;

    public const string CaptureExplanation =
        "Raw Socket promiscuous packet capture monitors network packets at the network layer. " +
        "On Windows, raw sockets require Administrator privileges and by default receive all network traffic on the bound adapter. " +
        "To minimize saving extraneous system traffic and protect user privacy, ExeScope applies strict filtering: " +
        "only packets whose local port matches active sockets opened by tracked target processes will be captured and written to PCAPNG.";

    public RawSocketCapture(ProcessCorrelationEngine correlationEngine, PcapngWriter pcapWriter, IDiagnosticLogger logger)
    {
        _correlationEngine = correlationEngine;
        _pcapWriter = pcapWriter;
        _logger = logger;
    }

    public void RegisterTrackedPort(int port)
    {
        if (port > 0 && port <= 65535)
        {
            lock (_portLock)
            {
                _monitoredPorts.Add(port);
            }
        }
    }

    public void Start()
    {
        if (_isRunning) return;

        try
        {
            // Bind to loopback or first active IPv4 address
            var localIp = GetLocalIpAddress();
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            _socket.Bind(new IPEndPoint(localIp, 0));

            // SIO_RCVALL = 0x98000001 (Receive all packets)
            byte[] inValue = new byte[] { 1, 0, 0, 0 };
            byte[] outValue = new byte[4];
            _socket.IOControl(unchecked((int)0x98000001), inValue, outValue);

            _isRunning = true;
            _captureThread = new Thread(CaptureLoop)
            {
                IsBackground = true,
                Name = "ExeScope_RawSocketCapture"
            };
            _captureThread.Start();

            _logger.Info("PacketCapture", $"Promiscuous packet capture active on {localIp}. Strict process-port filtering enabled.");
        }
        catch (SocketException sEx)
        {
            _logger.Warn("PacketCapture", $"Packet capture could not bind raw socket (Administrator required, or promiscuous mode restricted): {sEx.Message}");
        }
        catch (Exception ex)
        {
            _logger.Error("PacketCapture", "Failed to start raw packet capture", ex);
        }
    }

    private IPAddress GetLocalIpAddress()
    {
        try
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                {
                    return ip;
                }
            }
        }
        catch { }
        return IPAddress.Loopback;
    }

    private void CaptureLoop()
    {
        byte[] buffer = new byte[65536];

        while (_isRunning && _socket != null)
        {
            try
            {
                int received = _socket.Receive(buffer);
                if (received > 20) // IPv4 header is at least 20 bytes
                {
                    byte[] packet = new byte[received];
                    Buffer.BlockCopy(buffer, 0, packet, 0, received);

                    if (IsPacketRelevant(packet))
                    {
                        _pcapWriter.WritePacket(packet, DateTime.UtcNow);
                    }
                }
            }
            catch (SocketException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (_isRunning)
                    _logger.Error("PacketCapture", "Error reading packet from raw socket", ex);
            }
        }
    }

    public bool IsPacketRelevant(byte[] packet)
    {
        if (packet == null || packet.Length < 20)
            return false;

        int ipVersion = (packet[0] >> 4) & 0x0F;
        if (ipVersion != 4)
            return false;

        int ipHeaderLen = (packet[0] & 0x0F) * 4;
        if (ipHeaderLen < 20 || packet.Length < ipHeaderLen + 4)
            return false;

        byte protocol = packet[9];
        if (protocol != 6 && protocol != 17)
            return false;

        int srcPort = (packet[ipHeaderLen] << 8) | packet[ipHeaderLen + 1];
        int dstPort = (packet[ipHeaderLen + 2] << 8) | packet[ipHeaderLen + 3];

        if (srcPort <= 0 && dstPort <= 0)
            return false;

        lock (_portLock)
        {
            return _monitoredPorts.Contains(srcPort) || _monitoredPorts.Contains(dstPort);
        }
    }

    public void Stop()
    {
        _isRunning = false;
        try
        {
            _socket?.Close();
            _socket?.Dispose();
            _socket = null;
        }
        catch { }
    }

    public async ValueTask DisposeAsync()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        Stop();
        await Task.CompletedTask;
    }
}
