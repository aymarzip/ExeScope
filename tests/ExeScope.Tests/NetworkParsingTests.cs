using ExeScope.Core.Diagnostics;
using ExeScope.Core.Models;
using ExeScope.Engine.Network;
using ExeScope.Engine.Tracking;
using Xunit;

namespace ExeScope.Tests;

public class NetworkParsingTests
{
    private readonly RawSocketCapture _capture;

    public NetworkParsingTests()
    {
        var targetInfo = new TargetExeInfo { OriginalPath = @"C:\dummy.exe", CanonicalPath = @"C:\dummy.exe", FileName = "dummy.exe" };
        var logger = new DiagnosticLogger();
        var correlation = new ProcessCorrelationEngine(targetInfo, logger);
        var pcap = new PcapngWriter(Path.Combine(Path.GetTempPath(), $"dummy_{Guid.NewGuid():N}.pcapng"));
        _capture = new RawSocketCapture(correlation, pcap, logger);
    }

    [Fact]
    public void IsPacketRelevant_ReturnsFalse_ForInvalidOrTruncatedPackets()
    {
        Assert.False(_capture.IsPacketRelevant(null!));
        Assert.False(_capture.IsPacketRelevant(Array.Empty<byte>()));
        Assert.False(_capture.IsPacketRelevant(new byte[10])); // < 20 bytes
    }

    [Fact]
    public void IsPacketRelevant_ReturnsFalse_ForNonIpv4()
    {
        // IPv6 header starts with 0x60
        byte[] ipv6 = new byte[40];
        ipv6[0] = 0x60;
        Assert.False(_capture.IsPacketRelevant(ipv6));
    }

    [Fact]
    public void IsPacketRelevant_ReturnsFalse_ForInvalidIhl()
    {
        byte[] packet = new byte[24];
        packet[0] = 0x43; // Version 4, IHL 3 (12 bytes, invalid for IPv4)
        Assert.False(_capture.IsPacketRelevant(packet));
    }

    [Fact]
    public void IsPacketRelevant_ReturnsFalse_ForNonTcpUdpProtocols()
    {
        _capture.RegisterTrackedPort(80);

        byte[] icmp = new byte[28];
        icmp[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        icmp[9] = 1;    // ICMP protocol
        Assert.False(_capture.IsPacketRelevant(icmp));
    }

    [Fact]
    public void IsPacketRelevant_MatchesRegisteredTcpSourceOrDestPort()
    {
        _capture.RegisterTrackedPort(443);
        _capture.RegisterTrackedPort(54321);

        // TCP packet with sport=54321, dport=443
        byte[] tcpPacket = new byte[24];
        tcpPacket[0] = 0x45; // IPv4, IHL=5
        tcpPacket[9] = 6;    // TCP
        tcpPacket[20] = 0xD4; tcpPacket[21] = 0x31; // sport = 54321 (0xD431)
        tcpPacket[22] = 0x01; tcpPacket[23] = 0xBB; // dport = 443 (0x01BB)

        Assert.True(_capture.IsPacketRelevant(tcpPacket));

        // TCP packet with non-monitored ports: sport=1111, dport=2222
        byte[] otherTcp = new byte[24];
        otherTcp[0] = 0x45;
        otherTcp[9] = 6;
        otherTcp[20] = 0x04; otherTcp[21] = 0x57; // sport = 1111
        otherTcp[22] = 0x08; otherTcp[23] = 0xAE; // dport = 2222

        Assert.False(_capture.IsPacketRelevant(otherTcp));
    }

    [Fact]
    public void IsPacketRelevant_MatchesUdpPortsWithIpHeaderOptions()
    {
        _capture.RegisterTrackedPort(53); // DNS port

        // IPv4 with IHL = 6 (24 bytes header)
        byte[] udpWithOpts = new byte[28];
        udpWithOpts[0] = 0x46; // Version 4, IHL=6 (24 bytes)
        udpWithOpts[9] = 17;   // UDP
        udpWithOpts[24] = 0xC0; udpWithOpts[25] = 0x00; // sport = 49152
        udpWithOpts[26] = 0x00; udpWithOpts[27] = 0x35; // dport = 53 (DNS)

        Assert.True(_capture.IsPacketRelevant(udpWithOpts));
    }
}
