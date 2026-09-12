using ExeScope.Engine.Network;
using Xunit;

namespace ExeScope.Tests;

public class PcapngWriterTests
{
    [Fact]
    public void PcapngWriter_WritesValidHeadersAndPacketBlock()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid():N}.pcapng");

        try
        {
            using (var writer = new PcapngWriter(tempFile))
            {
                byte[] mockPacket = new byte[]
                {
                    0x45, 0x00, 0x00, 0x28, // IPv4 header: ver=4, IHL=5, totalLen=40
                    0x1c, 0x46, 0x40, 0x00,
                    0x40, 0x06, 0x00, 0x00, // proto=6 (TCP)
                    0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
                    0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
                    0xd4, 0x31, 0x00, 0x50, // sport=54321, dport=80
                    0x00, 0x00, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x50, 0x02, 0x20, 0x00,
                    0x00, 0x00, 0x00, 0x00
                };

                writer.WritePacket(mockPacket, DateTime.UtcNow);
                Assert.Equal(1, writer.PacketsWritten);
            }

            Assert.True(File.Exists(tempFile));
            byte[] fileBytes = File.ReadAllBytes(tempFile);

            // Verify Section Header Block Magic (0x0A0D0D0A) and Byte Order Magic (0x1A2B3C4D)
            uint shbType = BitConverter.ToUInt32(fileBytes, 0);
            uint byteOrder = BitConverter.ToUInt32(fileBytes, 8);

            Assert.Equal(0x0A0D0D0Au, shbType);
            Assert.Equal(0x1A2B3C4Du, byteOrder);

            // Verify Interface Description Block Type (0x00000001) at offset 28
            uint idbType = BitConverter.ToUInt32(fileBytes, 28);
            Assert.Equal(1u, idbType);

            // Verify Enhanced Packet Block Type (0x00000006) at offset 48
            uint epbType = BitConverter.ToUInt32(fileBytes, 48);
            Assert.Equal(6u, epbType);
        }
        finally
        {
            try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
        }
    }
}
