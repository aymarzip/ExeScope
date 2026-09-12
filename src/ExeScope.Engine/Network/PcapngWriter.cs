namespace ExeScope.Engine.Network;

public sealed class PcapngWriter : IDisposable
{
    private const uint BlockTypeSectionHeader = 0x0A0D0D0A;
    private const uint BlockTypeInterfaceDescription = 0x00000001;
    private const uint BlockTypeEnhancedPacket = 0x00000006;
    private const uint ByteOrderMagic = 0x1A2B3C4D;

    private readonly FileStream _fileStream;
    private readonly BinaryWriter _writer;
    private readonly object _lock = new();
    private bool _isDisposed;
    private long _packetsWritten;
    private int _unflushedPackets;

    public long PacketsWritten => Interlocked.Read(ref _packetsWritten);
    public string FilePath { get; }

    public PcapngWriter(string filePath, ushort linkType = 101) // 101 = LINKTYPE_RAW (raw IP)
    {
        FilePath = filePath;
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        _fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read, bufferSize: 65536);
        _writer = new BinaryWriter(_fileStream);

        WriteSectionHeaderBlock();
        WriteInterfaceDescriptionBlock(linkType);
    }

    private void WriteSectionHeaderBlock()
    {
        _writer.Write(BlockTypeSectionHeader);
        _writer.Write(28);
        _writer.Write(ByteOrderMagic);
        _writer.Write((ushort)1);
        _writer.Write((ushort)0);
        _writer.Write((long)-1);
        _writer.Write(28);
        _writer.Flush();
    }

    private void WriteInterfaceDescriptionBlock(ushort linkType)
    {
        _writer.Write(BlockTypeInterfaceDescription);
        _writer.Write(20);
        _writer.Write(linkType);
        _writer.Write((ushort)0);
        _writer.Write((uint)65535);
        _writer.Write(20);
        _writer.Flush();
    }

    public void WritePacket(byte[] packetData, DateTime timestampUtc)
    {
        if (_isDisposed || packetData == null || packetData.Length == 0)
            return;

        lock (_lock)
        {
            if (_isDisposed)
                return;

            uint capLen = (uint)packetData.Length;
            uint origLen = (uint)packetData.Length;

            int padding = (4 - ((int)capLen % 4)) % 4;
            uint blockTotalLen = (uint)(32 + capLen + padding);

            long epochTicks = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;
            long deltaTicks = timestampUtc.Ticks - epochTicks;
            ulong microSeconds = (ulong)(deltaTicks / 10);

            uint tsHigh = (uint)(microSeconds >> 32);
            uint tsLow = (uint)(microSeconds & 0xFFFFFFFF);

            _writer.Write(BlockTypeEnhancedPacket);
            _writer.Write(blockTotalLen);
            _writer.Write((uint)0);
            _writer.Write(tsHigh);
            _writer.Write(tsLow);
            _writer.Write(capLen);
            _writer.Write(origLen);
            _writer.Write(packetData);

            if (padding > 0)
            {
                for (int i = 0; i < padding; i++)
                    _writer.Write((byte)0);
            }

            _writer.Write(blockTotalLen);

            _unflushedPackets++;
            if (_unflushedPackets >= 100)
            {
                _writer.Flush();
                _unflushedPackets = 0;
            }

            Interlocked.Increment(ref _packetsWritten);
        }
    }

    public void Dispose()
    {
        if (_isDisposed)
            return;

        _isDisposed = true;
        lock (_lock)
        {
            try
            {
                _writer.Flush();
                _fileStream.Flush();
                _writer.Dispose();
                _fileStream.Dispose();
            }
            catch
            {
            }
        }
    }
}
