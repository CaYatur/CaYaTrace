using System.Buffers.Binary;
using System.Net;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Collectors.Network;

/// <summary>Per-conversation totals recovered from a capture file.</summary>
public sealed class CapturedFlow
{
    public required FlowKey Key { get; init; }
    public long Packets { get; set; }
    public long Bytes { get; set; }
    public DateTimeOffset First { get; set; }
    public DateTimeOffset Last { get; set; }
}

/// <summary>
/// Reads just enough of a pcapng file to recover conversations and their volumes.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately a minimal reader rather than a full parser. It walks the block
/// structure, decodes link-layer, IP, and transport headers, and stops there — it
/// never reconstructs streams or interprets payload. Everything above the transport
/// header is left to Wireshark, which the capture file is written for.
/// </para>
/// <para>
/// The point is not to duplicate a protocol analyser but to make the capture
/// <em>correlatable</em>: turning packets into 5-tuples lets them join the flow table and
/// pick up the process attribution the kernel provider already established. Packets on
/// their own carry no process, which is the single largest gap in packet-capture-based
/// tooling.
/// </para>
/// </remarks>
public static class PcapngReader
{
    private const uint SectionHeader = 0x0A0D0D0A;
    private const uint InterfaceDescription = 0x00000001;
    private const uint EnhancedPacket = 0x00000006;
    private const uint SimplePacket = 0x00000003;

    private const int LinkTypeEthernet = 1;
    private const int LinkTypeRaw = 101;
    private const int LinkTypeNull = 0;

    /// <summary>
    /// Extracts conversations from a pcapng file.
    /// </summary>
    /// <param name="maxPackets">
    /// Bound on work. A multi-gigabyte capture would otherwise stall session shutdown,
    /// and the totals converge long before then.
    /// </param>
    public static IReadOnlyList<CapturedFlow> ReadFlows(string path, int maxPackets = 2_000_000)
    {
        var flows = new Dictionary<FlowKey, CapturedFlow>();

        using FileStream stream = File.OpenRead(path);
        using var reader = new BinaryReader(stream);

        bool bigEndian = false;
        var linkTypes = new List<int>();
        long tsResolution = 1_000_000;   // pcapng default: microseconds
        int packets = 0;

        while (stream.Position + 12 <= stream.Length && packets < maxPackets)
        {
            long blockStart = stream.Position;

            uint blockType = reader.ReadUInt32();
            uint blockLength = reader.ReadUInt32();

            if (blockType == SectionHeader)
            {
                // The byte-order magic follows the length and defines endianness for
                // this section, including a re-read of the length field itself.
                uint magic = reader.ReadUInt32();
                bigEndian = magic == 0x1A2B3C4D && BitConverter.IsLittleEndian
                    ? false
                    : magic != 0x1A2B3C4D;

                if (bigEndian) blockLength = BinaryPrimitives.ReverseEndianness(blockLength);
                linkTypes.Clear();
            }

            if (blockLength < 12 || blockStart + blockLength > stream.Length)
                break;   // truncated or corrupt; keep what was read rather than throwing

            switch (blockType)
            {
                case InterfaceDescription:
                {
                    stream.Position = blockStart + 8;
                    ushort linkType = Read16(reader, bigEndian);
                    linkTypes.Add(linkType);
                    break;
                }

                case EnhancedPacket:
                {
                    stream.Position = blockStart + 8;
                    uint interfaceId = Read32(reader, bigEndian);
                    uint tsHigh = Read32(reader, bigEndian);
                    uint tsLow = Read32(reader, bigEndian);
                    uint capturedLength = Read32(reader, bigEndian);
                    uint originalLength = Read32(reader, bigEndian);

                    if (capturedLength > blockLength) break;

                    byte[] data = reader.ReadBytes((int)capturedLength);
                    int linkType = interfaceId < linkTypes.Count ? linkTypes[(int)interfaceId] : LinkTypeEthernet;

                    DateTimeOffset timestamp = ToTimestamp(((ulong)tsHigh << 32) | tsLow, tsResolution);
                    Accumulate(flows, data, linkType, originalLength, timestamp);
                    packets++;
                    break;
                }

                case SimplePacket:
                {
                    stream.Position = blockStart + 8;
                    uint originalLength = Read32(reader, bigEndian);
                    int available = (int)Math.Min(originalLength, blockLength - 16);
                    if (available <= 0) break;

                    byte[] data = reader.ReadBytes(available);
                    int linkType = linkTypes.Count > 0 ? linkTypes[0] : LinkTypeEthernet;
                    Accumulate(flows, data, linkType, originalLength, DateTimeOffset.UnixEpoch);
                    packets++;
                    break;
                }
            }

            stream.Position = blockStart + blockLength;
        }

        return flows.Values.ToList();
    }

    private static void Accumulate(
        Dictionary<FlowKey, CapturedFlow> flows, byte[] frame, int linkType,
        uint wireLength, DateTimeOffset timestamp)
    {
        int offset = linkType switch
        {
            LinkTypeEthernet => 14,
            LinkTypeNull => 4,
            LinkTypeRaw => 0,
            _ => 14,
        };

        if (linkType == LinkTypeEthernet && frame.Length >= 14)
        {
            ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(12, 2));

            // 802.1Q and QinQ tags shift the payload; skipping them would misparse
            // every packet on a tagged VLAN.
            while (etherType is 0x8100 or 0x88A8 && frame.Length >= offset + 4)
            {
                offset += 4;
                etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(offset - 2, 2));
            }

            if (etherType is not (0x0800 or 0x86DD)) return;
        }

        if (!TryParseIp(frame, offset, out FlowKey key)) return;

        if (!flows.TryGetValue(key, out CapturedFlow? flow))
        {
            flow = new CapturedFlow { Key = key, First = timestamp, Last = timestamp };
            flows[key] = flow;
        }

        flow.Packets++;
        flow.Bytes += wireLength;
        if (timestamp > flow.Last) flow.Last = timestamp;
        if (timestamp < flow.First && timestamp != DateTimeOffset.UnixEpoch) flow.First = timestamp;
    }

    private static bool TryParseIp(byte[] frame, int offset, out FlowKey key)
    {
        key = FlowKey.Empty;
        if (offset >= frame.Length) return false;

        int version = frame[offset] >> 4;

        if (version == 4)
        {
            if (frame.Length < offset + 20) return false;

            int headerLength = (frame[offset] & 0x0F) * 4;
            if (headerLength < 20 || frame.Length < offset + headerLength) return false;

            byte protocol = frame[offset + 9];
            var source = new IPAddress(frame.AsSpan(offset + 12, 4).ToArray());
            var destination = new IPAddress(frame.AsSpan(offset + 16, 4).ToArray());

            return TryParseTransport(frame, offset + headerLength, protocol, source, destination, out key);
        }

        if (version == 6)
        {
            if (frame.Length < offset + 40) return false;

            byte nextHeader = frame[offset + 6];
            var source = new IPAddress(frame.AsSpan(offset + 8, 16).ToArray());
            var destination = new IPAddress(frame.AsSpan(offset + 24, 16).ToArray());

            // Extension headers are not walked. They are rare in the traffic this tool
            // observes, and a wrong offset would produce fabricated ports — worse than
            // skipping the packet.
            return TryParseTransport(frame, offset + 40, nextHeader, source, destination, out key);
        }

        return false;
    }

    private static bool TryParseTransport(
        byte[] frame, int offset, byte protocol, IPAddress source, IPAddress destination, out FlowKey key)
    {
        key = FlowKey.Empty;
        if (frame.Length < offset + 4) return false;

        TransportProtocol transport = protocol switch
        {
            6 => TransportProtocol.Tcp,
            17 => TransportProtocol.Udp,
            _ => TransportProtocol.Unknown,
        };

        if (transport == TransportProtocol.Unknown) return false;

        ushort sourcePort = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(offset, 2));
        ushort destinationPort = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(offset + 2, 2));

        // Canonicalized so both directions of a conversation accumulate into one entry.
        key = new FlowKey(transport, source, sourcePort, destination, destinationPort).Canonical();
        return true;
    }

    private static DateTimeOffset ToTimestamp(ulong ticks, long resolution)
    {
        if (resolution <= 0) resolution = 1_000_000;
        long seconds = (long)(ticks / (ulong)resolution);
        long fraction = (long)(ticks % (ulong)resolution);

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds)
                .AddTicks(fraction * (TimeSpan.TicksPerSecond / resolution));
        }
        catch (ArgumentOutOfRangeException)
        {
            return DateTimeOffset.UnixEpoch;
        }
    }

    private static ushort Read16(BinaryReader reader, bool bigEndian)
    {
        ushort value = reader.ReadUInt16();
        return bigEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
    }

    private static uint Read32(BinaryReader reader, bool bigEndian)
    {
        uint value = reader.ReadUInt32();
        return bigEndian ? BinaryPrimitives.ReverseEndianness(value) : value;
    }
}
