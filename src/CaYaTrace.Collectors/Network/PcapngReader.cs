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

        ReadPackets(path, maxPackets, (segment, timestamp) =>
        {
            FlowKey key = segment.Key.Canonical();

            if (!flows.TryGetValue(key, out CapturedFlow? flow))
            {
                flow = new CapturedFlow { Key = key, First = timestamp, Last = timestamp };
                flows[key] = flow;
            }

            flow.Packets++;
            flow.Bytes += segment.WireLength;
            if (timestamp > flow.Last) flow.Last = timestamp;
            if (timestamp < flow.First && timestamp != DateTimeOffset.UnixEpoch) flow.First = timestamp;
        });

        return flows.Values.ToList();
    }

    /// <summary>
    /// Walks a capture and hands each transport segment, with its payload, to a callback.
    /// </summary>
    /// <remarks>
    /// The single parse everything else is built on. Flow totals and stream reassembly
    /// used to be two readings of the same file, which is both slower and — more to the
    /// point — two places for the packet layout to be interpreted slightly differently.
    /// </remarks>
    public static void ReadPackets(string path, int maxPackets, Action<Segment, DateTimeOffset> onSegment)
    {
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
                    if (TryParseSegment(data, linkType, originalLength, out Segment segment))
                        onSegment(segment, timestamp);
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
                    if (TryParseSegment(data, linkType, originalLength, out Segment simple))
                        onSegment(simple, DateTimeOffset.UnixEpoch);
                    packets++;
                    break;
                }
            }

            stream.Position = blockStart + blockLength;
        }
    }

    private static bool TryParseSegment(byte[] frame, int linkType, uint wireLength, out Segment segment)
    {
        segment = default;

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

            if (etherType is not (0x0800 or 0x86DD)) return false;
        }

        return TryParseIp(frame, offset, wireLength, out segment);
    }

    private static bool TryParseIp(byte[] frame, int offset, uint wireLength, out Segment segment)
    {
        segment = default;
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

            // The IP header carries the real length; the captured frame may be padded to
            // the Ethernet minimum, and treating that padding as payload appends nulls to
            // every short conversation.
            int totalLength = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(offset + 2, 2));
            int ipEnd = totalLength > 0 ? Math.Min(frame.Length, offset + totalLength) : frame.Length;

            return TryParseTransport(
                frame, offset + headerLength, ipEnd, protocol, source, destination, wireLength, out segment);
        }

        if (version == 6)
        {
            if (frame.Length < offset + 40) return false;

            byte nextHeader = frame[offset + 6];
            var source = new IPAddress(frame.AsSpan(offset + 8, 16).ToArray());
            var destination = new IPAddress(frame.AsSpan(offset + 24, 16).ToArray());

            int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(offset + 4, 2));
            int ipEnd = payloadLength > 0 ? Math.Min(frame.Length, offset + 40 + payloadLength) : frame.Length;

            // Extension headers are not walked. They are rare in the traffic this tool
            // observes, and a wrong offset would produce fabricated ports — worse than
            // skipping the packet.
            return TryParseTransport(
                frame, offset + 40, ipEnd, nextHeader, source, destination, wireLength, out segment);
        }

        return false;
    }

    private static bool TryParseTransport(
        byte[] frame, int offset, int ipEnd, byte protocol,
        IPAddress source, IPAddress destination, uint wireLength, out Segment segment)
    {
        segment = default;
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

        uint sequence = 0;
        bool syn = false;
        bool ack = false;
        byte[] payload = Array.Empty<byte>();

        if (transport == TransportProtocol.Tcp && frame.Length >= offset + 20)
        {
            sequence = BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(offset + 4, 4));

            byte flags = frame[offset + 13];
            syn = (flags & 0x02) != 0;
            ack = (flags & 0x10) != 0;

            int dataOffset = (frame[offset + 12] >> 4) * 4;
            if (dataOffset >= 20)
            {
                int start = offset + dataOffset;
                if (start < ipEnd) payload = frame[start..ipEnd];
            }
        }
        else if (transport == TransportProtocol.Udp && frame.Length >= offset + 8)
        {
            int start = offset + 8;
            if (start < ipEnd) payload = frame[start..ipEnd];
        }

        segment = new Segment(
            new FlowKey(transport, source, sourcePort, destination, destinationPort),
            source, sourcePort, sequence, syn, ack, wireLength, payload);

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
