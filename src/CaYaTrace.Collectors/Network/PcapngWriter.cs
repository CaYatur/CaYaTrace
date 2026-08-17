using System.Buffers.Binary;
using System.Text;

namespace CaYaTrace.Collectors.Network;

/// <summary>
/// Writes packets in the format everything downstream already reads.
/// </summary>
/// <remarks>
/// <para>
/// Small on purpose. libpcap can write a capture file itself, but it writes the classic
/// format, and this tool already has reassembly, direction, protocol detection and content
/// extraction sitting behind pcapng. One format in means one path to keep working, and the
/// three blocks needed to produce a valid file are a section header, an interface
/// description and one enhanced packet block each.
/// </para>
/// <para>
/// Little-endian throughout, which is what the byte-order magic in the section header
/// declares and what every reader on the platform prefers.
/// </para>
/// </remarks>
internal sealed class PcapngWriter : IDisposable
{
    private const uint SectionHeader = 0x0A0D0D0A;
    private const uint InterfaceDescription = 0x00000001;
    private const uint EnhancedPacket = 0x00000006;
    private const uint ByteOrderMagic = 0x1A2B3C4D;

    private readonly FileStream _stream;
    private readonly object _gate = new();
    private bool _closed;

    public PcapngWriter(string path, int linkType, int snapLength, string interfaceName)
    {
        _stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024);

        WriteSectionHeader();
        WriteInterfaceDescription(linkType, snapLength, interfaceName);
        _stream.Flush();
    }

    /// <summary>
    /// Appends one packet.
    /// </summary>
    /// <param name="seconds">Seconds since the epoch, as libpcap reported them.</param>
    /// <param name="microseconds">Microseconds within that second.</param>
    /// <param name="data">The captured bytes.</param>
    /// <param name="originalLength">
    /// How long the packet was on the wire, which is larger than <paramref name="data"/>
    /// when the snap length cut it short. Recording it is what lets a reader say a
    /// conversation was truncated instead of quietly reporting less traffic than happened.
    /// </param>
    public void Write(long seconds, long microseconds, byte[] data, int originalLength)
    {
        lock (_gate)
        {
            if (_closed) return;

            // The pcapng timestamp is one 64-bit count of microseconds, split across two
            // 32-bit fields, high half first.
            ulong timestamp = (ulong)(seconds * 1_000_000L + microseconds);

            int padded = (data.Length + 3) & ~3;
            int total = 32 + padded;

            Span<byte> header = stackalloc byte[28];
            BinaryPrimitives.WriteUInt32LittleEndian(header[..4], EnhancedPacket);
            BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(4, 4), (uint)total);
            BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(8, 4), 0);                       // interface 0
            BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(12, 4), (uint)(timestamp >> 32));
            BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(16, 4), (uint)timestamp);
            BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(20, 4), (uint)data.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(24, 4), (uint)Math.Max(originalLength, data.Length));

            _stream.Write(header);
            _stream.Write(data, 0, data.Length);

            for (int i = data.Length; i < padded; i++) _stream.WriteByte(0);

            Span<byte> trailer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(trailer, (uint)total);
            _stream.Write(trailer);
        }
    }

    private void WriteSectionHeader()
    {
        Span<byte> block = stackalloc byte[28];
        BinaryPrimitives.WriteUInt32LittleEndian(block[..4], SectionHeader);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(4, 4), 28);
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(8, 4), ByteOrderMagic);
        BinaryPrimitives.WriteUInt16LittleEndian(block.Slice(12, 2), 1);     // major
        BinaryPrimitives.WriteUInt16LittleEndian(block.Slice(14, 2), 0);     // minor
        BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(16, 8), unchecked((ulong)-1L)); // section length unknown
        BinaryPrimitives.WriteUInt32LittleEndian(block.Slice(24, 4), 28);

        _stream.Write(block);
    }

    /// <summary>
    /// Describes the one interface, and names it.
    /// </summary>
    /// <remarks>
    /// The name is written as an <c>if_name</c> option so the file says where it came from
    /// when somebody opens it in Wireshark six months later. An unlabelled capture of a
    /// loopback adapter looks exactly like an unlabelled capture of anything else.
    /// </remarks>
    private void WriteInterfaceDescription(int linkType, int snapLength, string interfaceName)
    {
        byte[] name = Encoding.UTF8.GetBytes(interfaceName);
        if (name.Length > 250) name = name[..250];

        int optionLength = 4 + ((name.Length + 3) & ~3);
        int total = 20 + optionLength + 4;   // header + name option + end-of-options

        var block = new byte[total];
        Span<byte> span = block;

        BinaryPrimitives.WriteUInt32LittleEndian(span[..4], InterfaceDescription);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(4, 4), (uint)total);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(8, 2), (ushort)linkType);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(10, 2), 0);      // reserved
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(12, 4), (uint)snapLength);

        int offset = 16;
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), 2);              // if_name
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset + 2, 2), (ushort)name.Length);
        name.CopyTo(span.Slice(offset + 4, name.Length));
        offset += optionLength;

        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), 0);              // opt_endofopt
        offset += 4;

        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), (uint)total);

        _stream.Write(block, 0, total);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_closed) return;
            _closed = true;

            try
            {
                _stream.Flush();
                _stream.Dispose();
            }
            catch (IOException)
            {
                // A capture file that could not be flushed is already reported by the
                // packet counts not matching; throwing from a stop helps nobody.
            }
        }
    }
}
