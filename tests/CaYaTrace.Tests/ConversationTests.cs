using System.Net;
using System.Text;
using CaYaTrace.Collectors.Network;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Reassembling what was actually said, from packets.
/// </summary>
/// <remarks>
/// The layer that answers "what did it say" rather than "did it talk to something". It is
/// also the only layer that sees a program talking to a peer on the local network or to a
/// second copy of itself — the HTTP stacks and the intercepting proxy both only see what
/// is routed through them.
/// </remarks>
public sealed class ConversationTests
{
    /// <summary>
    /// A conversation on the local network is not the same thing as one to the internet.
    /// </summary>
    /// <remarks>
    /// The distinction is the point. Traffic leaving the machine is what everything looks
    /// at; traffic to another machine on the same network is how software coordinates
    /// with its own components, and it appears in no firewall log and no proxy.
    /// </remarks>
    [Theory]
    [InlineData("127.0.0.1", PeerScope.Loopback)]
    [InlineData("::1", PeerScope.Loopback)]
    [InlineData("10.0.2.15", PeerScope.LocalNetwork)]
    [InlineData("192.168.1.180", PeerScope.LocalNetwork)]
    [InlineData("172.16.4.1", PeerScope.LocalNetwork)]
    [InlineData("172.32.4.1", PeerScope.Internet)]
    [InlineData("169.254.10.3", PeerScope.LocalNetwork)]
    [InlineData("224.0.0.251", PeerScope.LocalNetwork)]
    [InlineData("93.184.216.34", PeerScope.Internet)]
    [InlineData("fd17:625c:f037:2::1", PeerScope.LocalNetwork)]
    [InlineData("2606:2800:220:1::1", PeerScope.Internet)]
    public void KnowsWhichSideOfTheMachineAPeerIsOn(string address, PeerScope expected)
        => Assert.Equal(expected, ConversationRecorder.Classify(IPAddress.Parse(address)));

    /// <summary>
    /// The server name is the only thing an encrypted conversation says about where it is going.
    /// </summary>
    /// <remarks>
    /// Worth parsing by hand for exactly that reason. The bytes here are a real client
    /// hello shape: record header, handshake header, version, random, empty session id,
    /// one cipher suite, one compression method, then a server-name extension.
    /// </remarks>
    [Fact]
    public void ReadsTheServerNameOutOfAClientHello()
    {
        byte[] hello = BuildClientHello("updates.example.com");

        Assert.Equal("updates.example.com", TlsClientHelloProbe.ReadServerName(hello));
    }

    /// <summary>
    /// Malformed handshakes come from the network and must never throw.
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0x16, 0x03, 0x01 })]
    [InlineData(new byte[] { 0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c })]
    [InlineData(new byte[0])]
    public void RefusesRatherThanThrowingOnAMalformedHandshake(byte[] data)
        => Assert.Null(TlsClientHelloProbe.ReadServerName(data));

    private static byte[] BuildClientHello(string serverName)
    {
        byte[] name = Encoding.ASCII.GetBytes(serverName);

        var extension = new List<byte>();
        extension.AddRange(new byte[] { 0x00, 0x00 });                       // type: server_name
        extension.AddRange(Be16(name.Length + 5));                            // extension length
        extension.AddRange(Be16(name.Length + 3));                            // list length
        extension.Add(0x00);                                                  // host_name
        extension.AddRange(Be16(name.Length));
        extension.AddRange(name);

        var body = new List<byte>();
        body.AddRange(new byte[] { 0x03, 0x03 });                             // version
        body.AddRange(new byte[32]);                                          // random
        body.Add(0x00);                                                       // session id length
        body.AddRange(Be16(2));                                               // cipher suites length
        body.AddRange(new byte[] { 0x13, 0x01 });
        body.Add(0x01);                                                       // compression methods length
        body.Add(0x00);
        body.AddRange(Be16(extension.Count));
        body.AddRange(extension);

        var handshake = new List<byte> { 0x01 };                              // client hello
        handshake.AddRange(new[] { (byte)0, (byte)(body.Count >> 8), (byte)(body.Count & 0xFF) });
        handshake.AddRange(body);

        var record = new List<byte> { 0x16, 0x03, 0x01 };
        record.AddRange(Be16(handshake.Count));
        record.AddRange(handshake);

        return record.ToArray();
    }

    private static byte[] Be16(int value) => new[] { (byte)(value >> 8), (byte)(value & 0xFF) };
}

/// <summary>
/// Which end of a conversation is this machine.
/// </summary>
/// <remarks>
/// <para>
/// The canonical flow key orders its endpoints deterministically so both directions
/// accumulate into one entry, and that ordering has nothing to do with which end is the
/// recording machine. Reading the canonical "local" address as local names the operator's
/// own machine as the host contacted.
/// </para>
/// <para>
/// This is the second time the codebase has made that mistake — the flow table made it
/// first — which is why it is tested against the shape rather than left to review.
/// </para>
/// </remarks>
public sealed class ConversationOrientationTests
{
    private static readonly IPAddress Mine = IPAddress.Parse("192.168.1.180");
    private static readonly IPAddress Server = IPAddress.Parse("93.184.216.34");
    private static readonly IPAddress Peer = IPAddress.Parse("192.168.1.42");

    /// <summary>Reaching out to a server names the server, whichever way the key sorted.</summary>
    [Fact]
    public void AnOutboundConversationNamesTheServerNotThisMachine()
    {
        Conversation c = Reassemble(
            source: Mine, sourcePort: 51000, destination: Server, destinationPort: 443,
            local: new[] { Mine });

        Assert.Equal(Server, c.Key.RemoteAddress);
        Assert.Equal(443, c.Key.RemotePort);
        Assert.Equal(Mine, c.Key.LocalAddress);
        Assert.Equal(51000, c.Key.LocalPort);
        Assert.False(c.Inbound_Connection);
        Assert.Equal(PeerScope.Internet, c.Scope);
    }

    /// <summary>
    /// The same conversation with the endpoints the other way round is the same answer.
    /// </summary>
    /// <remarks>
    /// The discriminating case. Both orderings reach the reassembler depending on which
    /// packet arrived first, and both have to produce a conversation described from this
    /// machine's point of view.
    /// </remarks>
    [Fact]
    public void TheAnswerDoesNotDependOnWhichPacketArrivedFirst()
    {
        Conversation c = Reassemble(
            source: Server, sourcePort: 443, destination: Mine, destinationPort: 51000,
            local: new[] { Mine }, synFromSource: false);

        Assert.Equal(Server, c.Key.RemoteAddress);
        Assert.Equal(Mine, c.Key.LocalAddress);
    }

    /// <summary>
    /// Something connecting in means this machine was listening.
    /// </summary>
    /// <remarks>
    /// The more interesting of the two directions, and invisible everywhere else: a
    /// program that opens a socket and waits is expecting to be found.
    /// </remarks>
    [Fact]
    public void AConnectionFromAnotherMachineIsMarkedInbound()
    {
        Conversation c = Reassemble(
            source: Peer, sourcePort: 60000, destination: Mine, destinationPort: 48231,
            local: new[] { Mine }, synFromSource: true);

        Assert.True(c.Inbound_Connection);
        Assert.Equal(Peer, c.Key.RemoteAddress);
        Assert.Equal(Mine, c.Key.LocalAddress);
        Assert.Equal(48231, c.Key.LocalPort);
        Assert.Equal(PeerScope.LocalNetwork, c.Scope);
    }

    /// <summary>
    /// Writes a minimal capture and reads it back through the real reader.
    /// </summary>
    /// <remarks>
    /// Through the file rather than by calling the builder directly, because the packet
    /// parse and the reassembly are the pair that has to agree — and the parse was
    /// refactored to serve both flow totals and reassembly from one walk.
    /// </remarks>
    private static Conversation Reassemble(
        IPAddress source, ushort sourcePort, IPAddress destination, ushort destinationPort,
        IPAddress[] local, bool synFromSource = true)
    {
        string path = Path.Combine(Path.GetTempPath(), $"cayatrace-convo-{Guid.NewGuid():N}.pcapng");

        try
        {
            using (var stream = File.Create(path))
            {
                WriteHeaders(stream);

                // The handshake establishes who initiated; the payload gives it content.
                WritePacket(stream, source, sourcePort, destination, destinationPort,
                    sequence: 1000, syn: synFromSource, ack: false, payload: Array.Empty<byte>());
                WritePacket(stream, destination, destinationPort, source, sourcePort,
                    sequence: 5000, syn: true, ack: true, payload: Array.Empty<byte>());
                WritePacket(stream, source, sourcePort, destination, destinationPort,
                    sequence: 1001, syn: false, ack: true,
                    payload: Encoding.ASCII.GetBytes("GET /probe HTTP/1.1\r\n\r\n"));
            }

            return Assert.Single(ConversationRecorder.Read(path, local));
        }
        finally
        {
            try { File.Delete(path); } catch (IOException) { }
        }
    }

    private static void WriteHeaders(Stream stream)
    {
        // Section header block.
        Write32(stream, 0x0A0D0D0A);
        Write32(stream, 28);
        Write32(stream, 0x1A2B3C4D);
        Write32(stream, 0x00000001);              // version 1.0
        Write32(stream, 0xFFFFFFFF);              // section length: unknown
        Write32(stream, 0xFFFFFFFF);
        Write32(stream, 28);

        // Interface description block: Ethernet.
        Write32(stream, 0x00000001);
        Write32(stream, 20);
        Write32(stream, 1);                        // link type 1, reserved 0
        Write32(stream, 0);                        // snap length
        Write32(stream, 20);
    }

    private static void WritePacket(
        Stream stream, IPAddress source, ushort sourcePort, IPAddress destination, ushort destinationPort,
        uint sequence, bool syn, bool ack, byte[] payload)
    {
        byte[] frame = BuildFrame(source, sourcePort, destination, destinationPort, sequence, syn, ack, payload);

        int padded = (frame.Length + 3) / 4 * 4;
        int blockLength = 32 + padded;

        Write32(stream, 0x00000006);               // enhanced packet block
        Write32(stream, (uint)blockLength);
        Write32(stream, 0);                        // interface id
        Write32(stream, 0);                        // timestamp high
        Write32(stream, 1);                        // timestamp low
        Write32(stream, (uint)frame.Length);       // captured
        Write32(stream, (uint)frame.Length);       // original
        stream.Write(frame);
        for (int i = frame.Length; i < padded; i++) stream.WriteByte(0);
        Write32(stream, (uint)blockLength);
    }

    private static byte[] BuildFrame(
        IPAddress source, ushort sourcePort, IPAddress destination, ushort destinationPort,
        uint sequence, bool syn, bool ack, byte[] payload)
    {
        bool v6 = source.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

        var tcp = new byte[20 + payload.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(0), sourcePort);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2), destinationPort);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(4), sequence);
        tcp[12] = 5 << 4;                          // data offset: 5 words
        tcp[13] = (byte)((syn ? 0x02 : 0) | (ack ? 0x10 : 0));
        payload.CopyTo(tcp.AsSpan(20));

        byte[] ip;
        if (v6)
        {
            ip = new byte[40 + tcp.Length];
            ip[0] = 0x60;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(4), (ushort)tcp.Length);
            ip[6] = 6;                             // TCP
            source.GetAddressBytes().CopyTo(ip.AsSpan(8));
            destination.GetAddressBytes().CopyTo(ip.AsSpan(24));
            tcp.CopyTo(ip.AsSpan(40));
        }
        else
        {
            ip = new byte[20 + tcp.Length];
            ip[0] = 0x45;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2), (ushort)ip.Length);
            ip[9] = 6;                             // TCP
            source.GetAddressBytes().CopyTo(ip.AsSpan(12));
            destination.GetAddressBytes().CopyTo(ip.AsSpan(16));
            tcp.CopyTo(ip.AsSpan(20));
        }

        var frame = new byte[14 + ip.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), (ushort)(v6 ? 0x86DD : 0x0800));
        ip.CopyTo(frame.AsSpan(14));
        return frame;
    }

    private static void Write32(Stream stream, uint value)
        => stream.Write(BitConverter.GetBytes(value));
}
