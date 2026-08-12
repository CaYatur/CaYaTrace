using System.Buffers.Binary;
using System.Net;
using CaYaTrace.Collectors.Network;
using CaYaTrace.Core.Model;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Byte-level parsing of capture files. A wrong offset here does not crash — it
/// produces plausible-looking ports for the wrong conversation, which is the kind of
/// error that survives all the way into a report.
/// </summary>
public sealed class PcapngReaderTests : IDisposable
{
    private readonly string _path = Path.Combine(
        Path.GetTempPath(), $"cayatrace-{Guid.NewGuid():n}.pcapng");

    /// <summary>Builds a minimal but valid pcapng holding the given Ethernet frames.</summary>
    private void WriteCapture(int linkType, params byte[][] frames)
    {
        using var stream = new FileStream(_path, FileMode.Create);
        using var writer = new BinaryWriter(stream);

        // Section Header Block
        writer.Write(0x0A0D0D0Au);
        writer.Write(28u);
        writer.Write(0x1A2B3C4Du);        // byte-order magic, little endian
        writer.Write((ushort)1);           // major
        writer.Write((ushort)0);           // minor
        writer.Write(-1L);                 // section length: unknown
        writer.Write(28u);

        // Interface Description Block
        writer.Write(0x00000001u);
        writer.Write(20u);
        writer.Write((ushort)linkType);
        writer.Write((ushort)0);
        writer.Write(0u);                  // snaplen: unlimited
        writer.Write(20u);

        foreach (byte[] frame in frames)
        {
            int padded = (frame.Length + 3) & ~3;
            uint length = (uint)(32 + padded);

            writer.Write(0x00000006u);     // Enhanced Packet Block
            writer.Write(length);
            writer.Write(0u);              // interface id
            writer.Write(0u);              // timestamp high
            writer.Write(1_000_000u);      // timestamp low
            writer.Write((uint)frame.Length);
            writer.Write((uint)frame.Length);
            writer.Write(frame);
            writer.Write(new byte[padded - frame.Length]);
            writer.Write(length);
        }
    }

    private static byte[] EthernetIPv4Tcp(
        string source, ushort sourcePort, string destination, ushort destinationPort, int vlanTags = 0)
    {
        var frame = new List<byte>();

        frame.AddRange(new byte[6]);                       // destination MAC
        frame.AddRange(new byte[6]);                       // source MAC

        for (int i = 0; i < vlanTags; i++)
        {
            frame.AddRange(new byte[] { 0x81, 0x00 });     // 802.1Q
            frame.AddRange(new byte[] { 0x00, 0x64 });     // tag body
        }

        frame.AddRange(new byte[] { 0x08, 0x00 });         // EtherType: IPv4

        var ip = new List<byte>
        {
            0x45,                                          // version 4, 5 words
            0x00, 0x00, 0x28,                              // DSCP + total length
            0x00, 0x00, 0x40, 0x00,                        // id + flags
            0x40, 0x06,                                    // TTL, protocol TCP
            0x00, 0x00,                                    // checksum (not verified)
        };
        ip.AddRange(IPAddress.Parse(source).GetAddressBytes());
        ip.AddRange(IPAddress.Parse(destination).GetAddressBytes());
        frame.AddRange(ip);

        Span<byte> ports = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(ports[..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(ports[2..], destinationPort);
        frame.AddRange(ports.ToArray());
        frame.AddRange(new byte[16]);                      // rest of the TCP header

        return frame.ToArray();
    }

    [Fact]
    public void RecoversAConversationFromAnEthernetFrame()
    {
        WriteCapture(1, EthernetIPv4Tcp("10.0.0.5", 51000, "93.184.216.34", 443));

        CapturedFlow flow = Assert.Single(PcapngReader.ReadFlows(_path));

        Assert.Equal(TransportProtocol.Tcp, flow.Key.Protocol);
        Assert.Equal(1, flow.Packets);
        Assert.Contains("443", flow.Key.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void BothDirectionsAccumulateIntoOneConversation()
    {
        // Canonicalization is what stops a request and its response being counted as
        // two unrelated flows, which would halve every byte total in the report.
        WriteCapture(1,
            EthernetIPv4Tcp("10.0.0.5", 51000, "93.184.216.34", 443),
            EthernetIPv4Tcp("93.184.216.34", 443, "10.0.0.5", 51000));

        CapturedFlow flow = Assert.Single(PcapngReader.ReadFlows(_path));

        Assert.Equal(2, flow.Packets);
    }

    [Fact]
    public void VlanTaggedFramesAreParsedRatherThanMisread()
    {
        // A tag shifts the IP header by four bytes. Without skipping it the parser
        // reads the wrong offsets and invents addresses and ports.
        WriteCapture(1, EthernetIPv4Tcp("10.0.0.5", 51000, "93.184.216.34", 443, vlanTags: 1));

        CapturedFlow flow = Assert.Single(PcapngReader.ReadFlows(_path));

        Assert.Equal(TransportProtocol.Tcp, flow.Key.Protocol);
        Assert.Contains("93.184.216.34", flow.Key.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void SeparateConversationsStaySeparate()
    {
        WriteCapture(1,
            EthernetIPv4Tcp("10.0.0.5", 51000, "93.184.216.34", 443),
            EthernetIPv4Tcp("10.0.0.5", 51001, "1.1.1.1", 80));

        Assert.Equal(2, PcapngReader.ReadFlows(_path).Count);
    }

    [Fact]
    public void NonIpFramesAreIgnoredRatherThanGuessedAt()
    {
        var arp = new List<byte>();
        arp.AddRange(new byte[12]);
        arp.AddRange(new byte[] { 0x08, 0x06 });   // EtherType: ARP
        arp.AddRange(new byte[28]);

        WriteCapture(1, arp.ToArray());

        Assert.Empty(PcapngReader.ReadFlows(_path));
    }

    [Fact]
    public void ATruncatedFileYieldsWhatItCanRatherThanThrowing()
    {
        // A circular capture stopped mid-write ends in a partial block. Losing the
        // whole capture over the last few bytes would be the wrong trade.
        WriteCapture(1, EthernetIPv4Tcp("10.0.0.5", 51000, "93.184.216.34", 443));

        byte[] full = File.ReadAllBytes(_path);
        File.WriteAllBytes(_path, full[..^6]);

        IReadOnlyList<CapturedFlow> flows = PcapngReader.ReadFlows(_path);

        Assert.NotNull(flows);
    }

    [Fact]
    public void PacketBudgetIsHonoured()
    {
        WriteCapture(1,
            EthernetIPv4Tcp("10.0.0.5", 51000, "93.184.216.34", 443),
            EthernetIPv4Tcp("10.0.0.5", 51001, "1.1.1.1", 80),
            EthernetIPv4Tcp("10.0.0.5", 51002, "8.8.8.8", 53));

        Assert.Single(PcapngReader.ReadFlows(_path, maxPackets: 1));
    }

    public void Dispose()
    {
        try { if (File.Exists(_path)) File.Delete(_path); }
        catch (IOException) { }
    }
}
