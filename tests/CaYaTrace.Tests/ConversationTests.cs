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
