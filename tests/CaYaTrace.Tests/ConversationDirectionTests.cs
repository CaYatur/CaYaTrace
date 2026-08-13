using CaYaTrace.Collectors.Network;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Which half of a conversation is the one this machine sent.
/// </summary>
/// <remarks>
/// Reported backwards on a real capture, and backwards is worse than missing: a report
/// saying a program uploaded thirty kilobytes to an address, when it downloaded them, is
/// the difference between exfiltration and an update check. The halves are held by whoever
/// opened the connection while the key is ordered by a sort, and picking between the halves
/// by the sort is what inverted them wherever the two disagreed.
/// </remarks>
public sealed class ConversationDirectionTests
{
    /// <summary>
    /// A client hello, with a server name in it.
    /// </summary>
    /// <remarks>
    /// Hand-built rather than captured, so every length in it is one this test controls and
    /// the parser is being checked rather than a recording being trusted.
    /// </remarks>
    private static byte[] ClientHello(string host)
    {
        byte[] name = System.Text.Encoding.ASCII.GetBytes(host);

        var body = new List<byte>();
        body.AddRange(new byte[] { 0x03, 0x03 });                 // version
        body.AddRange(new byte[32]);                              // random
        body.Add(0x00);                                           // no session id
        body.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 });     // one cipher suite
        body.AddRange(new byte[] { 0x01, 0x00 });                 // one compression method

        var sni = new List<byte>
        {
            0x00, (byte)(name.Length + 3),                        // server name list length
            0x00,                                                 // host_name
            (byte)(name.Length >> 8), (byte)name.Length,
        };
        sni.AddRange(name);

        var extensions = new List<byte>
        {
            0x00, 0x00,                                           // server_name
            (byte)(sni.Count >> 8), (byte)sni.Count,
        };
        extensions.AddRange(sni);

        body.AddRange(new[] { (byte)(extensions.Count >> 8), (byte)extensions.Count });
        body.AddRange(extensions);

        var handshake = new List<byte>
        {
            0x01,                                                 // client_hello
            0x00, (byte)(body.Count >> 8), (byte)body.Count,
        };
        handshake.AddRange(body);

        var record = new List<byte>
        {
            0x16, 0x03, 0x01,
            (byte)(handshake.Count >> 8), (byte)handshake.Count,
        };
        record.AddRange(handshake);

        return record.ToArray();
    }

    [Fact]
    public void TheServerNameIsReadFromAClientHello()
    {
        Assert.Equal("example.com", TlsClientHelloProbe.ReadServerName(ClientHello("example.com")));
        Assert.Equal("www.example.com", TlsClientHelloProbe.ReadServerName(ClientHello("www.example.com")));
    }

    [Fact]
    public void AServerHelloCarriesNoClientName()
    {
        byte[] hello = ClientHello("example.com");

        // Same bytes, relabelled as the server's half of the handshake.
        hello[5] = 0x02;

        Assert.Null(TlsClientHelloProbe.ReadServerName(hello));
    }

    /// <summary>Nothing in a truncated or hostile handshake may throw.</summary>
    /// <remarks>
    /// The input is chosen by whatever is being recorded, so every bound in the parser is
    /// load-bearing. A crash here is a recording that stops.
    /// </remarks>
    [Fact]
    public void ATruncatedHandshakeIsNotAName()
    {
        byte[] full = ClientHello("example.com");

        for (int length = 0; length < full.Length; length++)
        {
            byte[] cut = full[..length];
            Assert.Null(Record.Exception(() => TlsClientHelloProbe.ReadServerName(cut)));
        }
    }

    [Fact]
    public void GarbageIsNotAName()
    {
        var random = new Random(20260813);

        for (int i = 0; i < 200; i++)
        {
            var noise = new byte[random.Next(1, 300)];
            random.NextBytes(noise);

            // Kept looking like a TLS record so the parser gets past its first check and
            // has to survive on its bounds rather than on its type byte.
            if (noise.Length >= 5)
            {
                noise[0] = 0x16;
                noise[1] = 0x03;
                noise[5 % noise.Length] = 0x01;
            }

            Assert.Null(Record.Exception(() => TlsClientHelloProbe.ReadServerName(noise)));
        }
    }
}
