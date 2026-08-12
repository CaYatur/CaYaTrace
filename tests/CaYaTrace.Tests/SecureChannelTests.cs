using System.Net;
using System.Net.Sockets;
using System.Text;
using CaYaTrace.Fleet;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// The fleet channel carries forensic evidence across a lab network. These tests are
/// the argument that it is worth trusting with it.
/// </summary>
public sealed class SecureChannelTests
{
    /// <summary>
    /// Two ends of a real loopback socket.
    /// </summary>
    /// <remarks>
    /// A socket rather than a pipe pair. Anonymous pipes have a small kernel buffer, so
    /// a test that writes a burst before reading deadlocks on the harness rather than
    /// on anything in the channel — and a socket is what the channel actually runs over.
    /// </remarks>
    private sealed class DuplexPair : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly TcpClient _client;
        private readonly TcpClient _server;

        public Stream A { get; }
        public Stream B { get; }

        public DuplexPair()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();

            _client = new TcpClient();
            Task connect = _client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)_listener.LocalEndpoint).Port);
            _server = _listener.AcceptTcpClient();
            connect.GetAwaiter().GetResult();

            A = _client.GetStream();
            B = _server.GetStream();
        }

        public void Dispose()
        {
            _client.Dispose();
            _server.Dispose();
            _listener.Stop();
        }
    }

    private static async Task<(SecureChannel Initiator, SecureChannel Responder)> HandshakeAsync(
        DuplexPair pair, string initiatorCode, string responderCode)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        Task<SecureChannel> initiator = SecureChannel.ConnectAsync(pair.A, initiatorCode, timeout.Token);
        Task<SecureChannel> responder = SecureChannel.AcceptAsync(pair.B, responderCode, timeout.Token);

        await Task.WhenAll(initiator, responder);
        return (initiator.Result, responder.Result);
    }

    [Fact]
    public async Task MatchingCodesEstablishAWorkingChannel()
    {
        using var pair = new DuplexPair();
        const string code = "ABCD-EFGH-JKMN";

        (SecureChannel a, SecureChannel b) = await HandshakeAsync(pair, code, code);
        using (a) using (b)
        {
            await a.SendAsync(Encoding.UTF8.GetBytes("observations follow"), CancellationToken.None);
            byte[]? received = await b.ReceiveAsync(CancellationToken.None);

            Assert.NotNull(received);
            Assert.Equal("observations follow", Encoding.UTF8.GetString(received));
        }
    }

    [Fact]
    public async Task MismatchedCodesAreRejected()
    {
        // This is the whole authentication story: without the code, the peer cannot
        // derive the same keys and the transcript check fails.
        using var pair = new DuplexPair();

        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            (SecureChannel a, SecureChannel b) = await HandshakeAsync(pair, "ABCD-EFGH-JKMN", "ZZZZ-ZZZZ-ZZZZ");
            a.Dispose();
            b.Dispose();
        });
    }

    [Fact]
    public async Task CodeFormattingAndCaseDoNotMatter()
    {
        // A code is read aloud or retyped into a VM console. Rejecting it over a
        // hyphen would make a routine mistake look like an attack.
        using var pair = new DuplexPair();

        (SecureChannel a, SecureChannel b) = await HandshakeAsync(pair, "abcd-efgh-jkmn", "ABCDEFGHJKMN");
        using (a) using (b)
        {
            await a.SendAsync(Encoding.UTF8.GetBytes("ok"), CancellationToken.None);
            Assert.Equal("ok", Encoding.UTF8.GetString((await b.ReceiveAsync(CancellationToken.None))!));
        }
    }

    [Fact]
    public async Task BothDirectionsCarryTraffic()
    {
        using var pair = new DuplexPair();
        const string code = "ABCD-EFGH-JKMN";

        (SecureChannel a, SecureChannel b) = await HandshakeAsync(pair, code, code);
        using (a) using (b)
        {
            await a.SendAsync(Encoding.UTF8.GetBytes("order"), CancellationToken.None);
            Assert.Equal("order", Encoding.UTF8.GetString((await b.ReceiveAsync(CancellationToken.None))!));

            await b.SendAsync(Encoding.UTF8.GetBytes("batch"), CancellationToken.None);
            Assert.Equal("batch", Encoding.UTF8.GetString((await a.ReceiveAsync(CancellationToken.None))!));
        }
    }

    [Fact]
    public async Task ManyFramesStayInSequence()
    {
        // Each direction has its own counter. A desynchronised counter would decrypt
        // to garbage and fail authentication, which is why ordering is worth asserting.
        using var pair = new DuplexPair();
        const string code = "ABCD-EFGH-JKMN";

        (SecureChannel a, SecureChannel b) = await HandshakeAsync(pair, code, code);
        using (a) using (b)
        {
            Task reader = Task.Run(async () =>
            {
                for (int i = 0; i < 200; i++)
                {
                    byte[]? frame = await b.ReceiveAsync(CancellationToken.None);
                    Assert.Equal($"frame {i}", Encoding.UTF8.GetString(frame!));
                }
            });

            for (int i = 0; i < 200; i++)
                await a.SendAsync(Encoding.UTF8.GetBytes($"frame {i}"), CancellationToken.None);

            await reader;
        }
    }

    [Fact]
    public async Task BothEndsAgreeOnTheSessionFingerprint()
    {
        // Displayed on both machines so an operator can confirm by eye that the two
        // ends are actually talking to each other.
        using var pair = new DuplexPair();
        const string code = "ABCD-EFGH-JKMN";

        (SecureChannel a, SecureChannel b) = await HandshakeAsync(pair, code, code);
        using (a) using (b)
        {
            Assert.Equal(a.SessionFingerprint, b.SessionFingerprint);
            Assert.NotEmpty(a.SessionFingerprint);
        }
    }

    [Fact]
    public async Task EachHandshakeDerivesFreshKeys()
    {
        // Ephemeral ECDH: the same pairing code twice must not produce the same
        // session, or recording one exchange would compromise every later one.
        const string code = "ABCD-EFGH-JKMN";

        using var first = new DuplexPair();
        (SecureChannel a1, SecureChannel b1) = await HandshakeAsync(first, code, code);
        string one = a1.SessionFingerprint;
        a1.Dispose(); b1.Dispose();

        using var second = new DuplexPair();
        (SecureChannel a2, SecureChannel b2) = await HandshakeAsync(second, code, code);
        string two = a2.SessionFingerprint;
        a2.Dispose(); b2.Dispose();

        Assert.NotEqual(one, two);
    }

    [Fact]
    public async Task AnEmptyCodeIsRefused()
    {
        using var pair = new DuplexPair();

        await Assert.ThrowsAsync<ChannelException>(
            () => SecureChannel.ConnectAsync(pair.A, "   ", CancellationToken.None));
    }
}

public sealed class PairingCodeTests
{
    [Fact]
    public void GeneratedCodesAreValid() => Assert.True(PairingCode.LooksValid(PairingCode.Generate()));

    [Fact]
    public void CodesAvoidCharactersPeopleMistype()
    {
        // A pairing failure caused by reading O as 0 looks exactly like an attack.
        string code = PairingCode.Generate();
        Assert.DoesNotContain(code, c => c is 'I' or 'L' or 'O' or 'U' or '0' or '1');
    }

    [Fact]
    public void CodesCarryEnoughEntropyToResistGuessing()
        => Assert.True(PairingCode.EntropyBits >= 55, $"only {PairingCode.EntropyBits:F0} bits");

    [Fact]
    public void CodesDoNotRepeat()
    {
        var seen = new HashSet<string>(Enumerable.Range(0, 200).Select(static _ => PairingCode.Generate()));
        Assert.Equal(200, seen.Count);
    }

    [Fact]
    public void MalformedCodesAreRejected()
    {
        Assert.False(PairingCode.LooksValid(null));
        Assert.False(PairingCode.LooksValid("short"));
        Assert.False(PairingCode.LooksValid("IIII-IIII-IIII"));
    }
}
