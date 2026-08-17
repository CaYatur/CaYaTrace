using System.Net;
using System.Net.Sockets;
using System.Text;
using CaYaTrace.Collectors.Network;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// Capturing what two programs on one machine say to each other.
/// </summary>
/// <remarks>
/// <para>
/// The gap this closes. An established TCP connection over 127.0.0.1 takes a fastpath
/// inside the stack and never becomes a packet on any adapter — measured twice with the
/// packet monitor Windows ships, capturing every component: 5,276 events and not one of
/// them loopback. So a program talking to a second copy of itself, or to a local service
/// it installed, showed byte counts and nothing else.
/// </para>
/// <para>
/// These tests speak over a real loopback socket and then look for the bytes. Nothing is
/// simulated: if the capture path stops working, the payload stops appearing.
/// </para>
/// </remarks>
public sealed class LoopbackCaptureTests : IDisposable
{
    private readonly ITestOutputHelper _out;

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "cayatrace-lb-" + Guid.NewGuid().ToString("n")[..8]);

    public LoopbackCaptureTests(ITestOutputHelper output)
    {
        _out = output;
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>
    /// Says something over loopback and returns the two markers, once both ends are done.
    /// </summary>
    private static (string Sent, string Received) Talk(int port, IPAddress? on = null)
    {
        IPAddress address = on ?? IPAddress.Loopback;

        string sent = "CAYATRACE-CLIENT-" + Guid.NewGuid().ToString("n")[..12];
        string received = "CAYATRACE-SERVER-" + Guid.NewGuid().ToString("n")[..12];

        var listener = new TcpListener(address, port);
        listener.Start();

        Task server = Task.Run(() =>
        {
            using TcpClient accepted = listener.AcceptTcpClient();
            using NetworkStream stream = accepted.GetStream();

            var buffer = new byte[4096];
            int read = stream.Read(buffer, 0, buffer.Length);
            _ = read;

            byte[] reply = Encoding.ASCII.GetBytes(received + "\n");
            stream.Write(reply, 0, reply.Length);
            stream.Flush();
        });

        using (var client = new TcpClient(address.AddressFamily))
        {
            client.Connect(address, port);
            using NetworkStream stream = client.GetStream();

            byte[] payload = Encoding.ASCII.GetBytes(sent + "\n");
            stream.Write(payload, 0, payload.Length);
            stream.Flush();

            var buffer = new byte[4096];
            stream.Read(buffer, 0, buffer.Length);
        }

        server.Wait(TimeSpan.FromSeconds(10));
        listener.Stop();

        return (sent, received);
    }

    private static int FreePort(IPAddress? on = null)
    {
        var probe = new TcpListener(on ?? IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    /// <summary>
    /// End to end: start the capture, talk over loopback, and find both halves.
    /// </summary>
    /// <remarks>
    /// Both directions asserted separately, because a capture that only ever sees one of
    /// them is a specific and quiet failure — it looks like a working capture of a program
    /// that never got a reply.
    /// </remarks>
    [Fact]
    public void WhatTwoProgramsSayOverLoopbackIsCaptured()
    {
        if (!LoopbackCapture.IsAvailable(out string why))
        {
            _out.WriteLine($"no loopback capture on this machine: {why}");
            return;
        }

        string path = Path.Combine(_root, "loopback.pcapng");

        using (var capture = new LoopbackCapture(path))
        {
            Assert.True(capture.Start(out string error), error);

            (string sent, string received) = Talk(FreePort());

            // The driver hands packets over asynchronously; a capture stopped the
            // instant the socket closes routinely loses the last of them.
            Thread.Sleep(1500);
            capture.Stop();

            _out.WriteLine($"{capture.PacketCount} packets, {new FileInfo(path).Length} bytes");

            byte[] file = File.ReadAllBytes(path);
            string flat = Encoding.ASCII.GetString(file);

            Assert.Contains(sent, flat, StringComparison.Ordinal);
            Assert.Contains(received, flat, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The captured file goes through the same reassembly as every other capture.
    /// </summary>
    /// <remarks>
    /// The point of writing pcapng rather than anything else. A loopback conversation
    /// arrives at the analysis as a conversation — with contents, direction, and a peer —
    /// and everything downstream of that was already built.
    /// </remarks>
    [Fact]
    public void ALoopbackConversationReadsBackWithItsContents()
    {
        if (!LoopbackCapture.IsAvailable(out string why))
        {
            _out.WriteLine($"no loopback capture on this machine: {why}");
            return;
        }

        string path = Path.Combine(_root, "readback.pcapng");
        int port = FreePort();

        string sent, received;
        using (var capture = new LoopbackCapture(path))
        {
            Assert.True(capture.Start(out string error), error);
            (sent, received) = Talk(port);
            Thread.Sleep(1500);
            capture.Stop();
        }

        IReadOnlyList<Conversation> conversations = ConversationRecorder.Read(
            path, new List<IPAddress> { IPAddress.Loopback, IPAddress.IPv6Loopback });

        foreach (Conversation c in conversations)
        {
            _out.WriteLine(
                $"{c.Key.LocalAddress}:{c.Key.LocalPort} -> {c.Key.RemoteAddress}:{c.Key.RemotePort}  " +
                $"{c.Scope}  out={c.Outbound.Length} in={c.Inbound.Length}");
        }

        Conversation? ours = conversations.FirstOrDefault(
            c => c.Key.RemotePort == port || c.Key.LocalPort == port);

        Assert.NotNull(ours);

        string outbound = Encoding.ASCII.GetString(ours!.Outbound);
        string inbound = Encoding.ASCII.GetString(ours.Inbound);

        _out.WriteLine($"outbound: {outbound.Trim()}");
        _out.WriteLine($"inbound:  {inbound.Trim()}");

        // Oriented, not merely separated. On loopback both ends are this machine, so
        // the address cannot say which one connected — the SYN can, and this is the
        // assertion that proves the recorder uses it. Getting it backwards would label
        // what the program sent as what it received, which is worse than not knowing.
        Assert.Contains(sent, outbound, StringComparison.Ordinal);
        Assert.Contains(received, inbound, StringComparison.Ordinal);
        Assert.DoesNotContain(received, outbound, StringComparison.Ordinal);

        Assert.Equal(PeerScope.Loopback, ours.Scope);
    }

    /// <summary>
    /// The half of loopback that everything modern actually uses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>localhost</c> resolves to <c>::1</c> before <c>127.0.0.1</c> on current Windows,
    /// so a service that binds by name, or a dual-stack client, talks over IPv6 loopback
    /// and never touches the IPv4 one. A capture that handled only IPv4 would be half a
    /// feature, and the half it was missing would be the common one — while looking
    /// identical to a program that never talked at all.
    /// </para>
    /// <para>
    /// The loopback link layer is four bytes of address family before the IP header, and
    /// the value used for IPv6 there is not the same number on every platform. Reading the
    /// version out of the IP header instead means the family never has to be interpreted —
    /// which is what makes this pass, and is worth a test rather than an argument.
    /// </para>
    /// </remarks>
    [Fact]
    public void IPv6LoopbackIsCapturedToo()
    {
        if (!LoopbackCapture.IsAvailable(out string why))
        {
            _out.WriteLine($"no loopback capture on this machine: {why}");
            return;
        }

        if (!Socket.OSSupportsIPv6)
        {
            _out.WriteLine("this machine has no IPv6");
            return;
        }

        string path = Path.Combine(_root, "ipv6.pcapng");
        int port = FreePort(IPAddress.IPv6Loopback);

        string sent, received;
        using (var capture = new LoopbackCapture(path))
        {
            Assert.True(capture.Start(out string error), error);
            (sent, received) = Talk(port, IPAddress.IPv6Loopback);
            Thread.Sleep(1500);
            capture.Stop();
        }

        IReadOnlyList<Conversation> conversations = ConversationRecorder.Read(
            path, new List<IPAddress> { IPAddress.Loopback, IPAddress.IPv6Loopback });

        Conversation? ours = conversations.FirstOrDefault(
            c => (c.Key.RemotePort == port || c.Key.LocalPort == port)
                 && c.Key.LocalAddress.AddressFamily == AddressFamily.InterNetworkV6);

        foreach (Conversation c in conversations.Where(
                     static x => x.Key.LocalAddress.AddressFamily == AddressFamily.InterNetworkV6))
        {
            _out.WriteLine($"[{c.Key.LocalAddress}]:{c.Key.LocalPort} -> [{c.Key.RemoteAddress}]:{c.Key.RemotePort}" +
                           $"  {c.Scope}  out={c.Outbound.Length} in={c.Inbound.Length}");
        }

        Assert.NotNull(ours);

        string outbound = Encoding.ASCII.GetString(ours!.Outbound);
        string inbound = Encoding.ASCII.GetString(ours.Inbound);

        _out.WriteLine($"outbound: {outbound.Trim()}");
        _out.WriteLine($"inbound:  {inbound.Trim()}");

        Assert.Contains(sent, outbound, StringComparison.Ordinal);
        Assert.Contains(received, inbound, StringComparison.Ordinal);
        Assert.Equal(PeerScope.Loopback, ours.Scope);
    }

    /// <summary>
    /// A machine with no capture driver says so, rather than recording nothing.
    /// </summary>
    /// <remarks>
    /// The failure mode this release exists to avoid. A capture that quietly produces an
    /// empty file looks exactly like a program that never talked to anything, and the
    /// analyst draws the opposite conclusion from the right one.
    /// </remarks>
    [Fact]
    public void AvailabilityIsAnswerableWithoutStartingAnything()
    {
        bool available = LoopbackCapture.IsAvailable(out string why);

        _out.WriteLine($"available: {available}  reason: {why}");

        // Whichever it is, it is explained. An unavailable capture with no reason is the
        // thing an operator cannot act on.
        Assert.False(string.IsNullOrWhiteSpace(why));
    }
}
