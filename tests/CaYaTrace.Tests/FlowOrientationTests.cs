using System.Net;
using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Model;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// One conversation is one flow, whichever way round the kernel reported it.
/// </summary>
/// <remarks>
/// <para>
/// Measured on a real capture: a single HTTP fetch produced two flow records. One had
/// the machine's address as local and the server as remote; the other had them the
/// other way round, because the connect event and the per-packet events do not agree on
/// which endpoint is the source.
/// </para>
/// <para>
/// The consequence was not a cosmetic duplicate. The report told the analyst the
/// program had connected to <c>192.168.1.180</c> — their own machine — and split the byte
/// totals across two rows so neither figure was right.
/// </para>
/// </remarks>
public sealed class FlowOrientationTests
{
    private static readonly IPAddress Mine = IPAddress.Parse("192.168.1.180");
    private static readonly IPAddress Server = IPAddress.Parse("93.184.216.34");

    private static FlowKey Outbound => new(TransportProtocol.Tcp, Mine, 59034, Server, 80);
    private static FlowKey AsReported => Outbound.Reversed();

    private static ProcessKey Actor => new(1234, 0xAABB, 0);

    [Fact]
    public void AConnectAndItsPacketsAreOneFlow()
    {
        var table = new FlowTable();
        DateTimeOffset t = DateTimeOffset.UtcNow;

        table.NoteConnect(Outbound, Actor, t);
        table.NoteBytes(Outbound, t, sent: 500, received: 0);

        // The same conversation, tuple the other way round.
        table.NoteBytes(AsReported, t, sent: 0, received: 1500);

        List<NetworkFlow> flows = table.Snapshot().ToList();
        Assert.Single(flows);

        NetworkFlow flow = flows[0];
        Assert.Equal(500, flow.BytesSent);
        Assert.Equal(1500, flow.BytesReceived);
    }

    [Fact]
    public void TheConnectEventDecidesWhichEndIsLocal()
    {
        var table = new FlowTable();
        DateTimeOffset t = DateTimeOffset.UtcNow;

        table.NoteConnect(Outbound, Actor, t);
        table.NoteBytes(AsReported, t, sent: 0, received: 10);

        NetworkFlow flow = table.Snapshot().Single();

        // A report that names the machine's own address as the host contacted is the
        // single most misleading thing a network view can say.
        Assert.Equal(Server, flow.Key.RemoteAddress);
        Assert.Equal(80, flow.Key.RemotePort);
        Assert.Equal(Mine, flow.Key.LocalAddress);
    }

    [Fact]
    public void FindReturnsTheSameFlowFromEitherOrientation()
    {
        var table = new FlowTable();
        DateTimeOffset t = DateTimeOffset.UtcNow;

        table.NoteConnect(Outbound, Actor, t);

        NetworkFlow? direct = table.Find(Outbound);
        NetworkFlow? reversed = table.Find(AsReported);

        Assert.NotNull(direct);
        Assert.Same(direct, reversed);
    }

    [Fact]
    public void ClosingFromTheOtherOrientationStillClosesTheFlow()
    {
        var table = new FlowTable();
        DateTimeOffset t = DateTimeOffset.UtcNow;

        table.NoteConnect(Outbound, Actor, t);
        table.NoteClose(AsReported, t.AddSeconds(1));

        Assert.NotNull(table.Snapshot().Single().ClosedAt);
    }

    [Fact]
    public void TwoGenuinelyDifferentConversationsStayApart()
    {
        // The unification must not collapse different flows: same peer, different
        // local port is a second connection and has to stay one.
        var table = new FlowTable();
        DateTimeOffset t = DateTimeOffset.UtcNow;

        table.NoteConnect(Outbound, Actor, t);
        table.NoteConnect(new FlowKey(TransportProtocol.Tcp, Mine, 59035, Server, 80), Actor, t);

        Assert.Equal(2, table.Snapshot().Count);
    }

    /// <summary>
    /// Both ends of a loopback connection stay separate records.
    /// </summary>
    /// <remarks>
    /// The discriminating case for the orientation fix, and the one that would have made
    /// it a regression. On loopback the two sockets are on this machine and the kernel
    /// reports each of them, so their tuples are exact reverses of one another — but the
    /// same bytes are observed twice, once leaving one socket and once arriving at the
    /// other. Unified, the record would claim double the traffic that crossed.
    ///
    /// This is not hypothetical: it is exactly the shape of a subject talking to the
    /// intercepting proxy, where the two ends also have different owners and which
    /// process is on each end is the entire question.
    /// </remarks>
    [Fact]
    public void BothEndsOfALoopbackConnectionStaySeparate()
    {
        var table = new FlowTable();
        DateTimeOffset t = DateTimeOffset.UtcNow;

        var client = new FlowKey(TransportProtocol.Tcp, IPAddress.Loopback, 51000, IPAddress.Loopback, 8443);
        var server = client.Reversed();

        var subject = new ProcessKey(1234, 0xAABB, 0);
        var proxy = new ProcessKey(4321, 0xCCDD, 0);

        table.NoteConnect(client, subject, t);
        table.NoteBytes(client, t, sent: 900, received: 0);

        table.NoteConnect(server, proxy, t);
        table.NoteBytes(server, t, sent: 0, received: 900);

        List<NetworkFlow> flows = table.Snapshot().ToList();
        Assert.Equal(2, flows.Count);

        // The same 900 bytes, seen once from each socket — not 900 sent and 900
        // received on one conversation.
        Assert.Equal(900, flows.Sum(static f => f.BytesSent));
        Assert.Equal(900, flows.Sum(static f => f.BytesReceived));

        // And each end keeps its own owner.
        Assert.Contains(flows, f => f.Owner == subject);
        Assert.Contains(flows, f => f.Owner == proxy);
    }
}
