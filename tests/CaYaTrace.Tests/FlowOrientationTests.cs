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
}
