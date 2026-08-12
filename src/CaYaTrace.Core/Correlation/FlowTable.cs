using System.Net;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Core.Correlation;

/// <summary>
/// Result of asking "which process owns this conversation?".
/// </summary>
public readonly record struct FlowAttribution(
    ProcessKey Owner,
    AttributionConfidence Confidence,
    string Evidence)
{
    public static readonly FlowAttribution None =
        new(ProcessKey.None, AttributionConfidence.None, "unattributed");
}

/// <summary>
/// Joins network activity to processes, and holds the per-flow rollup that the UI
/// renders under each connection node.
/// </summary>
/// <remarks>
/// <para>
/// Attribution quality varies by source and the difference is preserved rather than
/// flattened, because an analyst reading a tree needs to know which edges are facts:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>Kernel network events</b> name the process outright —
///     <see cref="AttributionConfidence.Direct"/>.
///   </description></item>
///   <item><description>
///     <b>Local port ownership tables</b> (<c>GetExtendedTcpTable</c>) are polled, so a
///     short-lived socket can open and close between two polls. Matching a port to an
///     owner within a validity window is <see cref="AttributionConfidence.Probable"/>.
///   </description></item>
///   <item><description>
///     <b>Packet capture</b> carries no process at all. It is matched to an existing
///     flow by 5-tuple; if no flow matches, the packets stay unattributed instead of
///     being guessed onto a plausible-looking process.
///   </description></item>
/// </list>
/// </remarks>
public sealed class FlowTable
{
    /// <summary>
    /// How long a polled port-ownership record stays usable after its last
    /// confirmation. Longer than the poll interval so records bridge the gap between
    /// polls, short enough that a recycled ephemeral port does not inherit an owner.
    /// </summary>
    private static readonly TimeSpan PortOwnershipGrace = TimeSpan.FromSeconds(4);

    private readonly object _gate = new();
    private readonly Dictionary<FlowKey, NetworkFlow> _flows = new();
    private readonly Dictionary<(TransportProtocol, ushort), List<PortOwnership>> _portOwners = new();
    private readonly int _maxFlows;

    private long _unattributed;

    private sealed record PortOwnership(ProcessKey Owner, DateTimeOffset From)
    {
        public DateTimeOffset Until { get; set; } = DateTimeOffset.MaxValue;
    }

    public FlowTable(int maxFlows = 200_000) => _maxFlows = maxFlows;

    public int Count { get { lock (_gate) return _flows.Count; } }

    public long UnattributedCount => Interlocked.Read(ref _unattributed);

    /// <summary>Records a connection the kernel attributed to a process directly.</summary>
    public NetworkFlow NoteConnect(FlowKey key, ProcessKey owner, DateTimeOffset when, string evidence = "kernel-network")
    {
        lock (_gate)
        {
            NetworkFlow flow = GetOrCreateLocked(key, when);
            if (owner != ProcessKey.None &&
                (flow.OwnerConfidence < AttributionConfidence.Direct || flow.Owner == ProcessKey.None))
            {
                flow.Owner = owner;
                flow.OwnerConfidence = AttributionConfidence.Direct;
                flow.OwnerEvidence = evidence;
            }
            flow.LastSeen = Max(flow.LastSeen, when);
            NoteLocalPortLocked(key.Protocol, key.LocalPort, owner, when);
            return flow;
        }
    }

    /// <summary>
    /// Records port ownership observed by polling the OS connection table. Ownership
    /// stays valid until superseded or until the grace period lapses.
    /// </summary>
    public void NoteLocalPort(TransportProtocol protocol, ushort port, ProcessKey owner, DateTimeOffset when)
    {
        lock (_gate) NoteLocalPortLocked(protocol, port, owner, when);
    }

    private void NoteLocalPortLocked(TransportProtocol protocol, ushort port, ProcessKey owner, DateTimeOffset when)
    {
        if (port == 0 || owner == ProcessKey.None) return;

        var slot = (protocol, port);
        if (!_portOwners.TryGetValue(slot, out List<PortOwnership>? owners))
        {
            owners = new List<PortOwnership>(1);
            _portOwners[slot] = owners;
        }

        PortOwnership? last = owners.Count > 0 ? owners[^1] : null;
        if (last is not null && last.Owner == owner && last.Until >= when - PortOwnershipGrace)
        {
            last.Until = when + PortOwnershipGrace;
            return;
        }

        if (last is not null && last.Until > when)
            last.Until = when;

        owners.Add(new PortOwnership(owner, when) { Until = when + PortOwnershipGrace });

        // A port that has changed hands many times is almost always an ephemeral
        // port churning; only the recent history is useful.
        if (owners.Count > 16)
            owners.RemoveRange(0, owners.Count - 16);
    }

    /// <summary>
    /// Attributes a flow that arrived without an owner — typically from packet
    /// capture. Tries the exact 5-tuple, then its reverse, then local port ownership.
    /// </summary>
    public FlowAttribution Attribute(FlowKey key, DateTimeOffset when)
    {
        lock (_gate)
        {
            if (_flows.TryGetValue(key, out NetworkFlow? exact) && exact.Owner != ProcessKey.None)
                return new FlowAttribution(exact.Owner, exact.OwnerConfidence, exact.OwnerEvidence ?? "flow-exact");

            FlowKey reversed = key.Reversed();
            if (_flows.TryGetValue(reversed, out NetworkFlow? rev) && rev.Owner != ProcessKey.None)
                return new FlowAttribution(rev.Owner, rev.OwnerConfidence, "flow-reverse");

            ProcessKey byPort = LookupPortOwnerLocked(key.Protocol, key.LocalPort, when);
            if (byPort != ProcessKey.None)
                return new FlowAttribution(byPort, AttributionConfidence.Probable, "local-port-table");

            // For an inbound capture the "local" port of the tuple is the remote side.
            ProcessKey byRemotePort = LookupPortOwnerLocked(key.Protocol, key.RemotePort, when);
            if (byRemotePort != ProcessKey.None)
                return new FlowAttribution(byRemotePort, AttributionConfidence.Weak, "local-port-table-reversed");

            Interlocked.Increment(ref _unattributed);
            return FlowAttribution.None;
        }
    }

    /// <summary>
    /// Resolves the process behind a connection arriving at the local intercepting
    /// proxy. The proxy sees only <c>127.0.0.1:&lt;ephemeral&gt;</c>, so the ephemeral port is
    /// the entire link back to the real client.
    /// </summary>
    public FlowAttribution AttributeProxyClient(ushort clientPort, DateTimeOffset when)
    {
        lock (_gate)
        {
            ProcessKey owner = LookupPortOwnerLocked(TransportProtocol.Tcp, clientPort, when);
            return owner == ProcessKey.None
                ? FlowAttribution.None
                : new FlowAttribution(owner, AttributionConfidence.Probable, "proxy-client-port");
        }
    }

    private ProcessKey LookupPortOwnerLocked(TransportProtocol protocol, ushort port, DateTimeOffset when)
    {
        if (port == 0) return ProcessKey.None;
        if (!_portOwners.TryGetValue((protocol, port), out List<PortOwnership>? owners)) return ProcessKey.None;

        for (int i = owners.Count - 1; i >= 0; i--)
        {
            PortOwnership o = owners[i];
            if (when >= o.From - PortOwnershipGrace && when <= o.Until)
                return o.Owner;
        }
        return ProcessKey.None;
    }

    public NetworkFlow GetOrCreate(FlowKey key, DateTimeOffset when)
    {
        lock (_gate) return GetOrCreateLocked(key, when);
    }

    private NetworkFlow GetOrCreateLocked(FlowKey key, DateTimeOffset when)
    {
        if (_flows.TryGetValue(key, out NetworkFlow? existing))
        {
            existing.LastSeen = Max(existing.LastSeen, when);
            return existing;
        }

        // A conversation already known in the other orientation is the same
        // conversation. This matters because the kernel's per-packet events and its
        // connect event do not agree on which endpoint is the source, so without this a
        // single HTTP fetch produced two flow records: one correct, and one whose
        // "remote" endpoint was the machine's own address on an ephemeral port. The
        // second is not merely a duplicate — it is a report telling an analyst that the
        // program connected to their own machine, and it split the byte totals across
        // two rows so neither was right either.
        //
        // The connect and accept events establish orientation; everything else attaches
        // to what they established.
        //
        // Except on loopback, where both ends of the connection are sockets on this
        // machine and the kernel reports each of them. Their tuples are exact reverses,
        // but they are two records worth keeping apart: the same bytes are observed
        // twice — once leaving one socket and once arriving at the other — so unifying
        // them would report double the traffic that crossed. And they have different
        // owners, which is the whole question when the subject is talking to the
        // intercepting proxy: collapsing them hands both sides to whichever process
        // registered first.
        if (!key.IsLoopback && _flows.TryGetValue(key.Reversed(), out NetworkFlow? reversed))
        {
            reversed.LastSeen = Max(reversed.LastSeen, when);
            return reversed;
        }

        if (_flows.Count >= _maxFlows)
            EvictLocked();

        var flow = new NetworkFlow { Key = key, FirstSeen = when, LastSeen = when };
        _flows[key] = flow;
        return flow;
    }

    /// <summary>
    /// The flow for this conversation, in whichever orientation it was first seen.
    /// </summary>
    /// <remarks>
    /// Loopback is exact-match only, for the reason given in
    /// <see cref="GetOrCreateLocked"/>: both ends are separate records there.
    /// </remarks>
    public NetworkFlow? Find(FlowKey key)
    {
        lock (_gate)
        {
            NetworkFlow? exact = _flows.GetValueOrDefault(key);
            if (exact is not null || key.IsLoopback) return exact;
            return _flows.GetValueOrDefault(key.Reversed());
        }
    }

    public void NoteBytes(FlowKey key, DateTimeOffset when, long sent, long received, long packetsSent = 0, long packetsReceived = 0)
    {
        lock (_gate)
        {
            NetworkFlow flow = GetOrCreateLocked(key, when);
            flow.BytesSent += sent;
            flow.BytesReceived += received;
            flow.PacketsSent += packetsSent;
            flow.PacketsReceived += packetsReceived;
            flow.LastSeen = Max(flow.LastSeen, when);
        }
    }

    public void NoteClose(FlowKey key, DateTimeOffset when)
    {
        NetworkFlow? flow = Find(key);
        if (flow is not null) flow.ClosedAt = when;
    }

    /// <summary>Attaches a resolved hostname to every flow to that address.</summary>
    public int NoteDnsAnswer(IPAddress address, string hostname, DateTimeOffset when)
    {
        lock (_gate)
        {
            int tagged = 0;
            foreach (NetworkFlow flow in _flows.Values)
            {
                if (!flow.RemoteAddress().Equals(address)) continue;
                if (flow.ResolvedHost is not null) continue;
                // Only tag flows that started after the answer; an address reused for
                // a different host later must not inherit this name.
                if (flow.FirstSeen < when - TimeSpan.FromMinutes(30)) continue;
                flow.ResolvedHost = hostname;
                tagged++;
            }
            return tagged;
        }
    }

    public IReadOnlyList<NetworkFlow> Snapshot()
    {
        lock (_gate) return _flows.Values.ToList();
    }

    /// <summary>
    /// Drops the oldest closed flows. Open flows are never evicted: they are the ones
    /// still capable of receiving new packets that would otherwise go unattributed.
    /// </summary>
    private void EvictLocked()
    {
        int target = Math.Max(1, _maxFlows / 10);
        List<FlowKey> victims = _flows.Values
            .Where(static f => f.ClosedAt is not null)
            .OrderBy(static f => f.ClosedAt!.Value)
            .Take(target)
            .Select(static f => f.Key)
            .ToList();

        if (victims.Count == 0)
        {
            victims = _flows.Values
                .OrderBy(static f => f.LastSeen)
                .Take(target)
                .Select(static f => f.Key)
                .ToList();
        }

        foreach (FlowKey v in victims) _flows.Remove(v);
    }

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a > b ? a : b;
}

internal static class NetworkFlowExtensions
{
    public static IPAddress RemoteAddress(this NetworkFlow flow) => flow.Key.RemoteAddress;
}
