using System.Buffers.Binary;
using System.Net;
using System.Text;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Collectors.Network;

/// <summary>What a reassembled conversation turned out to be carrying.</summary>
public enum ConversationProtocol
{
    Unknown,
    Http,
    Tls,
    Dns,
    Text,
    Binary,
}

/// <summary>Which side of the machine a peer is on.</summary>
public enum PeerScope
{
    /// <summary>The same machine, over the loopback interface.</summary>
    Loopback,

    /// <summary>Another machine on a private network.</summary>
    LocalNetwork,

    /// <summary>Somewhere on the internet.</summary>
    Internet,
}

/// <summary>
/// One conversation, with what was actually said in it.
/// </summary>
/// <remarks>
/// The point of this record is the two byte streams. Counts and endpoints answer "did it
/// talk to something"; the streams answer "what did it say", which is the question that
/// was actually being asked.
/// </remarks>
public sealed record Conversation
{
    public required FlowKey Key { get; init; }
    public required PeerScope Scope { get; init; }
    public ConversationProtocol Protocol { get; init; }

    public DateTimeOffset First { get; init; }
    public DateTimeOffset Last { get; init; }

    public long PacketsOut { get; init; }
    public long PacketsIn { get; init; }
    public long BytesOut { get; init; }
    public long BytesIn { get; init; }

    /// <summary>Bytes the initiator sent, in order, up to the capture limit.</summary>
    public byte[] Outbound { get; init; } = Array.Empty<byte>();

    /// <summary>Bytes the initiator received, in order, up to the capture limit.</summary>
    public byte[] Inbound { get; init; } = Array.Empty<byte>();

    /// <summary>True when the streams were cut short by the size limit.</summary>
    public bool Truncated { get; init; }

    /// <summary>Server name from a TLS handshake, when one was seen.</summary>
    public string? ServerName { get; init; }

    /// <summary>First request line of an HTTP conversation, when one was seen.</summary>
    public string? Summary { get; init; }

    /// <summary>True when the local end accepted rather than initiated.</summary>
    public bool Inbound_Connection { get; init; }
}

public sealed class ConversationOptions
{
    /// <summary>
    /// How much of each direction to keep.
    /// </summary>
    /// <remarks>
    /// A cap rather than everything, because a session that downloads an installer would
    /// otherwise put hundreds of megabytes into the evidence database. The first part of
    /// a conversation is where the protocol, the request, the credentials and the command
    /// live; the tail is usually payload.
    /// </remarks>
    public int MaxBytesPerDirection { get; init; } = 256 * 1024;

    /// <summary>Bound on total work, so a huge capture cannot stall session shutdown.</summary>
    public int MaxPackets { get; init; } = 2_000_000;

    /// <summary>Bound on how many conversations are reassembled at once.</summary>
    public int MaxConversations { get; init; } = 20_000;

    public static ConversationOptions Default { get; } = new();
}

/// <summary>
/// Reassembles what was said on the wire, from the packet capture.
/// </summary>
/// <remarks>
/// <para>
/// The packet capture already told us which endpoints talked and how much. This turns
/// that into the contents — the actual bytes, in order, in both directions — so a
/// conversation can be read rather than counted.
/// </para>
/// <para>
/// <b>Why this covers the local network, which nothing else here does.</b> The HTTP stacks
/// report URLs, and the intercepting proxy reads request bodies, but both only see traffic
/// that goes through them: a program that opens its own socket on the local network and
/// talks to another machine, or to a second copy of itself, is completely invisible to
/// both. That is exactly the arrangement worth finding — components of one thing talking
/// to each other, or a machine being told what to do by a peer rather than by a server on
/// the internet. Packets see it because packets see everything on the wire.
/// </para>
/// <para>
/// Reassembly is sequence-ordered and gap-tolerant. A capture taken on a busy machine
/// drops packets, and the useful behaviour when a gap appears is to keep what arrived and
/// mark the stream rather than to discard a conversation because one segment is missing.
/// </para>
/// </remarks>
public static class ConversationRecorder
{
    public static IReadOnlyList<Conversation> Read(
        string pcapngPath,
        IReadOnlyCollection<IPAddress> localAddresses,
        ConversationOptions? options = null)
    {
        options ??= ConversationOptions.Default;

        var builders = new Dictionary<FlowKey, Builder>();

        PcapngReader.ReadPackets(pcapngPath, options.MaxPackets, (segment, timestamp) =>
        {
            FlowKey canonical = segment.Key.Canonical();

            if (!builders.TryGetValue(canonical, out Builder? builder))
            {
                if (builders.Count >= options.MaxConversations) return;
                builders[canonical] = builder = new Builder(canonical, timestamp, options.MaxBytesPerDirection);
            }

            builder.Add(segment, timestamp);
        });

        return builders.Values
            .Select(b => b.Build(localAddresses))
            .OrderByDescending(static c => c.BytesOut + c.BytesIn)
            .ToList();
    }

    /// <summary>
    /// Accumulates one conversation's two directions.
    /// </summary>
    /// <remarks>
    /// The first packet carrying a SYN without an ACK establishes which end initiated,
    /// which is what makes "this program connected out" distinguishable from "something
    /// connected to this program" — and the second is the more interesting finding.
    /// </remarks>
    private sealed class Builder
    {
        private readonly FlowKey _canonical;
        private readonly int _limit;
        private readonly Direction _forward = new();
        private readonly Direction _reverse = new();

        private IPAddress? _initiator;
        private ushort _initiatorPort;

        public Builder(FlowKey canonical, DateTimeOffset first, int limit)
        {
            _canonical = canonical;
            _limit = limit;
            First = first;
            Last = first;
        }

        public DateTimeOffset First { get; }
        public DateTimeOffset Last { get; private set; }

        public void Add(Segment segment, DateTimeOffset timestamp)
        {
            if (timestamp > Last) Last = timestamp;

            if (segment.Syn && !segment.Ack && _initiator is null)
            {
                _initiator = segment.Source;
                _initiatorPort = segment.SourcePort;
            }

            bool forward = _initiator is null
                ? segment.Source.Equals(_canonical.LocalAddress) && segment.SourcePort == _canonical.LocalPort
                : segment.Source.Equals(_initiator) && segment.SourcePort == _initiatorPort;

            Direction direction = forward ? _forward : _reverse;
            direction.Packets++;
            direction.Bytes += segment.WireLength;

            if (segment.Payload.Length > 0)
                direction.Append(segment.Sequence, segment.Payload, _limit);
        }

        public Conversation Build(IReadOnlyCollection<IPAddress> localAddresses)
        {
            byte[] outbound = _forward.ToArray();
            byte[] inbound = _reverse.ToArray();

            // Orientation. If the initiator is one of this machine's addresses the local
            // end reached out; if it is not, something reached in.
            IPAddress local = _canonical.LocalAddress;
            IPAddress remote = _canonical.RemoteAddress;
            bool inboundConnection = false;

            if (_initiator is not null)
            {
                bool initiatorIsLocal = localAddresses.Any(a => a.Equals(_initiator));
                if (!initiatorIsLocal && localAddresses.Any(a => a.Equals(_canonical.RemoteAddress)))
                {
                    (local, remote) = (remote, local);
                    (outbound, inbound) = (inbound, outbound);
                    inboundConnection = true;
                }
            }

            var key = new FlowKey(
                _canonical.Protocol,
                local,
                local.Equals(_canonical.LocalAddress) ? _canonical.LocalPort : _canonical.RemotePort,
                remote,
                remote.Equals(_canonical.RemoteAddress) ? _canonical.RemotePort : _canonical.LocalPort);

            (ConversationProtocol protocol, string? sni, string? summary) =
                Identify(outbound, inbound, key.RemotePort);

            return new Conversation
            {
                Key = key,
                Scope = Classify(key.RemoteAddress),
                Protocol = protocol,
                First = First,
                Last = Last,
                PacketsOut = inboundConnection ? _reverse.Packets : _forward.Packets,
                PacketsIn = inboundConnection ? _forward.Packets : _reverse.Packets,
                BytesOut = inboundConnection ? _reverse.Bytes : _forward.Bytes,
                BytesIn = inboundConnection ? _forward.Bytes : _reverse.Bytes,
                Outbound = outbound,
                Inbound = inbound,
                Truncated = _forward.Truncated || _reverse.Truncated,
                ServerName = sni,
                Summary = summary,
                Inbound_Connection = inboundConnection,
            };
        }
    }

    /// <summary>One direction's bytes, ordered by sequence number.</summary>
    /// <remarks>
    /// Held as a sorted map rather than appended in arrival order, because a capture on a
    /// loaded machine delivers segments out of order and a stream assembled in arrival
    /// order is a stream that reads as corrupt. Duplicates — retransmissions — are
    /// dropped by keying on the sequence number.
    /// </remarks>
    private sealed class Direction
    {
        private readonly SortedDictionary<uint, byte[]> _segments = new();
        private int _held;

        public long Packets { get; set; }
        public long Bytes { get; set; }
        public bool Truncated { get; private set; }

        public void Append(uint sequence, byte[] payload, int limit)
        {
            if (_held >= limit) { Truncated = true; return; }
            if (_segments.ContainsKey(sequence)) return;

            int take = Math.Min(payload.Length, limit - _held);
            if (take < payload.Length) Truncated = true;

            _segments[sequence] = take == payload.Length ? payload : payload[..take];
            _held += take;
        }

        public byte[] ToArray()
        {
            if (_segments.Count == 0) return Array.Empty<byte>();

            var buffer = new byte[_held];
            int at = 0;
            foreach (byte[] chunk in _segments.Values)
            {
                Buffer.BlockCopy(chunk, 0, buffer, at, chunk.Length);
                at += chunk.Length;
            }
            return buffer;
        }
    }

    /// <summary>
    /// Works out what a conversation was, from what it carried.
    /// </summary>
    /// <remarks>
    /// From the bytes rather than the port number. Port 8080 is not necessarily HTTP and
    /// HTTP is frequently not on port 80 — and something choosing an unexpected port is
    /// itself worth noticing, which a port-based guess would hide.
    /// </remarks>
    private static (ConversationProtocol, string? ServerName, string? Summary) Identify(
        byte[] outbound, byte[] inbound, ushort remotePort)
    {
        if (outbound.Length >= 6 && LooksLikeHttp(outbound))
        {
            int end = Array.IndexOf(outbound, (byte)'\r');
            if (end < 0 || end > 200) end = Math.Min(outbound.Length, 200);
            return (ConversationProtocol.Http, null, Encoding.ASCII.GetString(outbound, 0, end));
        }

        if (outbound.Length >= 5 && outbound[0] == 0x16 && outbound[1] == 0x03)
        {
            string? sni = TlsClientHello.ReadServerName(outbound);
            return (ConversationProtocol.Tls, sni, sni is null ? "TLS handshake" : $"TLS to {sni}");
        }

        if (remotePort is 53 or 5353 or 5355) return (ConversationProtocol.Dns, null, "name lookup");

        byte[] sample = outbound.Length > 0 ? outbound : inbound;
        if (sample.Length == 0) return (ConversationProtocol.Unknown, null, null);

        if (IsMostlyText(sample))
        {
            int end = Math.Min(sample.Length, 120);
            return (ConversationProtocol.Text, null, Encoding.UTF8.GetString(sample, 0, end).Trim());
        }

        return (ConversationProtocol.Binary, null, null);
    }

    private static readonly string[] HttpVerbs =
    {
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
    };

    private static bool LooksLikeHttp(byte[] data)
    {
        int length = Math.Min(data.Length, 16);
        string head = Encoding.ASCII.GetString(data, 0, length);
        return HttpVerbs.Any(v => head.StartsWith(v, StringComparison.Ordinal));
    }

    private static bool IsMostlyText(byte[] data)
    {
        int length = Math.Min(data.Length, 512);
        int printable = 0;

        for (int i = 0; i < length; i++)
        {
            byte b = data[i];
            if (b is 9 or 10 or 13 || (b >= 32 && b < 127)) printable++;
        }

        return printable * 10 >= length * 9;
    }

    /// <summary>
    /// Which side of the machine a peer is on.
    /// </summary>
    /// <remarks>
    /// The distinction is the whole reason this exists. Traffic to the internet is what
    /// everyone looks at; traffic to another machine on the same network, or to a second
    /// process on this one, is how software coordinates with its own components — and it
    /// never appears in a firewall log or a proxy.
    /// </remarks>
    public static PeerScope Classify(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return PeerScope.Loopback;

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            byte[] b = address.GetAddressBytes();

            bool priv = b[0] == 10
                        || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                        || (b[0] == 192 && b[1] == 168)
                        || (b[0] == 169 && b[1] == 254)              // link-local
                        || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) // carrier-grade NAT
                        || b[0] >= 224;                               // multicast and broadcast

            return priv ? PeerScope.LocalNetwork : PeerScope.Internet;
        }

        if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal) return PeerScope.LocalNetwork;

        // Unique local addresses, fc00::/7.
        byte first = address.GetAddressBytes()[0];
        if ((first & 0xFE) == 0xFC) return PeerScope.LocalNetwork;
        if (address.IsIPv6Multicast) return PeerScope.LocalNetwork;

        return PeerScope.Internet;
    }
}

/// <summary>Reads the server name out of a TLS client hello.</summary>
/// <remarks>
/// Worth the parsing because it is the only place an encrypted conversation says where it
/// is going. Every read is bounds-checked and any malformed field abandons the parse —
/// this input arrives from the network and is under nobody's control, which is also why
/// it is exercised directly by tests through <see cref="TlsClientHelloProbe"/>.
/// </remarks>
internal static class TlsClientHello
{
    public static string? ReadServerName(byte[] data)
    {
        try
        {
            int at = 5;                                  // past the record header
            if (data.Length < at + 4 || data[at] != 0x01) return null;   // client hello

            at += 4;                                     // handshake header
            at += 2 + 32;                                // version + random
            if (data.Length <= at) return null;

            at += 1 + data[at];                          // session id
            if (data.Length < at + 2) return null;

            int cipherSuites = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(at, 2));
            at += 2 + cipherSuites;
            if (data.Length <= at) return null;

            at += 1 + data[at];                          // compression methods
            if (data.Length < at + 2) return null;

            int extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(at, 2));
            at += 2;
            int end = Math.Min(data.Length, at + extensionsLength);

            while (at + 4 <= end)
            {
                int type = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(at, 2));
                int length = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(at + 2, 2));
                at += 4;

                if (type == 0 && at + 5 <= end)
                {
                    int nameLength = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(at + 3, 2));
                    if (at + 5 + nameLength <= data.Length)
                        return Encoding.ASCII.GetString(data, at + 5, nameLength);
                }

                at += length;
            }
        }
        catch (ArgumentOutOfRangeException)
        {
            // Malformed or truncated. No name is the right answer.
        }

        return null;
    }
}

/// <summary>
/// Public door onto the client-hello parser, so it can be tested against real bytes.
/// </summary>
/// <remarks>
/// The parser itself stays internal because nothing outside this file should be reaching
/// into a handshake. It is exposed for testing rather than made public because it reads
/// attacker-controlled input and every bound in it is load-bearing.
/// </remarks>
public static class TlsClientHelloProbe
{
    public static string? ReadServerName(byte[] data) => TlsClientHello.ReadServerName(data);
}

/// <summary>One transport segment, as the reassembler needs it.</summary>
public readonly record struct Segment(
    FlowKey Key,
    IPAddress Source,
    ushort SourcePort,
    uint Sequence,
    bool Syn,
    bool Ack,
    uint WireLength,
    byte[] Payload);
