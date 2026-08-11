using System.Net;
using System.Net.Sockets;

namespace CaYaTrace.Core.Model;

public enum TransportProtocol
{
    Unknown = 0,
    Tcp = 6,
    Udp = 17,
    Icmp = 1,
    IcmpV6 = 58,
}

/// <summary>
/// The canonical 5-tuple identifying a network conversation.
/// </summary>
/// <remarks>
/// Used as the join key between three sources that each know something different:
/// the kernel network provider knows the owning process but little about content,
/// packet capture knows the bytes but no process, and the intercepting proxy knows
/// the full HTTP exchange but only sees a local socket. The 5-tuple plus a time
/// window is what stitches them into one story.
/// </remarks>
public readonly record struct FlowKey(
    TransportProtocol Protocol,
    IPAddress LocalAddress,
    ushort LocalPort,
    IPAddress RemoteAddress,
    ushort RemotePort)
{
    public static readonly FlowKey Empty = new(
        TransportProtocol.Unknown, IPAddress.None, 0, IPAddress.None, 0);

    public bool IsEmpty => LocalPort == 0 && RemotePort == 0;

    public bool IsLoopback
        => IPAddress.IsLoopback(LocalAddress) && IPAddress.IsLoopback(RemoteAddress);

    public bool IsIPv6 => LocalAddress.AddressFamily == AddressFamily.InterNetworkV6;

    /// <summary>The same conversation seen from the other endpoint.</summary>
    public FlowKey Reversed()
        => new(Protocol, RemoteAddress, RemotePort, LocalAddress, LocalPort);

    /// <summary>
    /// Direction-independent identity, so a connect observed outbound and the same
    /// conversation observed inbound collapse to one flow.
    /// </summary>
    public FlowKey Canonical()
    {
        int cmp = CompareEndpoints(LocalAddress, LocalPort, RemoteAddress, RemotePort);
        return cmp <= 0 ? this : Reversed();
    }

    public bool Equals(FlowKey other)
        => Protocol == other.Protocol
           && LocalPort == other.LocalPort
           && RemotePort == other.RemotePort
           && LocalAddress.Equals(other.LocalAddress)
           && RemoteAddress.Equals(other.RemoteAddress);

    public override int GetHashCode()
        => HashCode.Combine(Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort);

    public override string ToString()
    {
        string local = Format(LocalAddress, LocalPort);
        string remote = Format(RemoteAddress, RemotePort);
        return $"{Protocol.ToString().ToUpperInvariant()} {local} -> {remote}";
    }

    public static string Format(IPAddress address, ushort port)
        => address.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{address}]:{port}"
            : $"{address}:{port}";

    private static int CompareEndpoints(IPAddress a, ushort ap, IPAddress b, ushort bp)
    {
        byte[] ab = a.GetAddressBytes(), bb = b.GetAddressBytes();
        if (ab.Length != bb.Length) return ab.Length.CompareTo(bb.Length);
        for (int i = 0; i < ab.Length; i++)
        {
            if (ab[i] != bb[i]) return ab[i].CompareTo(bb[i]);
        }
        return ap.CompareTo(bp);
    }
}

/// <summary>A network conversation with everything we learned about it.</summary>
public sealed class NetworkFlow
{
    public required FlowKey Key { get; init; }

    public ProcessKey Owner { get; set; }

    public AttributionConfidence OwnerConfidence { get; set; }

    /// <summary>How the owner was determined, for the evidence trail.</summary>
    public string? OwnerEvidence { get; set; }

    public DateTimeOffset FirstSeen { get; set; }

    public DateTimeOffset LastSeen { get; set; }

    public DateTimeOffset? ClosedAt { get; set; }

    public long BytesSent { get; set; }

    public long BytesReceived { get; set; }

    public long PacketsSent { get; set; }

    public long PacketsReceived { get; set; }

    /// <summary>Hostname the remote address resolved from, when a DNS answer matched.</summary>
    public string? ResolvedHost { get; set; }

    /// <summary>TLS SNI observed in the ClientHello, when the flow was TLS.</summary>
    public string? ServerName { get; set; }

    public string? TlsVersion { get; set; }

    public string? Alpn { get; set; }

    /// <summary>JA3/JA4 client fingerprint, when computed from the ClientHello.</summary>
    public string? ClientFingerprint { get; set; }

    /// <summary>Sequence numbers of HTTP observations carried over this flow.</summary>
    public List<long> HttpExchanges { get; } = new();

    public string? OriginId { get; set; }

    public bool IsActive(DateTimeOffset at) => at >= FirstSeen && (ClosedAt is null || at <= ClosedAt.Value);
}
