using System.Net;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Collectors.Network;

/// <summary>
/// Turns a capture file into conversations, and joins them to what is known about processes.
/// </summary>
/// <remarks>
/// <para>
/// Shared by every source that produces a capture — the packet monitor watching adapters,
/// and the loopback adapter watching what never reaches one. Both arrive as pcapng, and a
/// second copy of this reading would be a second place for the two to disagree about what
/// a conversation is.
/// </para>
/// <para>
/// Packets carry no process, which is the standing gap in capture-based tooling; feeding
/// the recovered 5-tuples through the flow table attaches the attribution the kernel
/// provider already established. Where it cannot, the conversation stays unattributed —
/// guessing an owner would undo the point of tracking attribution confidence at all.
/// </para>
/// </remarks>
internal static class CaptureCorrelator
{
    internal sealed class Result
    {
        public int Conversations { get; set; }
        public int Attributed { get; set; }
        public int WithContent { get; set; }
        public int LocalNetwork { get; set; }
        public int Loopback { get; set; }
        public int Skipped { get; set; }
    }

    /// <summary>
    /// Reads a capture and emits one observation per conversation.
    /// </summary>
    /// <param name="ignorePorts">
    /// Local ports belonging to this tool itself. The workbench renders through an embedded
    /// browser and the interception proxy has a loopback leg of its own, so a loopback
    /// capture records CaYaTrace talking to CaYaTrace — several megabytes of it, in the
    /// middle of the evidence for something else.
    /// </param>
    internal static Result Correlate(
        CollectorContext ctx,
        string collectorName,
        string pcapngPath,
        EvidenceSource source,
        IReadOnlyCollection<ushort>? ignorePorts = null)
    {
        var result = new Result();

        IReadOnlyList<Conversation> conversations;
        try
        {
            conversations = ConversationRecorder.Read(pcapngPath, LocalAddresses());
        }
        catch (Exception ex) when (ex is IOException or EndOfStreamException or InvalidDataException)
        {
            ctx.Store.LogQuality(collectorName, "warning", $"the capture could not be read back: {ex.Message}");
            return result;
        }

        foreach (Conversation conversation in conversations)
        {
            FlowKey key = conversation.Key;

            if (ignorePorts is { Count: > 0 }
                && (ignorePorts.Contains(key.LocalPort) || ignorePorts.Contains(key.RemotePort)))
            {
                result.Skipped++;
                continue;
            }

            result.Conversations++;

            Core.Correlation.FlowAttribution owner = ctx.Flows.Attribute(key, conversation.Last);

            ctx.Flows.NoteBytes(key, conversation.Last, sent: 0, received: 0,
                packetsSent: conversation.PacketsOut, packetsReceived: conversation.PacketsIn);

            NetworkFlow tracked = ctx.Flows.GetOrCreate(key, conversation.First);
            if (tracked.BytesSent + tracked.BytesReceived < conversation.BytesOut + conversation.BytesIn)
            {
                // The wire totals are authoritative over the kernel provider's, which
                // counts payload handed to the stack rather than bytes on the link.
                tracked.BytesSent = conversation.BytesOut;
                tracked.BytesReceived = conversation.BytesIn;
            }

            tracked.ServerName ??= conversation.ServerName;

            if (owner.Owner != ProcessKey.None) result.Attributed++;
            if (conversation.Scope == PeerScope.LocalNetwork) result.LocalNetwork++;
            if (conversation.Scope == PeerScope.Loopback) result.Loopback++;

            string? outboundHash = StoreBody(ctx, conversation.Outbound);
            string? inboundHash = StoreBody(ctx, conversation.Inbound);
            if (outboundHash is not null || inboundHash is not null) result.WithContent++;

            ctx.Emit(new Observation
            {
                Timestamp = conversation.First,
                Category = EventCategory.Network,
                Action = conversation.Inbound_Connection ? EventAction.Accept : EventAction.Connect,
                Actor = owner.Owner,
                Target = $"{key.RemoteAddress}:{key.RemotePort}",
                Target2 = conversation.ServerName ?? conversation.Protocol.ToString(),
                NewValue = conversation.Summary,
                Bytes = conversation.BytesOut + conversation.BytesIn,
                Source = source,
                Confidence = owner.Confidence,
                Status = EventStatus.Success,

                // The hashes are how the view finds the bodies. Written as details rather
                // than as columns because nothing filters on them.
                Details = System.Text.Json.JsonSerializer.Serialize(new
                {
                    scope = conversation.Scope.ToString(),
                    protocol = conversation.Protocol.ToString(),
                    localPort = key.LocalPort,
                    inbound = conversation.Inbound_Connection,
                    truncated = conversation.Truncated,
                    sentBody = outboundHash,
                    receivedBody = inboundHash,
                    sentBytes = conversation.Outbound.Length,
                    receivedBytes = conversation.Inbound.Length,
                    evidence = owner.Evidence,
                }),
            });
        }

        return result;
    }

    /// <summary>Stores one direction's bytes, returning the hash that finds them again.</summary>
    /// <remarks>
    /// Content-addressed, so two conversations that carried the same bytes are stored
    /// once — which is common, because the same beacon repeated fifty times is fifty
    /// identical payloads.
    /// </remarks>
    private static string? StoreBody(CollectorContext ctx, byte[] body)
    {
        if (body.Length == 0) return null;

        string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(body)).ToLowerInvariant();

        try
        {
            ctx.Store.WriteBlob(hash, body, "application/octet-stream");
            return hash;
        }
        catch (Exception ex) when (ex is IOException or Microsoft.Data.Sqlite.SqliteException)
        {
            return null;
        }
    }

    /// <summary>
    /// This machine's addresses, used to tell an outbound conversation from an inbound one.
    /// </summary>
    /// <remarks>
    /// Which end connected is the difference between "it called out to a server" and
    /// "something on the network connected to it", and only the second one means the
    /// program was listening. On loopback both ends are this machine and the addresses
    /// settle nothing — there the recorder falls back to the SYN, which is the only thing
    /// that actually knows.
    /// </remarks>
    internal static List<IPAddress> LocalAddresses()
    {
        var result = new List<IPAddress> { IPAddress.Loopback, IPAddress.IPv6Loopback };

        try
        {
            foreach (System.Net.NetworkInformation.NetworkInterface nic in
                     System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (System.Net.NetworkInformation.UnicastIPAddressInformation address in
                         nic.GetIPProperties().UnicastAddresses)
                {
                    result.Add(address.Address);
                }
            }
        }
        catch (System.Net.NetworkInformation.NetworkInformationException)
        {
            // Without the interface list, orientation falls back to the canonical key —
            // less accurate, still usable.
        }

        return result;
    }
}
