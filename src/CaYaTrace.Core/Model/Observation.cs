using System.Text.Json.Serialization;

namespace CaYaTrace.Core.Model;

/// <summary>
/// The canonical unit of evidence. Every collector — kernel ETW, snapshot diff,
/// packet capture, proxy, remote agent — normalizes into this one shape so that
/// correlation, storage, export, and remediation all speak a single language.
/// </summary>
/// <remarks>
/// The shape is deliberately flat rather than a polymorphic hierarchy. A session
/// routinely holds millions of rows; a flat record maps onto indexed SQLite columns
/// without a join, keeps filtering cheap, and survives schema drift because anything
/// kind-specific lives in <see cref="Details"/>. Fields that the UI or a removal plan
/// needs to reason about generically are promoted to real columns.
/// </remarks>
public sealed record Observation
{
    /// <summary>Monotonic ingest sequence. Ordering key; unique within a session.</summary>
    public long Seq { get; init; }

    /// <summary>When the event occurred, as reported by the source.</summary>
    public DateTimeOffset Timestamp { get; init; }

    public EventCategory Category { get; init; }

    public EventAction Action { get; init; }

    /// <summary>The process that caused this. <see cref="ProcessKey.None"/> if unattributed.</summary>
    public ProcessKey Actor { get; init; }

    /// <summary>OS thread that performed the operation, when known.</summary>
    public uint ThreadId { get; init; }

    /// <summary>
    /// Primary object acted upon, already normalized: a full file path, a full
    /// registry key path, a service name, a URL, or "ip:port".
    /// </summary>
    public string Target { get; init; } = string.Empty;

    /// <summary>
    /// Secondary object, where the verb has two. Rename destination, registry value
    /// name under <see cref="Target"/>'s key, DNS answer, or HTTP status reason.
    /// </summary>
    public string? Target2 { get; init; }

    /// <summary>
    /// Prior state, when the collector could capture it. Registry value before a set,
    /// old path before a rename, previous service binary path.
    /// </summary>
    public string? OldValue { get; init; }

    /// <summary>New state after the operation.</summary>
    public string? NewValue { get; init; }

    public EventStatus Status { get; init; } = EventStatus.Unknown;

    /// <summary>Bytes moved, where meaningful (file write, socket send, HTTP body).</summary>
    public long Bytes { get; init; }

    public EvidenceSource Source { get; init; }

    public AttributionConfidence Confidence { get; init; }

    /// <summary>
    /// Identifier of the machine this was observed on. Empty for the local host;
    /// set to the agent id for observations arriving from a fleet member. Multi-VM
    /// comparison keys on this.
    /// </summary>
    public string? OriginId { get; init; }

    /// <summary>
    /// Links this observation to another by <see cref="Seq"/> — an HTTP response to
    /// its request, a DNS answer to its query, a send to its connection. Zero when
    /// there is no parent observation.
    /// </summary>
    public long CausedBySeq { get; init; }

    /// <summary>Kind-specific payload as JSON. Never used for filtering.</summary>
    public string? Details { get; init; }

    [JsonIgnore]
    public bool IsAttributed => Actor != ProcessKey.None;

    /// <summary>
    /// Stable content identity, used to recognise "the same change" across machines
    /// and across runs. Deliberately excludes timestamp, sequence, and actor.
    /// </summary>
    public string ArtifactSignature()
        => $"{Category}|{Action}|{Target}|{Target2}";
}
