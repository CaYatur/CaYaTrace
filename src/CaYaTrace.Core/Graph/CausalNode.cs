using CaYaTrace.Core.Model;

namespace CaYaTrace.Core.Graph;

public enum CausalNodeKind
{
    /// <summary>A process instance. The only kind that can carry another process.</summary>
    Process = 0,

    /// <summary>A verb bucket under a process, e.g. "FILE CREATE".</summary>
    ActionGroup = 1,

    /// <summary>A concrete object: a file path, a registry value, a service name.</summary>
    Artifact = 2,

    /// <summary>A network conversation.</summary>
    Flow = 3,

    /// <summary>One HTTP request/response pair.</summary>
    HttpExchange = 4,

    /// <summary>A leaf carrying metadata about its parent.</summary>
    Detail = 5,
}

/// <summary>Coarse severity, assigned by the scoring pass in CaYaTrace.Analysis.</summary>
public enum RiskLevel
{
    None = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

/// <summary>
/// One node of the causal tree the analyst reads.
/// </summary>
/// <remarks>
/// The tree is a projection, not the storage model. Observations are stored flat and
/// this shape is rebuilt on demand, which is what lets the same session be re-rendered
/// under different scoping and grouping without re-collecting anything.
/// </remarks>
public sealed class CausalNode
{
    public required string Id { get; init; }

    public required CausalNodeKind Kind { get; init; }

    /// <summary>Primary text, e.g. <c>setup.exe</c> or <c>%PROGRAMFILES%\Example\app.exe</c>.</summary>
    public required string Label { get; set; }

    /// <summary>Secondary text: PID, command line, value data, HTTP status.</summary>
    public string? Sublabel { get; set; }

    public EventCategory Category { get; set; }

    public EventAction? Action { get; set; }

    /// <summary>Number of observations collapsed into this node.</summary>
    public int EventCount { get; set; }

    public long BytesSent { get; set; }

    public long BytesReceived { get; set; }

    public DateTimeOffset FirstSeen { get; set; }

    public DateTimeOffset LastSeen { get; set; }

    /// <summary>Process this node belongs to. Set on every node, not just processes.</summary>
    public ProcessKey Process { get; set; }

    /// <summary>
    /// Sequence number of the representative observation, so the UI can jump from a
    /// tree node to the raw evidence.
    /// </summary>
    public long Seq { get; set; }

    /// <summary>All observation sequence numbers folded into this node.</summary>
    public List<long> Evidence { get; } = new();

    public EvidenceSource Source { get; set; }

    public AttributionConfidence Confidence { get; set; }

    public RiskLevel Risk { get; set; }

    /// <summary>Why the node was scored the way it was; shown on hover.</summary>
    public List<string> RiskReasons { get; } = new();

    /// <summary>
    /// Ordered key/value facts rendered beneath the node — old and new registry data,
    /// rename source, HTTP request headers, TLS parameters.
    /// </summary>
    public List<KeyValuePair<string, string>> Facts { get; } = new();

    public List<CausalNode> Children { get; } = new();

    /// <summary>
    /// Set when the node stands for more items than were rendered, so the UI can
    /// offer to expand rather than silently truncating the evidence.
    /// </summary>
    public int TruncatedChildren { get; set; }

    /// <summary>Machine this subtree was observed on. Empty for the local host.</summary>
    public string? OriginId { get; set; }

    public void Absorb(Observation o)
    {
        EventCount++;
        if (Evidence.Count < 512) Evidence.Add(o.Seq);
        if (Seq == 0) Seq = o.Seq;
        if (FirstSeen == default || o.Timestamp < FirstSeen) FirstSeen = o.Timestamp;
        if (o.Timestamp > LastSeen) LastSeen = o.Timestamp;
        if (Confidence < o.Confidence) Confidence = o.Confidence;
        if (Source == EvidenceSource.Unknown) Source = o.Source;
    }

    public int TotalDescendants()
    {
        int n = Children.Count;
        foreach (CausalNode c in Children) n += c.TotalDescendants();
        return n;
    }
}
