namespace CaYaTrace.Core.Model;

/// <summary>What the operator asked to be monitored.</summary>
public enum SessionMode
{
    /// <summary>Watch a program the operator launches from inside CaYaTrace.</summary>
    LaunchTarget = 0,

    /// <summary>Watch everything, and decide scope afterwards.</summary>
    SystemWide = 1,

    /// <summary>Attach to an already-running process and its future children.</summary>
    AttachExisting = 2,

    /// <summary>Collect on behalf of a remote host as a fleet agent.</summary>
    RemoteAgent = 3,
}

/// <summary>
/// Honest accounting of how complete a session's data actually is.
/// </summary>
/// <remarks>
/// <para>
/// This is deliberately prominent rather than buried in a log. Enabling kernel file
/// and registry keywords machine-wide can produce tens of thousands of events per
/// second during an installer run; when ETW buffers fill, events are dropped
/// silently. If a dropped event happens to be a <c>KCBCreate</c> or a file rundown, every
/// later operation under that object becomes unresolvable — the tool then shows a
/// smaller, cleaner-looking tree that is simply missing things.
/// </para>
/// <para>
/// A monitor that hides this failure mode is worse than one that reports it, because
/// the analyst concludes the program did less than it did. Every number here is shown
/// in the session header and written into every export.
/// </para>
/// </remarks>
public sealed class DataQuality
{
    /// <summary>Events ETW discarded because no buffer was free. Should be zero.</summary>
    public long EventsLost { get; set; }

    /// <summary>Buffers the consumer failed to read in time.</summary>
    public long BuffersLost { get; set; }

    /// <summary>Events accepted into the pipeline.</summary>
    public long EventsCollected { get; set; }

    /// <summary>Events dropped by our own ring buffer because storage fell behind.</summary>
    public long EventsDroppedBySink { get; set; }

    /// <summary>Fraction of file-object lookups that resolved to a path.</summary>
    public double FileNameHitRate { get; set; } = 1.0;

    /// <summary>Fraction of registry KCB lookups that resolved to a key path.</summary>
    public double RegistryNameHitRate { get; set; } = 1.0;

    /// <summary>Network flows that could not be tied to any process.</summary>
    public long UnattributedFlows { get; set; }

    /// <summary>Collectors that failed to start, with the reason.</summary>
    public List<string> CollectorFailures { get; } = new();

    /// <summary>Collectors that were requested but skipped for lack of privilege.</summary>
    public List<string> SkippedForPrivilege { get; } = new();

    public bool IsDegraded
        => EventsLost > 0
           || BuffersLost > 0
           || EventsDroppedBySink > 0
           || FileNameHitRate < 0.95
           || RegistryNameHitRate < 0.95
           || CollectorFailures.Count > 0;

    /// <summary>
    /// Short human-readable verdict for the session header. Returns null when the
    /// session is clean.
    /// </summary>
    public string? Summarize()
    {
        var parts = new List<string>();
        if (EventsLost > 0) parts.Add($"{EventsLost:N0} events lost to ETW buffer pressure");
        if (BuffersLost > 0) parts.Add($"{BuffersLost:N0} buffers lost");
        if (EventsDroppedBySink > 0) parts.Add($"{EventsDroppedBySink:N0} events dropped before storage");
        if (FileNameHitRate < 0.95) parts.Add($"{1 - FileNameHitRate:P1} of file operations unresolved");
        if (RegistryNameHitRate < 0.95) parts.Add($"{1 - RegistryNameHitRate:P1} of registry operations unresolved");
        if (UnattributedFlows > 0) parts.Add($"{UnattributedFlows:N0} network flows unattributed");
        if (CollectorFailures.Count > 0) parts.Add($"{CollectorFailures.Count} collector(s) failed");
        return parts.Count == 0 ? null : string.Join("; ", parts);
    }
}

/// <summary>Identity and provenance of the machine a session was recorded on.</summary>
public sealed class MachineProfile
{
    public string MachineId { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string OsBuild { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public string? UserSid { get; set; }
    public string? UserName { get; set; }
    public bool IsVirtualMachine { get; set; }
    public string? Hypervisor { get; set; }
    public string Locale { get; set; } = string.Empty;
    public string? TimeZone { get; set; }

    /// <summary>
    /// Device-path to drive-letter map, so paths recorded here can be re-resolved
    /// somewhere else.
    /// </summary>
    public Dictionary<string, string> VolumeMap { get; set; } = new();

    /// <summary>Token to concrete-path map for this machine's folder layout.</summary>
    public Dictionary<string, string> KnownFolders { get; set; } = new();
}

/// <summary>Everything describing one recording session.</summary>
public sealed class SessionInfo
{
    public required string SessionId { get; init; }

    public string Name { get; set; } = string.Empty;

    public SessionMode Mode { get; set; }

    public DateTimeOffset StartedAt { get; set; }

    public DateTimeOffset? StoppedAt { get; set; }

    /// <summary>Path of the binary the operator asked to observe, if any.</summary>
    public string? TargetPath { get; set; }

    public string? TargetArguments { get; set; }

    public string? TargetSha256 { get; set; }

    public ProcessKey RootProcess { get; set; }

    public MachineProfile Machine { get; set; } = new();

    public DataQuality Quality { get; set; } = new();

    /// <summary>Collector names that were active for this session.</summary>
    public List<string> EnabledCollectors { get; } = new();

    /// <summary>
    /// True when the intercepting proxy ran and a temporary CA was placed in the
    /// machine trust store. Recorded so the CA's removal can be verified later.
    /// </summary>
    public bool ProxyEnabled { get; set; }

    public string? ProxyCaThumbprint { get; set; }

    public bool ProxyCaRemoved { get; set; }

    /// <summary>Whether the process was elevated. Non-elevated sessions see far less.</summary>
    public bool WasElevated { get; set; }

    public string ToolVersion { get; set; } = string.Empty;

    /// <summary>Agent ids of fleet members that contributed to this session.</summary>
    public List<string> Contributors { get; } = new();

    public TimeSpan Duration => (StoppedAt ?? DateTimeOffset.UtcNow) - StartedAt;
}
