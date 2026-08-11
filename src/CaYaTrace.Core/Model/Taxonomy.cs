namespace CaYaTrace.Core.Model;

/// <summary>
/// Top-level grouping of an observation. Drives UI filtering, export category
/// selection, and which remediation planner handles the artifact.
/// </summary>
public enum EventCategory
{
    Unknown = 0,
    Process = 1,
    Module = 2,
    File = 3,
    Registry = 4,
    Service = 5,
    ScheduledTask = 6,
    Autorun = 7,
    Network = 8,
    Dns = 9,
    Tls = 10,
    Http = 11,
    Security = 12,
    Wmi = 13,
    Driver = 14,
    Firewall = 15,
    Session = 16,
}

/// <summary>Verb of an observation, scoped by its <see cref="EventCategory"/>.</summary>
public enum EventAction
{
    Unknown = 0,

    // Process
    Start = 100,
    Stop = 101,
    ImageLoad = 102,
    ImageUnload = 103,
    RemoteThread = 104,
    HandleOpen = 105,
    MemoryWrite = 106,
    TokenChange = 107,

    // File system
    FileCreate = 200,
    FileOpen = 201,
    FileWrite = 202,
    FileRead = 203,
    FileDelete = 204,
    FileRename = 205,
    FileSetInfo = 206,
    FileSetSecurity = 207,
    DirectoryCreate = 208,
    DirectoryDelete = 209,
    HardLinkCreate = 210,

    // Registry
    KeyCreate = 300,
    KeyOpen = 301,
    KeyDelete = 302,
    KeyRename = 303,
    ValueSet = 304,
    ValueDelete = 305,
    KeySetSecurity = 306,

    // Service / task / autorun
    ServiceInstall = 400,
    ServiceModify = 401,
    ServiceDelete = 402,
    ServiceStart = 403,
    ServiceStop = 404,
    TaskRegister = 410,
    TaskModify = 411,
    TaskDelete = 412,
    AutorunAdd = 420,
    AutorunModify = 421,
    AutorunRemove = 422,

    // Network
    Connect = 500,
    Accept = 501,
    Disconnect = 502,
    Send = 503,
    Receive = 504,
    Listen = 505,
    Reconnect = 506,

    // Name resolution / crypto / application protocol
    DnsQuery = 600,
    DnsResponse = 601,
    TlsClientHello = 610,
    TlsServerHello = 611,
    TlsHandshakeComplete = 612,
    TlsAlert = 613,
    HttpRequest = 620,
    HttpResponse = 621,
    WebSocketMessage = 622,

    // Misc system surface
    DriverLoad = 700,
    FirewallRuleAdd = 710,
    FirewallRuleRemove = 711,
    WmiConsumerCreate = 720,
    WmiFilterCreate = 721,

    // Session lifecycle markers emitted by CaYaTrace itself
    SessionStart = 900,
    SessionStop = 901,
    SnapshotTaken = 902,
    CollectorFault = 903,
    DataLoss = 904,
    UserAnnotation = 905,
}

/// <summary>Outcome of the observed operation, where the source reports one.</summary>
public enum EventStatus
{
    Unknown = 0,
    Success = 1,
    AccessDenied = 2,
    Failed = 3,
    Pending = 4,
}

/// <summary>
/// Which collector produced an observation. Provenance is first-class: an analyst
/// must be able to tell a directly observed kernel event from something inferred by
/// diffing two snapshots, because the two carry very different evidentiary weight.
/// </summary>
public enum EvidenceSource
{
    Unknown = 0,

    /// <summary>Live kernel ETW event. Highest fidelity, carries an actor.</summary>
    KernelEtw = 1,

    /// <summary>User-mode ETW (WinINet, WinHTTP, Schannel, DNS client).</summary>
    UserEtw = 2,

    /// <summary>Derived by diffing a before/after system inventory snapshot.</summary>
    SnapshotDiff = 3,

    /// <summary>Packet capture (Pktmon / WFP), attributed by 5-tuple.</summary>
    PacketCapture = 4,

    /// <summary>Local intercepting HTTP(S) proxy. Full request/response fidelity.</summary>
    Proxy = 5,

    /// <summary>Polled from a Win32/WMI API rather than observed as an event.</summary>
    ApiPoll = 6,

    /// <summary>Produced by CaYaTrace's own correlation, not directly observed.</summary>
    Inferred = 7,

    /// <summary>Supplied by a remote fleet agent running on another machine.</summary>
    RemoteAgent = 8,

    /// <summary>Entered by the analyst.</summary>
    Analyst = 9,
}

/// <summary>
/// How much an observation's <em>attribution</em> should be trusted — specifically,
/// how confident we are that <see cref="Observation.Actor"/> is really the process
/// that caused it. The event itself may be perfectly reliable while its attribution
/// is a guess (a packet matched to a process by 5-tuple, for instance).
/// </summary>
public enum AttributionConfidence
{
    /// <summary>No actor could be determined.</summary>
    None = 0,

    /// <summary>Correlated heuristically; treat as a lead, not a fact.</summary>
    Weak = 1,

    /// <summary>Correlated through a documented but indirect path (port -> PID table).</summary>
    Probable = 2,

    /// <summary>The event source named the actor directly.</summary>
    Direct = 3,
}

public static class TaxonomyExtensions
{
    /// <summary>
    /// Category an action belongs to. Used when a collector knows the verb but the
    /// category was not set explicitly.
    /// </summary>
    public static EventCategory InferCategory(this EventAction action) => (int)action switch
    {
        >= 100 and < 200 => action is EventAction.ImageLoad or EventAction.ImageUnload
            ? EventCategory.Module
            : EventCategory.Process,
        >= 200 and < 300 => EventCategory.File,
        >= 300 and < 400 => EventCategory.Registry,
        >= 400 and < 410 => EventCategory.Service,
        >= 410 and < 420 => EventCategory.ScheduledTask,
        >= 420 and < 500 => EventCategory.Autorun,
        >= 500 and < 600 => EventCategory.Network,
        >= 600 and < 610 => EventCategory.Dns,
        >= 610 and < 620 => EventCategory.Tls,
        >= 620 and < 700 => EventCategory.Http,
        >= 700 and < 710 => EventCategory.Driver,
        >= 710 and < 720 => EventCategory.Firewall,
        >= 720 and < 800 => EventCategory.Wmi,
        >= 900 => EventCategory.Session,
        _ => EventCategory.Unknown,
    };

    /// <summary>
    /// Whether an action represents a persistent change to the system — the subset
    /// that a removal plan can act on. Reads and transient network I/O are excluded.
    /// </summary>
    public static bool IsPersistentChange(this EventAction action) => action switch
    {
        EventAction.FileCreate or EventAction.FileWrite or EventAction.FileRename
            or EventAction.DirectoryCreate or EventAction.HardLinkCreate => true,
        EventAction.KeyCreate or EventAction.ValueSet or EventAction.KeyRename => true,
        EventAction.ServiceInstall or EventAction.ServiceModify => true,
        EventAction.TaskRegister or EventAction.TaskModify => true,
        EventAction.AutorunAdd or EventAction.AutorunModify => true,
        EventAction.DriverLoad => true,
        EventAction.FirewallRuleAdd => true,
        EventAction.WmiConsumerCreate or EventAction.WmiFilterCreate => true,
        _ => false,
    };
}
