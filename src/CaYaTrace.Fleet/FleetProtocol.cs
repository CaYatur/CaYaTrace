using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CaYaTrace.Fleet;

public enum FleetMessageType
{
    /// <summary>Agent announces itself after the handshake. Carries no evidence.</summary>
    Hello = 0,

    /// <summary>Host accepts the agent. Nothing is collected before this arrives.</summary>
    Approved = 1,

    /// <summary>Host rejects the agent, which then disconnects.</summary>
    Rejected = 2,

    /// <summary>Host tells the agent what to record.</summary>
    StartCollection = 3,

    /// <summary>Host tells the agent to stop and finalize.</summary>
    StopCollection = 4,

    /// <summary>A batch of observations from the agent.</summary>
    Observations = 5,

    /// <summary>Agent's session metadata, sent once collection stops.</summary>
    SessionSummary = 6,

    /// <summary>Keeps an idle connection alive and proves both ends are responsive.</summary>
    Ping = 7,

    Pong = 8,

    /// <summary>
    /// The agent's process table.
    /// </summary>
    /// <remarks>
    /// Sent before the observations, because it is what makes them readable. Without it
    /// a transferred session has no way to say which program did anything: a measured
    /// fleet capture of 106,311 observations rendered its entire causal tree under one
    /// "(unattributed)" root, showed an empty network view, and could not be scoped to
    /// the subject at all, because only observations ever crossed the wire.
    /// </remarks>
    Processes = 9,

    /// <summary>The agent's flow table, for the same reason as <see cref="Processes"/>.</summary>
    Flows = 10,

    /// <summary>
    /// A live sample of what the agent's machine is doing, sent while it records.
    /// </summary>
    /// <remarks>
    /// Deliberately a summary and not evidence: counters and a bounded process list, so
    /// an operator watching several machines can see which one is busy without waiting
    /// for the session to finish. Nothing here is stored as a finding.
    /// </remarks>
    Telemetry = 11,

    /// <summary>Host asks for a telemetry sample, optionally the full process list.</summary>
    TelemetryRequest = 12,

    /// <summary>Host asks the agent to stop a process or a service on its machine.</summary>
    Control = 13,

    /// <summary>The outcome of a <see cref="Control"/> request.</summary>
    ControlResult = 14,
}

public sealed record FleetMessage
{
    [JsonPropertyName("type")] public FleetMessageType Type { get; init; }

    /// <summary>Agent identity, stable across reconnects within a session.</summary>
    [JsonPropertyName("agent")] public string? AgentId { get; init; }

    [JsonPropertyName("payload")] public JsonElement? Payload { get; init; }

    public static FleetMessage Create<T>(FleetMessageType type, string? agentId, T payload)
        => new()
        {
            Type = type,
            AgentId = agentId,
            Payload = JsonSerializer.SerializeToElement(payload, Json),
        };

    public T? Read<T>() where T : class
        => Payload is null ? null : Payload.Value.Deserialize<T>(Json);

    internal static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };
}

/// <summary>What an agent tells the host about itself before anything is collected.</summary>
public sealed record AgentHello
{
    public required string MachineName { get; init; }
    public required string OsBuild { get; init; }
    public required string Architecture { get; init; }
    public bool IsVirtualMachine { get; init; }
    public string? Hypervisor { get; init; }
    public required string ToolVersion { get; init; }
    public bool IsElevated { get; init; }

    /// <summary>Shown to the operator so they can tell which VM is asking.</summary>
    public string Describe()
        => $"{MachineName} · {OsBuild} · {Architecture}" +
           (IsVirtualMachine ? $" · {Hypervisor ?? "virtual machine"}" : " · physical") +
           (IsElevated ? " · elevated" : " · NOT elevated, kernel tracing unavailable");
}

/// <summary>Instructions the host sends once an agent has been approved.</summary>
public sealed record CollectionOrder
{
    public string? TargetPath { get; init; }
    public string? TargetArguments { get; init; }
    public int DurationSeconds { get; init; }
    public bool CaptureSnapshots { get; init; } = true;
    public bool CollectReads { get; init; }

    /// <summary>
    /// Which categories the agent records, matching the choices the local capture screen
    /// offers so that a remote recording and a local one mean the same thing.
    /// </summary>
    public bool CollectFile { get; init; } = true;
    public bool CollectRegistry { get; init; } = true;
    public bool CollectNetwork { get; init; } = true;
    public bool CollectImageLoad { get; init; } = true;
    public bool CollectNetworkMetadata { get; init; } = true;

    /// <summary>
    /// Discard activity outside the subject's process tree at ingest. Only meaningful
    /// with a target; system-wide recording has no tree to be outside of.
    /// </summary>
    public bool DropOutOfScope { get; init; }

    /// <summary>
    /// Packet capture and HTTPS interception are never ordered remotely.
    /// </summary>
    /// <remarks>
    /// Deliberately absent from the order. Both change the machine they run on — one
    /// writes a large capture file, the other installs a trusted root — and a host
    /// being able to trigger either on a remote machine turns a paired agent into a
    /// remote administration channel. Those stay local, operator-initiated decisions.
    /// </remarks>
    [JsonIgnore] public bool RemoteInvasiveCollectionIsNotPermitted => true;
}

/// <summary>
/// A live sample of an agent's machine, sent while it records.
/// </summary>
/// <remarks>
/// A summary rather than evidence. It exists so an operator watching several machines
/// can tell which one is doing something, and so a machine that has been compromised can
/// be looked at without waiting for its recording to finish. Nothing sampled here is
/// stored as a finding — the session on the agent remains the record.
/// </remarks>
public sealed record AgentTelemetry
{
    public required DateTimeOffset SampledAt { get; init; }
    public long EventsRecorded { get; init; }
    public long EventsDropped { get; init; }
    public bool Recording { get; init; }
    public int ProcessCount { get; init; }
    public double CpuPercent { get; init; }
    public long MemoryUsedBytes { get; init; }
    public long MemoryTotalBytes { get; init; }

    /// <summary>
    /// Processes that started or exited since the previous sample, so a watching
    /// operator sees change rather than a list they have to diff by eye.
    /// </summary>
    public List<AgentProcessSample> Started { get; init; } = new();
    public List<AgentProcessSample> Exited { get; init; } = new();

    /// <summary>Present only when the host asked for the full list.</summary>
    public List<AgentProcessSample>? Processes { get; init; }
}

/// <summary>One process as the agent's live view sees it.</summary>
public sealed record AgentProcessSample
{
    public required uint Pid { get; init; }
    public uint ParentPid { get; init; }
    public required string Name { get; init; }
    public string? Path { get; init; }
    public string? CommandLine { get; init; }
    public string? User { get; init; }
    public DateTimeOffset? Started { get; init; }
    public long WorkingSetBytes { get; init; }
    public int ThreadCount { get; init; }

    /// <summary>
    /// True when stopping this process would take the machine down with it. The agent
    /// decides, not the host: the host cannot see the machine and a mistake here is a
    /// blue screen on someone else's computer.
    /// </summary>
    public bool IsCritical { get; init; }

    public string? ServiceNames { get; init; }
}

/// <summary>What the host may ask an agent to do to a running program.</summary>
public enum AgentControlAction
{
    /// <summary>Ask the process to close, and only then stop it.</summary>
    StopProcess = 0,

    /// <summary>Stop the process and everything it started, youngest first.</summary>
    StopProcessTree = 1,

    /// <summary>Stop a service through the service control manager.</summary>
    StopService = 2,

    /// <summary>Set a service to manual start so it does not come back at boot.</summary>
    DisableServiceAutostart = 3,
}

/// <summary>
/// A request to intervene on the agent's machine.
/// </summary>
/// <remarks>
/// <para>
/// This is the one place where the fleet channel stops being read-only, so it is bounded
/// deliberately. The actions are enumerated — there is no "run this command" — the agent
/// refuses anything it judges critical to the machine regardless of what was asked, and
/// every request and outcome is recorded on both ends.
/// </para>
/// <para>
/// It exists because the alternative, when a machine under observation turns out to be
/// compromised, is walking to it. Nothing here can start a program; it can only stop one.
/// </para>
/// </remarks>
public sealed record ControlRequest
{
    public required string RequestId { get; init; }
    public required AgentControlAction Action { get; init; }
    public uint Pid { get; init; }
    public string? ServiceName { get; init; }

    /// <summary>
    /// The name the host believed it was acting on. The agent re-checks it against the
    /// live process before doing anything, so a pid that was recycled between the sample
    /// and the click stops the request instead of hitting an unrelated program.
    /// </summary>
    public string? ExpectedName { get; init; }
}

public sealed record ControlOutcome
{
    public required string RequestId { get; init; }
    public required bool Succeeded { get; init; }
    public required string Message { get; init; }
    public List<string> Affected { get; init; } = new();
}

/// <summary>
/// Frames <see cref="FleetMessage"/> values over a <see cref="SecureChannel"/>.
/// </summary>
public static class FleetTransport
{
    public static async Task SendAsync(SecureChannel channel, FleetMessage message, CancellationToken cancellationToken)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(message, FleetMessage.Json);
        await channel.SendAsync(json, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<FleetMessage?> ReceiveAsync(SecureChannel channel, CancellationToken cancellationToken)
    {
        byte[]? frame = await channel.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        if (frame is null) return null;

        try
        {
            return JsonSerializer.Deserialize<FleetMessage>(frame, FleetMessage.Json);
        }
        catch (JsonException ex)
        {
            // The frame authenticated, so this is a version mismatch rather than an
            // attack — but it is still not something to act on.
            throw new ChannelException("the peer sent a message this build cannot read", ex);
        }
    }

    /// <summary>Human-readable size of a frame, for the transfer log.</summary>
    public static string Describe(FleetMessage message)
        => $"{message.Type} from {message.AgentId ?? "host"}" +
           (message.Payload is null ? string.Empty : $" ({Encoding.UTF8.GetByteCount(message.Payload.Value.GetRawText())} bytes)");
}
