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
