using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Fleet;

public enum AgentState
{
    /// <summary>Handshake completed, waiting for the operator to approve it.</summary>
    Pending = 0,

    Approved = 1,
    Rejected = 2,
    Collecting = 3,
    Finished = 4,
    Gone = 5,
}

/// <summary>One agent's connection, as the host sees it.</summary>
public sealed class FleetAgentConnection
{
    public required string Id { get; init; }

    public required string Fingerprint { get; init; }

    public AgentHello? Hello { get; set; }

    public AgentState State { get; set; } = AgentState.Pending;

    public long EventsReceived { get; set; }

    public long ProcessesReceived { get; set; }

    public long FlowsReceived { get; set; }

    /// <summary>The most recent live sample, or null if none has arrived.</summary>
    public AgentTelemetry? Telemetry { get; set; }

    /// <summary>
    /// How many recordings this agent has completed on this connection.
    /// </summary>
    /// <remarks>
    /// An agent used to exit after one, so a second run meant re-pairing a machine that
    /// was already trusted. It now stays, and this is what tells the operator which of
    /// the listed machines has already produced a session.
    /// </remarks>
    public int SessionsCompleted { get; set; }

    public DateTimeOffset ConnectedAt { get; } = DateTimeOffset.UtcNow;

    internal TaskCompletionSource<bool> Approval { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal SecureChannel? Channel { get; set; }

    public string Describe() => Hello?.Describe() ?? Id;
}

/// <summary>A batch of evidence from one agent.</summary>
public sealed record ObservationBatch
{
    public required string OriginId { get; init; }
    public required List<Observation> Observations { get; init; }
    public bool IsFinal { get; init; }
}

/// <summary>
/// The agent's process table.
/// </summary>
/// <remarks>
/// Transferred separately from the observations and before them, because it is the thing
/// that gives them meaning. See <see cref="FleetMessageType.Processes"/> for what a
/// session looks like without it.
/// </remarks>
public sealed record ProcessBatch
{
    public required string OriginId { get; init; }
    public required List<ProcessNode> Processes { get; init; }
    public bool IsFinal { get; init; }
}

/// <summary>The agent's flow table.</summary>
public sealed record FlowBatch
{
    public required string OriginId { get; init; }
    public required List<NetworkFlow> Flows { get; init; }
    public bool IsFinal { get; init; }
}

/// <summary>
/// Accepts collection agents over an authenticated, encrypted channel.
/// </summary>
/// <remarks>
/// <para>
/// The security posture is the reason this class exists rather than a socket and a
/// callback. An agent that completes the handshake has proved it knows the pairing code
/// and nothing more: it is <b>inert until the operator approves it by name</b>, and
/// approval is a decision made against the machine description the agent sent, shown
/// next to a session fingerprint that both ends display.
/// </para>
/// <para>
/// Nothing is collected before approval, and nothing invasive is ever ordered remotely.
/// See <see cref="CollectionOrder"/> for why packet capture and HTTPS interception are
/// deliberately absent from what a host can ask for.
/// </para>
/// </remarks>
public sealed class FleetHost : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<string, FleetAgentConnection> _agents = new(StringComparer.Ordinal);

    private TcpListener? _listener;
    private CancellationTokenSource? _cancellation;

    /// <summary>
    /// How long an unapproved agent is left waiting.
    /// </summary>
    /// <remarks>
    /// Long enough for an operator to walk to another machine and read a fingerprint
    /// off its screen; short enough that a forgotten connection does not sit open on an
    /// analysis network overnight.
    /// </remarks>
    private static readonly TimeSpan ApprovalWindow = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The current code. Named <c>Code</c> rather than <c>PairingCode</c> so it does not shadow
    /// the type of the same name inside this class.
    /// </summary>
    public string Code { get; private set; } = CaYaTrace.Fleet.PairingCode.Generate();

    public int Port { get; private set; }

    public bool Listening => _listener is not null;

    public event Action? Changed;

    public event Action<FleetAgentConnection, ObservationBatch>? BatchReceived;

    public event Action<FleetAgentConnection, ProcessBatch>? ProcessesReceived;

    public event Action<FleetAgentConnection, FlowBatch>? FlowsReceived;

    /// <summary>
    /// The agent's own account of the session it just finished, which is the only place
    /// the collectors it actually ran, the events it lost, and whether it was elevated
    /// are recorded. The host's stub knows none of that.
    /// </summary>
    public event Action<FleetAgentConnection, SessionInfo>? SummaryReceived;

    public event Action<FleetAgentConnection, ControlOutcome>? ControlCompleted;

    public event Action<FleetAgentConnection, string>? Notice;

    public IReadOnlyList<FleetAgentConnection> Agents
    {
        get { lock (_gate) return _agents.Values.OrderBy(static a => a.ConnectedAt).ToList(); }
    }

    public void Start(int port)
    {
        if (_listener is not null) return;

        _cancellation = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Any, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;

        _ = AcceptLoopAsync(_listener, _cancellation.Token);
        Changed?.Invoke();
    }

    public void Stop()
    {
        _cancellation?.Cancel();

        try { _listener?.Stop(); }
        catch (SocketException) { }

        _listener = null;

        lock (_gate)
        {
            foreach (FleetAgentConnection agent in _agents.Values)
            {
                agent.State = AgentState.Gone;
                agent.Channel?.Dispose();
            }
            _agents.Clear();
        }

        Changed?.Invoke();
    }

    /// <summary>
    /// Issues a new pairing code.
    /// </summary>
    /// <remarks>
    /// The code is the whole of the authentication, so it is treated like a password:
    /// one per run, and rotatable the moment the operator suspects it was seen. Already
    /// connected agents keep their session — their keys were derived at handshake time
    /// and do not depend on the code still being current.
    /// </remarks>
    public void NewPairingCode()
    {
        Code = CaYaTrace.Fleet.PairingCode.Generate();
        Changed?.Invoke();
    }

    public void Decide(string agentId, bool approve)
    {
        lock (_gate)
        {
            if (!_agents.TryGetValue(agentId, out FleetAgentConnection? agent)) return;
            agent.State = approve ? AgentState.Approved : AgentState.Rejected;
            agent.Approval.TrySetResult(approve);
        }
        Changed?.Invoke();
    }

    /// <summary>Sends a collection order to every approved agent.</summary>
    public void StartCollection(CollectionOrder order)
        => Broadcast(FleetMessageType.StartCollection, order, AgentState.Approved);

    public void StopCollection()
        => Broadcast(FleetMessageType.StopCollection, new { }, AgentState.Collecting);

    /// <summary>Sends an order to one agent rather than all of them.</summary>
    /// <remarks>
    /// Several machines under one host is the case this feature exists for, and doing
    /// something to all of them when the operator picked one is the kind of mistake that
    /// only shows up when it is expensive.
    /// </remarks>
    public void StartCollection(string agentId, CollectionOrder order)
        => SendTo(agentId, FleetMessageType.StartCollection, order, becomes: AgentState.Collecting);

    public void StopCollection(string agentId)
        => SendTo(agentId, FleetMessageType.StopCollection, new { });

    /// <summary>Asks one agent for a live sample.</summary>
    public void RequestTelemetry(string agentId, bool fullProcessList)
        => SendTo(agentId, FleetMessageType.TelemetryRequest, new { processes = fullProcessList });

    /// <summary>Asks an agent to stop something on its machine.</summary>
    public void SendControl(string agentId, ControlRequest request)
        => SendTo(agentId, FleetMessageType.Control, request);

    private void SendTo(string agentId, FleetMessageType type, object payload, AgentState? becomes = null)
    {
        FleetAgentConnection? agent;
        lock (_gate) _agents.TryGetValue(agentId, out agent);

        SecureChannel? channel = agent?.Channel;
        if (agent is null || channel is null) return;

        _ = Task.Run(async () =>
        {
            try
            {
                await FleetTransport.SendAsync(
                    channel, FleetMessage.Create(type, agent.Id, payload), CancellationToken.None)
                    .ConfigureAwait(false);

                if (becomes is not null) agent.State = becomes.Value;
                Changed?.Invoke();
            }
            catch (Exception ex) when (ex is IOException or ChannelException or ObjectDisposedException)
            {
                agent.State = AgentState.Gone;
                Changed?.Invoke();
            }
        });
    }

    private void Broadcast(FleetMessageType type, object payload, AgentState required)
    {
        List<FleetAgentConnection> targets;
        lock (_gate) targets = _agents.Values.Where(a => a.State == required).ToList();

        foreach (FleetAgentConnection agent in targets)
        {
            SecureChannel? channel = agent.Channel;
            if (channel is null) continue;

            _ = Task.Run(async () =>
            {
                try
                {
                    await FleetTransport.SendAsync(
                        channel, FleetMessage.Create(type, agent.Id, payload), CancellationToken.None)
                        .ConfigureAwait(false);

                    if (type == FleetMessageType.StartCollection) agent.State = AgentState.Collecting;
                    Changed?.Invoke();
                }
                catch (Exception ex) when (ex is IOException or ChannelException or ObjectDisposedException)
                {
                    agent.State = AgentState.Gone;
                    Changed?.Invoke();
                }
            });
        }
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = HandleAgentAsync(client, cancellationToken);
        }
    }

    private async Task HandleAgentAsync(TcpClient client, CancellationToken cancellationToken)
    {
        FleetAgentConnection? agent = null;

        try
        {
            using (client)
            {
                NetworkStream stream = client.GetStream();

                // The handshake is where an unauthenticated socket becomes a peer that
                // knows the pairing code. Bounded, because an unauthenticated connection
                // that can hold a slot open indefinitely is a denial of service against
                // the only channel the operator has.
                using var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                handshake.CancelAfter(TimeSpan.FromSeconds(30));

                using SecureChannel channel = await SecureChannel
                    .AcceptAsync(stream, Code, handshake.Token)
                    .ConfigureAwait(false);

                FleetMessage? hello = await FleetTransport.ReceiveAsync(channel, handshake.Token).ConfigureAwait(false);
                if (hello is null || hello.Type != FleetMessageType.Hello) return;

                agent = new FleetAgentConnection
                {
                    Id = Guid.NewGuid().ToString("N")[..12],
                    Fingerprint = channel.SessionFingerprint,
                    Hello = hello.Read<AgentHello>(),
                    Channel = channel,
                };

                lock (_gate) _agents[agent.Id] = agent;
                Changed?.Invoke();

                bool approved = await WaitForApprovalAsync(agent, cancellationToken).ConfigureAwait(false);

                await FleetTransport.SendAsync(channel, FleetMessage.Create(
                    approved ? FleetMessageType.Approved : FleetMessageType.Rejected,
                    agent.Id,
                    new { agentId = agent.Id }), cancellationToken).ConfigureAwait(false);

                if (!approved)
                {
                    agent.State = AgentState.Rejected;
                    Changed?.Invoke();
                    return;
                }

                await PumpAsync(agent, channel, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or ChannelException or SocketException
                                      or OperationCanceledException or ObjectDisposedException)
        {
            if (agent is not null) Notice?.Invoke(agent, ex.Message);
        }
        finally
        {
            if (agent is not null)
            {
                agent.Channel = null;
                if (agent.State != AgentState.Finished) agent.State = AgentState.Gone;
                Changed?.Invoke();
            }
        }
    }

    private async Task<bool> WaitForApprovalAsync(FleetAgentConnection agent, CancellationToken cancellationToken)
    {
        using var window = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        window.CancelAfter(ApprovalWindow);

        Task<bool> approval = agent.Approval.Task;
        Task completed = await Task.WhenAny(approval, Task.Delay(Timeout.Infinite, window.Token))
            .ConfigureAwait(false);

        // A window that lapsed is a no. Defaulting the other way would mean an operator
        // who walked away had implicitly approved whatever connected while they were out.
        return completed == approval && approval.Result;
    }

    private async Task PumpAsync(FleetAgentConnection agent, SecureChannel channel, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            FleetMessage? message = await FleetTransport.ReceiveAsync(channel, cancellationToken).ConfigureAwait(false);
            if (message is null) return;

            switch (message.Type)
            {
                case FleetMessageType.Observations:
                    ObservationBatch? batch = message.Read<ObservationBatch>();
                    if (batch is null) break;

                    agent.EventsReceived += batch.Observations.Count;

                    // Not Finished on the last observation batch: the process table, the
                    // flows and the agent's own session record still have to arrive, and
                    // marking the transfer complete here is what let a session be opened
                    // while half of it was still on the wire.
                    agent.State = AgentState.Collecting;
                    BatchReceived?.Invoke(agent, batch);
                    Changed?.Invoke();
                    break;

                case FleetMessageType.Processes:
                    ProcessBatch? processes = message.Read<ProcessBatch>();
                    if (processes is null) break;

                    agent.ProcessesReceived += processes.Processes.Count;
                    ProcessesReceived?.Invoke(agent, processes);
                    Changed?.Invoke();
                    break;

                case FleetMessageType.Flows:
                    FlowBatch? flows = message.Read<FlowBatch>();
                    if (flows is null) break;

                    agent.FlowsReceived += flows.Flows.Count;
                    FlowsReceived?.Invoke(agent, flows);
                    Changed?.Invoke();
                    break;

                case FleetMessageType.Telemetry:
                    AgentTelemetry? sample = message.Read<AgentTelemetry>();
                    if (sample is null) break;

                    agent.Telemetry = sample;
                    Changed?.Invoke();
                    break;

                case FleetMessageType.ControlResult:
                    ControlOutcome? outcome = message.Read<ControlOutcome>();
                    if (outcome is null) break;

                    ControlCompleted?.Invoke(agent, outcome);
                    Changed?.Invoke();
                    break;

                case FleetMessageType.SessionSummary:
                    SessionInfo? summary = message.Read<SessionInfo>();

                    // The agent stays connected now, so a completed recording is a state
                    // it can leave again rather than the end of the conversation.
                    agent.State = AgentState.Finished;
                    agent.SessionsCompleted++;
                    if (summary is not null) SummaryReceived?.Invoke(agent, summary);
                    Changed?.Invoke();
                    break;

                case FleetMessageType.Ping:
                    await FleetTransport.SendAsync(channel,
                        FleetMessage.Create(FleetMessageType.Pong, agent.Id, new { }), cancellationToken)
                        .ConfigureAwait(false);
                    break;
            }
        }
    }

    public void Dispose() => Stop();
}

/// <summary>Serializer settings shared by both ends of the fleet channel.</summary>
public static class FleetJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };
}
