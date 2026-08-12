using System.Net.Sockets;
using CaYaTrace.Collectors.Live;
using CaYaTrace.Core.Model;
using CaYaTrace.Fleet;
using CaYaTrace.Storage;

namespace CaYaTrace.App.Fleet;

/// <summary>Progress an agent reports back to whatever is hosting it.</summary>
public sealed record AgentProgress(string State, string Message)
{
    public static AgentProgress Of(string state, string message) => new(state, message);
}

/// <summary>
/// The agent half of multi-machine collection: records locally, reports to a host it
/// has been paired with.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately passive. The agent connects out to an address the operator typed and
/// then does nothing at all until the host approves it and sends an order. It opens no
/// listening socket, so a machine running the agent has not gained a remote entry point.
/// </para>
/// <para>
/// It also refuses to do the two things that would change the machine it runs on without
/// a local decision: packet capture and HTTPS interception cannot be ordered remotely,
/// and the order type has no field to ask for them.
/// </para>
/// <para>
/// It does accept requests to stop a process or a service, which is the one way the
/// channel is not read-only. That is bounded by construction — the actions are an
/// enumeration, not a command string — and by the agent re-checking every target against
/// the live machine before touching it. It exists because the alternative, when a machine
/// under observation turns out to be compromised, is walking to it.
/// </para>
/// </remarks>
public static class FleetAgentRunner
{
    /// <summary>
    /// How often the agent samples its machine while recording.
    /// </summary>
    /// <remarks>
    /// Two seconds is fast enough that an operator watching a machine sees a program
    /// appear more or less when it appears, and slow enough that the sampling is not
    /// itself a meaningful share of what the recording is measuring.
    /// </remarks>
    private static readonly TimeSpan TelemetryInterval = TimeSpan.FromSeconds(2);

    public static Task<int> RunAsync(
        string host, int port, string pairingCode, string sessionRoot, CancellationToken cancellationToken)
        => RunAsync(host, port, pairingCode, sessionRoot, null, cancellationToken);

    public static async Task<int> RunAsync(
        string host,
        int port,
        string pairingCode,
        string sessionRoot,
        Action<AgentProgress>? report,
        CancellationToken cancellationToken)
    {
        void Say(string state, string message)
        {
            report?.Invoke(AgentProgress.Of(state, message));
            if (report is null) Console.WriteLine(message);
        }

        using var client = new TcpClient();

        Say("connecting", $"connecting to {host}:{port}");
        await client.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);

        using SecureChannel channel = await SecureChannel
            .ConnectAsync(client.GetStream(), pairingCode, cancellationToken)
            .ConfigureAwait(false);

        Say("fingerprint", channel.SessionFingerprint);
        if (report is null)
            Console.WriteLine("Check that the host shows the same fingerprint before approving.");

        var paths = Core.Naming.PathNormalizer.CreateForCurrentMachine();
        MachineProfile machine = Collectors.MachineProfiler.Describe(paths);

        await FleetTransport.SendAsync(channel, FleetMessage.Create(FleetMessageType.Hello, null, new AgentHello
        {
            MachineName = machine.MachineName,
            OsBuild = machine.OsBuild,
            Architecture = machine.Architecture,
            IsVirtualMachine = machine.IsVirtualMachine,
            Hypervisor = machine.Hypervisor,
            ToolVersion = BuildInfo.Version,
            IsElevated = Privilege.IsElevated(),
        }), cancellationToken).ConfigureAwait(false);

        Say("waiting", "waiting for the host to approve this machine…");

        FleetMessage? decision = await FleetTransport.ReceiveAsync(channel, cancellationToken).ConfigureAwait(false);
        if (decision is null || decision.Type != FleetMessageType.Approved)
        {
            Say("rejected", "the host did not approve this agent.");
            return 4;
        }

        string agentId = decision.AgentId ?? Guid.NewGuid().ToString("N")[..12];
        Say("approved", $"approved as {agentId}");

        return await ServeAsync(channel, agentId, sessionRoot, Say, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ServeAsync(
        SecureChannel channel,
        string agentId,
        string sessionRoot,
        Action<string, string> say,
        CancellationToken cancellationToken)
    {
        Collectors.SessionOrchestrator? orchestrator = null;
        string? directory = null;
        CancellationTokenSource? telemetry = null;

        // Kept across samples so each one reports what changed rather than a list the
        // operator has to diff by eye.
        Dictionary<uint, string> lastSeen = new();

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                FleetMessage? message = await FleetTransport.ReceiveAsync(channel, cancellationToken).ConfigureAwait(false);
                if (message is null) return 0;

                switch (message.Type)
                {
                    case FleetMessageType.StartCollection when orchestrator is null:
                    {
                        CollectionOrder order = message.Read<CollectionOrder>() ?? new CollectionOrder();

                        orchestrator = new Collectors.SessionOrchestrator(new Collectors.SessionOptions
                        {
                            Mode = order.TargetPath is { Length: > 0 }
                                ? SessionMode.LaunchTarget
                                : SessionMode.SystemWide,
                            TargetPath = order.TargetPath,
                            TargetArguments = order.TargetArguments,
                            SessionRoot = sessionRoot,
                            Name = $"agent_{agentId}",
                            CaptureSnapshots = order.CaptureSnapshots,
                            CollectNetworkMetadata = order.CollectNetworkMetadata,
                            DropOutOfScope = order.DropOutOfScope && order.TargetPath is { Length: > 0 },
                            Kernel = new Collectors.Etw.KernelCollectorOptions
                            {
                                CollectReads = order.CollectReads,
                                CollectFile = order.CollectFile,
                                CollectRegistry = order.CollectRegistry,
                                CollectNetwork = order.CollectNetwork,
                                CollectImageLoad = order.CollectImageLoad,
                            },

                            // Absent on purpose, and not configurable from the wire.
                            CapturePackets = false,
                            InterceptionConsent = null,
                        });

                        await orchestrator.StartAsync(cancellationToken).ConfigureAwait(false);
                        directory = orchestrator.SessionDirectory;
                        say("recording", $"recording into {directory}");

                        telemetry = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        Collectors.SessionOrchestrator running = orchestrator;
                        _ = PumpTelemetryAsync(channel, agentId, running, lastSeen, telemetry.Token);
                        break;
                    }

                    case FleetMessageType.StopCollection when orchestrator is not null:
                    {
                        say("stopping", "stopping…");

                        telemetry?.Cancel();
                        telemetry?.Dispose();
                        telemetry = null;

                        SessionInfo finished = await orchestrator.StopAsync(cancellationToken).ConfigureAwait(false);
                        await orchestrator.DisposeAsync().ConfigureAwait(false);
                        orchestrator = null;

                        await SendSessionAsync(channel, agentId, directory!, finished, say, cancellationToken)
                            .ConfigureAwait(false);

                        // Deliberately does not return. An agent that exited here meant a
                        // second recording on the same machine needed the operator to
                        // re-pair a machine they had already approved, which is friction
                        // in exactly the situation — a lab of VMs — the feature exists for.
                        say("idle", "ready for another recording");
                        break;
                    }

                    case FleetMessageType.TelemetryRequest:
                    {
                        bool full = message.Payload?.TryGetProperty("processes", out System.Text.Json.JsonElement p) == true
                                    && p.ValueKind == System.Text.Json.JsonValueKind.True;

                        await SendTelemetryAsync(channel, agentId, orchestrator, lastSeen, full, cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    }

                    case FleetMessageType.Control:
                    {
                        ControlRequest? request = message.Read<ControlRequest>();
                        if (request is null) break;

                        ControlOutcome outcome = Execute(request, say);
                        await FleetTransport.SendAsync(channel,
                            FleetMessage.Create(FleetMessageType.ControlResult, agentId, outcome), cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    }

                    case FleetMessageType.Ping:
                        await FleetTransport.SendAsync(channel,
                            FleetMessage.Create(FleetMessageType.Pong, agentId, new { }), cancellationToken)
                            .ConfigureAwait(false);
                        break;
                }
            }

            return 0;
        }
        finally
        {
            telemetry?.Cancel();
            telemetry?.Dispose();

            if (orchestrator is not null)
            {
                try { await orchestrator.StopAsync(CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) when (ex is IOException or InvalidOperationException) { }
                await orchestrator.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Carries out a host's request, having checked it against the live machine first.
    /// </summary>
    /// <remarks>
    /// The re-check is not ceremony. The host is acting on a list that is at best seconds
    /// old, process ids are recycled within seconds on a busy machine, and terminating the
    /// wrong program is not recoverable by trying again.
    /// </remarks>
    private static ControlOutcome Execute(ControlRequest request, Action<string, string> say)
    {
        say("control", $"host asked to {request.Action} {request.ExpectedName ?? request.ServiceName ?? request.Pid.ToString()}");

        ControlResult result = request.Action switch
        {
            AgentControlAction.StopProcess => ProcessControl.Stop(request.Pid, request.ExpectedName),
            AgentControlAction.StopProcessTree => ProcessControl.StopTree(request.Pid, request.ExpectedName),
            AgentControlAction.StopService when request.ServiceName is { Length: > 0 } =>
                ProcessControl.StopService(request.ServiceName),
            AgentControlAction.DisableServiceAutostart when request.ServiceName is { Length: > 0 } =>
                ProcessControl.DisableAutostart(request.ServiceName),
            _ => ControlResult.Refused("the request named nothing this agent can act on"),
        };

        say("control", result.Message);

        return new ControlOutcome
        {
            RequestId = request.RequestId,
            Succeeded = result.Succeeded,
            Message = result.Message,
            Affected = result.Affected.ToList(),
        };
    }

    private static async Task PumpTelemetryAsync(
        SecureChannel channel,
        string agentId,
        Collectors.SessionOrchestrator orchestrator,
        Dictionary<uint, string> lastSeen,
        CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(TelemetryInterval, cancellationToken).ConfigureAwait(false);
                await SendTelemetryAsync(channel, agentId, orchestrator, lastSeen, false, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is IOException or ChannelException or ObjectDisposedException)
        {
            // The channel went away. The recording is the thing that matters and it keeps
            // running; losing the live view is not a reason to stop collecting.
        }
    }

    private static async Task SendTelemetryAsync(
        SecureChannel channel,
        string agentId,
        Collectors.SessionOrchestrator? orchestrator,
        Dictionary<uint, string> lastSeen,
        bool full,
        CancellationToken cancellationToken)
    {
        List<LiveProcess> live = LiveProcessTable.Read(detailed: full);

        var started = new List<AgentProcessSample>();
        var exited = new List<AgentProcessSample>();
        var current = new Dictionary<uint, string>(live.Count);

        foreach (LiveProcess p in live)
        {
            current[p.Pid] = p.Name;
            if (!lastSeen.ContainsKey(p.Pid)) started.Add(Sample(p));
        }

        foreach ((uint pid, string name) in lastSeen)
        {
            if (current.ContainsKey(pid)) continue;
            exited.Add(new AgentProcessSample { Pid = pid, Name = name });
        }

        lastSeen.Clear();
        foreach ((uint pid, string name) in current) lastSeen[pid] = name;

        var sample = new AgentTelemetry
        {
            SampledAt = DateTimeOffset.UtcNow,
            Recording = orchestrator is not null,
            EventsRecorded = orchestrator?.Context?.Sink?.Accepted ?? 0,
            EventsDropped = orchestrator?.Context?.Sink?.Dropped ?? 0,
            ProcessCount = live.Count,
            MemoryUsedBytes = MachineMemory.Used(),
            MemoryTotalBytes = MachineMemory.Total(),

            // Bounded. A machine mid-install can churn dozens of processes between two
            // samples, and a frame that grows without limit on the busiest machine is the
            // one that breaks when it is most needed.
            Started = started.Take(50).ToList(),
            Exited = exited.Take(50).ToList(),
            Processes = full ? live.Select(Sample).ToList() : null,
        };

        await FleetTransport.SendAsync(channel,
            FleetMessage.Create(FleetMessageType.Telemetry, agentId, sample), cancellationToken)
            .ConfigureAwait(false);
    }

    private static AgentProcessSample Sample(LiveProcess p) => new()
    {
        Pid = p.Pid,
        ParentPid = p.ParentPid,
        Name = p.Name,
        Path = p.Path,
        CommandLine = p.CommandLine,
        User = p.User,
        Started = p.Started,
        WorkingSetBytes = p.WorkingSetBytes,
        ThreadCount = p.ThreadCount,
        IsCritical = p.IsCritical,
        ServiceNames = p.ServiceNames,
    };

    /// <summary>
    /// Streams a finished session to the host in bounded batches.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Batched because a session is routinely millions of rows and a single frame holding
    /// all of them would need to be buffered whole at both ends.
    /// </para>
    /// <para>
    /// The process and flow tables go first, and they are not optional. A measured fleet
    /// transfer that sent only observations produced a session of 106,311 events whose
    /// entire causal tree hung under one "(unattributed)" node, whose network view was
    /// empty, and which could not be narrowed to the subject at all — every row was there
    /// and nothing could be said about any of it.
    /// </para>
    /// </remarks>
    private static async Task SendSessionAsync(
        SecureChannel channel,
        string agentId,
        string directory,
        SessionInfo session,
        Action<string, string> say,
        CancellationToken cancellationToken)
    {
        const int BatchSize = 400;

        using SessionStore store = SessionStore.Open(Path.Combine(directory, "session.ctdb"));

        List<ProcessNode> processes = store.LoadProcesses();
        for (int i = 0; i < processes.Count || i == 0; i += BatchSize)
        {
            List<ProcessNode> slice = processes.Skip(i).Take(BatchSize).ToList();
            await FleetTransport.SendAsync(channel, FleetMessage.Create(
                FleetMessageType.Processes, agentId,
                new ProcessBatch
                {
                    OriginId = agentId,
                    Processes = slice,
                    IsFinal = i + BatchSize >= processes.Count,
                }), cancellationToken).ConfigureAwait(false);

            if (processes.Count == 0) break;
        }

        say("sending", $"sent {processes.Count:N0} processes");

        List<NetworkFlow> flows = store.LoadFlows();
        for (int i = 0; i < flows.Count || i == 0; i += BatchSize)
        {
            List<NetworkFlow> slice = flows.Skip(i).Take(BatchSize).ToList();
            await FleetTransport.SendAsync(channel, FleetMessage.Create(
                FleetMessageType.Flows, agentId,
                new FlowBatch
                {
                    OriginId = agentId,
                    Flows = slice,
                    IsFinal = i + BatchSize >= flows.Count,
                }), cancellationToken).ConfigureAwait(false);

            if (flows.Count == 0) break;
        }

        say("sending", $"sent {flows.Count:N0} flows");

        var batch = new List<Observation>(BatchSize);
        long sent = 0;

        foreach (Observation observation in store.Query())
        {
            batch.Add(observation);
            if (batch.Count < BatchSize) continue;

            await SendBatchAsync(channel, agentId, batch, false, cancellationToken).ConfigureAwait(false);
            sent += batch.Count;
            batch.Clear();

            if (sent % 20_000 == 0) say("sending", $"sent {sent:N0} observations");
        }

        await SendBatchAsync(channel, agentId, batch, true, cancellationToken).ConfigureAwait(false);
        sent += batch.Count;

        say("sending", $"sent {sent:N0} observations");

        // Last, because it is what tells the host the transfer is complete — and because
        // it is the only place the collectors that actually ran, the events lost, and
        // whether the machine was elevated are recorded. The host's own stub knows none
        // of that and used to be all a transferred session had.
        await FleetTransport.SendAsync(channel,
            FleetMessage.Create(FleetMessageType.SessionSummary, agentId, session), cancellationToken)
            .ConfigureAwait(false);
    }

    private static Task SendBatchAsync(
        SecureChannel channel, string agentId, List<Observation> batch, bool isFinal, CancellationToken cancellationToken)
        => FleetTransport.SendAsync(channel, FleetMessage.Create(
            FleetMessageType.Observations, agentId,
            new ObservationBatch
            {
                OriginId = agentId,
                Observations = new List<Observation>(batch),
                IsFinal = isFinal,
            }), cancellationToken);
}

/// <summary>Machine memory, for the live view's one-line summary.</summary>
internal static class MachineMemory
{
    public static long Total()
    {
        var status = new MEMORYSTATUSEX { dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MEMORYSTATUSEX>() };
        return GlobalMemoryStatusEx(ref status) ? (long)status.ullTotalPhys : 0;
    }

    public static long Used()
    {
        var status = new MEMORYSTATUSEX { dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MEMORYSTATUSEX>() };
        return GlobalMemoryStatusEx(ref status) ? (long)(status.ullTotalPhys - status.ullAvailPhys) : 0;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buffer);
}
