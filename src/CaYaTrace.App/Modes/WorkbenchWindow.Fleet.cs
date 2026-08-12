using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using CaYaTrace.App.Fleet;
using CaYaTrace.Core.Model;
using CaYaTrace.Fleet;
using CaYaTrace.Storage;

namespace CaYaTrace.App.Modes;

/// <summary>
/// The host half of multi-machine collection.
/// </summary>
/// <remarks>
/// The operator's decision is the whole security model here, so the UI is built around
/// making it a real decision: an agent that connects is listed with the machine it says
/// it is and a fingerprint both ends display, and it collects nothing until someone
/// approves it by name.
/// </remarks>
public sealed partial class WorkbenchWindow
{
    private FleetHost? _fleetHost;
    private readonly Dictionary<string, SessionStore> _agentStores = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _agentDirectories = new(StringComparer.Ordinal);

    private void FleetStart(int port)
    {
        if (_fleetHost is not null) return;

        int chosen = port > 0 ? port : _settings.FleetPort;

        var host = new FleetHost();
        host.Changed += () => Post("fleet", BuildFleetState());
        host.BatchReceived += OnAgentBatch;
        host.ProcessesReceived += OnAgentProcesses;
        host.FlowsReceived += OnAgentFlows;
        host.SummaryReceived += OnAgentSummary;
        host.ControlCompleted += OnAgentControlResult;
        host.Notice += (agent, message) => Toast($"{agent.Describe()}: {message}", "error");

        try
        {
            host.Start(chosen);
        }
        catch (SocketException ex)
        {
            host.Dispose();
            Toast(ex.Message, "error");
            return;
        }

        _fleetHost = host;
        _settings.FleetPort = host.Port;
        _settings.Save();

        PostFleetState();
    }

    private void FleetStop()
    {
        _fleetHost?.Dispose();
        _fleetHost = null;

        foreach (SessionStore store in _agentStores.Values) store.Dispose();
        _agentStores.Clear();

        PostFleetState();
    }

    private void FleetNewCode()
    {
        _fleetHost?.NewPairingCode();
        PostFleetState();
    }

    private void FleetDecide(string? agentId, bool approve)
    {
        if (agentId is null) return;
        _fleetHost?.Decide(agentId, approve);
        PostFleetState();
    }

    /// <summary>
    /// Starts or stops recording, on one machine or on all of them.
    /// </summary>
    /// <remarks>
    /// The order carries the same category choices the local capture screen offers, so a
    /// remote recording and a local one mean the same thing and can be compared. Packet
    /// capture and HTTPS interception are still deliberately absent: a host that could
    /// switch them on remotely turns a paired agent into a remote administration channel,
    /// and both change the machine they run on.
    /// </remarks>
    private void FleetCollect(bool start, string? agentId, JsonElement request)
    {
        if (_fleetHost is null) return;

        if (start)
        {
            var order = new CollectionOrder
            {
                DurationSeconds = 0,
                TargetPath = Str(request, "targetPath"),
                TargetArguments = Str(request, "targetArguments"),
                CaptureSnapshots = Bool(request, "snapshots", true),
                CollectReads = Bool(request, "reads", false),
                CollectFile = Bool(request, "file", true),
                CollectRegistry = Bool(request, "registry", true),
                CollectNetwork = Bool(request, "network", true),
                CollectImageLoad = Bool(request, "modules", true),
                CollectNetworkMetadata = Bool(request, "networkMetadata", true),
                DropOutOfScope = Bool(request, "subjectOnly", false),
            };

            if (agentId is { Length: > 0 }) _fleetHost.StartCollection(agentId, order);
            else _fleetHost.StartCollection(order);
        }
        else
        {
            if (agentId is { Length: > 0 }) _fleetHost.StopCollection(agentId);
            else _fleetHost.StopCollection();
        }

        PostFleetState();
    }

    /// <summary>Asks one machine for a live sample, optionally the whole process list.</summary>
    private void FleetInspect(string? agentId, bool full)
    {
        if (agentId is null) return;
        _fleetHost?.RequestTelemetry(agentId, full);
    }

    /// <summary>
    /// Asks a machine to stop something.
    /// </summary>
    /// <remarks>
    /// The host names what it believes it is acting on and the agent re-checks that
    /// against its own machine before doing anything, because the list this was clicked
    /// from is seconds old and process ids are recycled in seconds.
    /// </remarks>
    private void FleetControl(string? agentId, JsonElement request)
    {
        if (agentId is null || _fleetHost is null) return;

        string action = Str(request, "action") ?? string.Empty;
        AgentControlAction resolved = action switch
        {
            "stop" => AgentControlAction.StopProcess,
            "stopTree" => AgentControlAction.StopProcessTree,
            "stopService" => AgentControlAction.StopService,
            "disableService" => AgentControlAction.DisableServiceAutostart,
            _ => AgentControlAction.StopProcess,
        };

        if (action is not ("stop" or "stopTree" or "stopService" or "disableService"))
        {
            Toast(Strings.T("fleet.control.unknown"), "error");
            return;
        }

        _fleetHost.SendControl(agentId, new ControlRequest
        {
            RequestId = Guid.NewGuid().ToString("N")[..8],
            Action = resolved,
            Pid = (uint)Math.Max(0, Int(request, "pid")),
            ServiceName = Str(request, "service"),
            ExpectedName = Str(request, "name"),
        });
    }

    // ------------------------------------------------------------- agent side

    private CancellationTokenSource? _agentCancellation;
    private Task? _agentTask;
    private string _agentState = "idle";
    private string _agentMessage = string.Empty;

    /// <summary>
    /// Joins a fleet as an agent.
    /// </summary>
    /// <remarks>
    /// The half that was missing: the host screen existed and the agent side was
    /// command-line only, so a machine could host a fleet from the window but could only
    /// join one from a terminal — on the analysis VM, which is the machine least likely
    /// to have one open.
    /// </remarks>
    private async Task FleetJoinAsync(JsonElement request)
    {
        if (_agentTask is { IsCompleted: false })
        {
            Toast(Strings.T("fleet.agent.already"), "error");
            return;
        }

        string host = Str(request, "host") ?? string.Empty;
        int port = Int(request, "port");
        string code = Str(request, "code") ?? string.Empty;

        if (host.Length == 0 || code.Length == 0)
        {
            Toast(Strings.T("fleet.agent.needs_host"), "error");
            return;
        }

        _agentCancellation = new CancellationTokenSource();
        CancellationToken token = _agentCancellation.Token;

        void Report(AgentProgress progress)
        {
            if (InvokeRequired)
            {
                try { BeginInvoke(() => Report(progress)); }
                catch (ObjectDisposedException) { }
                catch (InvalidOperationException) { }
                return;
            }

            _agentState = progress.State;
            _agentMessage = progress.Message;
            PostAgentState();
        }

        _agentState = "connecting";
        _agentMessage = string.Empty;
        PostAgentState();

        string root = _settings.SessionRoot ?? UserSettings.DefaultSessionRoot;

        _agentTask = Task.Run(() => FleetAgentRunner.RunAsync(
            host, port > 0 ? port : _settings.FleetPort, code, root, Report, token), token);

        try
        {
            await _agentTask.ConfigureAwait(true);
            _agentState = "idle";
            _agentMessage = Strings.T("fleet.agent.disconnected");
        }
        catch (OperationCanceledException)
        {
            _agentState = "idle";
            _agentMessage = Strings.T("fleet.agent.disconnected");
        }
        catch (Exception ex) when (ex is ChannelException or System.Net.Sockets.SocketException or IOException)
        {
            _agentState = "error";

            // A wrong code and a wrong address fail identically here, and saying so saves
            // the operator from re-reading the code when the address is what is wrong.
            _agentMessage = ex is ChannelException
                ? Strings.T("fleet.agent.handshake_failed")
                : ex.Message;
        }

        PostAgentState();
    }

    private void FleetLeave()
    {
        _agentCancellation?.Cancel();
        _agentState = "idle";
        _agentMessage = Strings.T("fleet.agent.disconnected");
        PostAgentState();
    }

    private void PostAgentState() => Post("fleetAgent", new
    {
        state = _agentState,
        message = _agentMessage,
        connected = _agentTask is { IsCompleted: false },
    });

    private void PostFleetState() => Post("fleet", BuildFleetState());

    private object BuildFleetState()
    {
        FleetHost? host = _fleetHost;
        if (host is null)
        {
            return new
            {
                listening = false,
                port = _settings.FleetPort,
                hostAddress = LocalAddress(),
                agents = Array.Empty<object>(),
            };
        }

        return new
        {
            listening = host.Listening,
            port = host.Port,
            pairingCode = host.Code,
            hostAddress = LocalAddress(),
            agents = host.Agents.Select(static a => new
            {
                id = a.Id,
                machine = a.Hello?.MachineName ?? a.Id,
                describe = a.Describe(),
                fingerprint = a.Fingerprint,
                os = a.Hello?.OsBuild,
                architecture = a.Hello?.Architecture,
                virtualMachine = a.Hello?.IsVirtualMachine ?? false,
                hypervisor = a.Hello?.Hypervisor,
                elevated = a.Hello?.IsElevated ?? false,
                toolVersion = a.Hello?.ToolVersion,
                connectedAt = a.ConnectedAt,
                sessions = a.SessionsCompleted,
                state = a.State switch
                {
                    AgentState.Pending => "pending",
                    AgentState.Approved => "approved",
                    AgentState.Collecting => "collecting",
                    AgentState.Finished => "done",
                    AgentState.Rejected => "gone",
                    _ => "gone",
                },
                events = a.EventsReceived,
                processesTransferred = a.ProcessesReceived,
                flowsTransferred = a.FlowsReceived,
                live = a.Telemetry is null ? null : new
                {
                    at = a.Telemetry.SampledAt,
                    recording = a.Telemetry.Recording,
                    recorded = a.Telemetry.EventsRecorded,
                    dropped = a.Telemetry.EventsDropped,
                    processCount = a.Telemetry.ProcessCount,
                    memoryUsed = a.Telemetry.MemoryUsedBytes,
                    memoryTotal = a.Telemetry.MemoryTotalBytes,
                    started = a.Telemetry.Started.Select(Describe).ToList(),
                    exited = a.Telemetry.Exited.Select(Describe).ToList(),
                    processes = a.Telemetry.Processes?.Select(Describe).ToList(),
                },
            }).ToList(),
        };
    }

    private static object Describe(AgentProcessSample p) => new
    {
        pid = p.Pid,
        parent = p.ParentPid,
        name = p.Name,
        path = p.Path,
        commandLine = p.CommandLine,
        user = p.User,
        started = p.Started,
        memory = p.WorkingSetBytes,
        threads = p.ThreadCount,
        critical = p.IsCritical,
        services = p.ServiceNames,
    };

    /// <summary>
    /// The address an agent on the lab network should connect back to.
    /// </summary>
    /// <remarks>
    /// Chosen rather than guessed: a machine running analysis VMs typically has several
    /// interfaces, and the loopback or a Hyper-V default switch address would be shown
    /// with equal confidence and would not work. Preferring a private-range IPv4 address
    /// picks the lab network in the overwhelmingly common case, and the operator can
    /// still read the right one off <c>ipconfig</c> when it does not.
    /// </remarks>
    private static string LocalAddress()
    {
        try
        {
            List<IPAddress> candidates = Dns.GetHostAddresses(Dns.GetHostName())
                .Where(static a => a.AddressFamily == AddressFamily.InterNetwork)
                .Where(static a => !IPAddress.IsLoopback(a))
                .ToList();

            IPAddress? preferred = candidates.FirstOrDefault(static a =>
            {
                byte[] b = a.GetAddressBytes();
                return b[0] == 10
                       || (b[0] == 192 && b[1] == 168)
                       || (b[0] == 172 && b[1] >= 16 && b[1] <= 31);
            });

            return (preferred ?? candidates.FirstOrDefault())?.ToString() ?? "HOST";
        }
        catch (SocketException)
        {
            return "HOST";
        }
    }

    /// <summary>
    /// The store one agent's evidence is being written into, created on first use.
    /// </summary>
    /// <remarks>
    /// Each agent gets its own session directory rather than being merged into one. That
    /// is what makes the comparison view work: two machines have to stay two origins,
    /// because the whole point of comparing them is asking which artifacts appear on
    /// both.
    /// </remarks>
    private SessionStore StoreFor(FleetAgentConnection agent)
    {
        if (_agentStores.TryGetValue(agent.Id, out SessionStore? existing)) return existing;

        string root = _settings.SessionRoot ?? UserSettings.DefaultSessionRoot;
        string machine = agent.Hello?.MachineName ?? agent.Id;
        string directory = Path.Combine(root,
            $"session_fleet_{Sanitize(machine)}_{DateTime.Now:yyyyMMdd_HHmmss}");

        Directory.CreateDirectory(directory);
        SessionStore store = SessionStore.Create(Path.Combine(directory, SessionPaths.DatabaseName));

        // A placeholder until the agent's own record arrives with the summary. It says
        // only what the host can actually know from the handshake.
        store.SaveSessionInfo(new SessionInfo
        {
            SessionId = agent.Id,
            Name = $"{machine} (fleet)",
            Mode = SessionMode.SystemWide,
            StartedAt = agent.ConnectedAt,
            ToolVersion = agent.Hello?.ToolVersion ?? string.Empty,
            WasElevated = agent.Hello?.IsElevated ?? false,
            Machine = new MachineProfile
            {
                MachineId = agent.Id,
                MachineName = machine,
                OsBuild = agent.Hello?.OsBuild ?? string.Empty,
                Architecture = agent.Hello?.Architecture ?? string.Empty,
                IsVirtualMachine = agent.Hello?.IsVirtualMachine ?? false,
                Hypervisor = agent.Hello?.Hypervisor,
            },
        });

        _agentStores[agent.Id] = store;
        _agentDirectories[agent.Id] = directory;
        return store;
    }

    /// <summary>
    /// Runs work against an agent's store on the UI thread.
    /// </summary>
    /// <remarks>
    /// Marshalled because each agent has its own receive loop, and the store map and the
    /// SQLite connections underneath it are not thread-safe — a defect that would never
    /// appear with the single agent it is easiest to test with, and would appear on
    /// exactly the multi-machine run the feature exists for.
    /// </remarks>
    private void WithAgentStore(FleetAgentConnection agent, Action<SessionStore> work)
    {
        if (InvokeRequired)
        {
            try { BeginInvoke(() => WithAgentStore(agent, work)); }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
            return;
        }

        try
        {
            work(StoreFor(agent));
        }
        catch (Exception ex) when (ex is IOException or Microsoft.Data.Sqlite.SqliteException)
        {
            Toast(ex.Message, "error");
        }
    }

    private void OnAgentBatch(FleetAgentConnection agent, ObservationBatch batch)
        => WithAgentStore(agent, store =>
        {
            // The origin is stamped here, not trusted from the wire: it is what keeps two
            // machines separable in a comparison, and an agent should not be able to
            // claim to be a different one.
            store.ImportObservations(batch.Observations
                .Select(o => o with { OriginId = agent.Id })
                .ToList());

            PostFleetState();
        });

    private void OnAgentProcesses(FleetAgentConnection agent, ProcessBatch batch)
        => WithAgentStore(agent, store =>
        {
            foreach (ProcessNode node in batch.Processes) node.OriginId = agent.Id;
            store.UpsertProcesses(batch.Processes);
            PostFleetState();
        });

    private void OnAgentFlows(FleetAgentConnection agent, FlowBatch batch)
        => WithAgentStore(agent, store =>
        {
            store.UpsertFlows(batch.Flows.Select(f => { f.OriginId = agent.Id; return f; }));
            PostFleetState();
        });

    /// <summary>
    /// Applies the agent's own account of the session, and closes it.
    /// </summary>
    /// <remarks>
    /// The summary arrives last and is what marks a transfer complete. It is also the
    /// only place the collectors that actually ran, the events lost, and whether the
    /// machine was elevated are recorded — the host's placeholder knows none of that, and
    /// used to be everything a transferred session said about itself.
    /// </remarks>
    private void OnAgentSummary(FleetAgentConnection agent, SessionInfo summary)
        => WithAgentStore(agent, store =>
        {
            string machine = agent.Hello?.MachineName ?? agent.Id;

            // The agent's record is kept as it stands — it is the only account of what
            // actually ran — and only the identity is re-stamped, so that two agents
            // cannot collide and neither can claim to be a machine it is not.
            summary.Name = $"{machine} (fleet)";
            summary.Machine.MachineId = agent.Id;
            summary.Machine.MachineName = machine;

            store.SaveSessionInfo(summary);
            store.Checkpoint();
            store.Dispose();
            _agentStores.Remove(agent.Id);

            Toast(Strings.Format("fleet.imported", 1, 1), "ok");
            ListSessions(_settings.SessionRoot);
            PostFleetState();
        });

    private void OnAgentControlResult(FleetAgentConnection agent, ControlOutcome outcome)
    {
        if (InvokeRequired)
        {
            try { BeginInvoke(() => OnAgentControlResult(agent, outcome)); }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
            return;
        }

        Toast($"{agent.Hello?.MachineName ?? agent.Id}: {outcome.Message}", outcome.Succeeded ? "ok" : "error");
        PostFleetState();
    }
}
