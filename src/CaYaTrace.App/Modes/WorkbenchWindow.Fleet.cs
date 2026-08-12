using System.Net;
using System.Net.Sockets;
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

    private void FleetCollect(bool start)
    {
        if (_fleetHost is null) return;

        if (start)
        {
            // Deliberately a bare order. Packet capture and HTTPS interception are not
            // fields on this record — a host that could switch them on remotely turns a
            // paired agent into a remote administration channel, and both change the
            // machine they run on.
            _fleetHost.StartCollection(new CollectionOrder
            {
                DurationSeconds = 0,
                CaptureSnapshots = true,
            });
        }
        else
        {
            _fleetHost.StopCollection();
        }

        PostFleetState();
    }

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
            }).ToList(),
        };
    }

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
    /// Stores a batch of evidence that arrived from an agent.
    /// </summary>
    /// <remarks>
    /// Each agent gets its own session directory rather than being merged into one. That
    /// is what makes the comparison view work: two machines have to stay two origins,
    /// because the whole point of comparing them is asking which artifacts appear on
    /// both.
    /// </remarks>
    private void OnAgentBatch(FleetAgentConnection agent, ObservationBatch batch)
    {
        // Marshalled to the UI thread. This fires from one receive loop per agent, and
        // the store map and the SQLite connections underneath it are not thread-safe —
        // a defect that would never appear with the single agent it is easiest to test
        // with, and would appear on exactly the multi-VM run the feature exists for.
        if (InvokeRequired)
        {
            try { BeginInvoke(() => OnAgentBatch(agent, batch)); }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
            return;
        }

        try
        {
            if (!_agentStores.TryGetValue(agent.Id, out SessionStore? store))
            {
                string root = _settings.SessionRoot ?? UserSettings.DefaultSessionRoot;
                string machine = agent.Hello?.MachineName ?? agent.Id;
                string directory = Path.Combine(root,
                    $"session_fleet_{Sanitize(machine)}_{DateTime.Now:yyyyMMdd_HHmmss}");

                Directory.CreateDirectory(directory);
                store = SessionStore.Create(Path.Combine(directory, SessionPaths.DatabaseName));

                store.SaveSessionInfo(new SessionInfo
                {
                    SessionId = agent.Id,
                    Name = $"{machine} (fleet)",
                    Mode = SessionMode.SystemWide,
                    StartedAt = agent.ConnectedAt,
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
            }

            // The origin is stamped here, not trusted from the wire: it is what keeps two
            // machines separable in a comparison, and an agent should not be able to
            // claim to be a different one.
            store.ImportObservations(batch.Observations
                .Select(o => o with { OriginId = agent.Id })
                .ToList());

            if (batch.IsFinal)
            {
                store.Checkpoint();
                store.Dispose();
                _agentStores.Remove(agent.Id);

                Toast(Strings.Format("fleet.imported", 1, 1), "ok");
                ListSessions(_settings.SessionRoot);
            }
        }
        catch (Exception ex) when (ex is IOException or Microsoft.Data.Sqlite.SqliteException)
        {
            Toast(ex.Message, "error");
        }
    }

}

/// <summary>
/// The agent half of multi-machine collection: records locally, reports to a host it
/// has been paired with.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately passive. The agent connects out to an address the operator typed and
/// then does nothing at all until the host approves it and sends an order. It opens no
/// listening socket by default, so a machine running the agent has not gained a remote
/// entry point.
/// </para>
/// <para>
/// It also refuses to do the two things that would change the machine it runs on
/// without a local decision: packet capture and HTTPS interception cannot be ordered
/// remotely, and the order type has no field to ask for them.
/// </para>
/// </remarks>
public static class FleetAgentRunner
{
    public static async Task<int> RunAsync(
        string host, int port, string pairingCode, string sessionRoot, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();

        Console.WriteLine($"connecting to {host}:{port}");
        await client.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);

        using SecureChannel channel = await SecureChannel
            .ConnectAsync(client.GetStream(), pairingCode, cancellationToken)
            .ConfigureAwait(false);

        Console.WriteLine($"fingerprint {channel.SessionFingerprint}");
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

        Console.WriteLine("waiting for the host to approve this machine…");

        FleetMessage? decision = await FleetTransport.ReceiveAsync(channel, cancellationToken).ConfigureAwait(false);
        if (decision is null || decision.Type != FleetMessageType.Approved)
        {
            Console.Error.WriteLine("the host did not approve this agent.");
            return 4;
        }

        string agentId = decision.AgentId ?? Guid.NewGuid().ToString("N")[..12];
        Console.WriteLine($"approved as {agentId}");

        return await ServeAsync(channel, agentId, sessionRoot, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ServeAsync(
        SecureChannel channel, string agentId, string sessionRoot, CancellationToken cancellationToken)
    {
        Collectors.SessionOrchestrator? orchestrator = null;
        string? directory = null;

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
                            Kernel = new Collectors.Etw.KernelCollectorOptions { CollectReads = order.CollectReads },

                            // Absent on purpose, and not configurable from the wire.
                            CapturePackets = false,
                            InterceptionConsent = null,
                        });

                        await orchestrator.StartAsync(cancellationToken).ConfigureAwait(false);
                        directory = orchestrator.SessionDirectory;
                        Console.WriteLine($"recording into {directory}");
                        break;
                    }

                    case FleetMessageType.StopCollection when orchestrator is not null:
                    {
                        Console.WriteLine("stopping…");
                        SessionInfo finished = await orchestrator.StopAsync(cancellationToken).ConfigureAwait(false);
                        await orchestrator.DisposeAsync().ConfigureAwait(false);
                        orchestrator = null;

                        await SendSessionAsync(channel, agentId, directory!, finished, cancellationToken)
                            .ConfigureAwait(false);
                        return 0;
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
            if (orchestrator is not null)
            {
                try { await orchestrator.StopAsync(CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) when (ex is IOException or InvalidOperationException) { }
                await orchestrator.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>Streams a finished session to the host in bounded batches.</summary>
    /// <remarks>
    /// Batched because a session is routinely millions of rows and a single frame
    /// holding all of them would need to be buffered whole at both ends. The final batch
    /// is flagged so the host knows the session is complete rather than truncated by a
    /// dropped connection.
    /// </remarks>
    private static async Task SendSessionAsync(
        SecureChannel channel, string agentId, string directory, SessionInfo session, CancellationToken cancellationToken)
    {
        const int BatchSize = 400;

        using SessionStore store = SessionStore.Open(Path.Combine(directory, "session.ctdb"));

        var batch = new List<Observation>(BatchSize);
        long sent = 0;

        foreach (Observation observation in store.Query())
        {
            batch.Add(observation);
            if (batch.Count < BatchSize) continue;

            await SendBatchAsync(channel, agentId, batch, false, cancellationToken).ConfigureAwait(false);
            sent += batch.Count;
            batch.Clear();

            Console.Write($"\rsent {sent:N0}");
        }

        await SendBatchAsync(channel, agentId, batch, true, cancellationToken).ConfigureAwait(false);
        sent += batch.Count;

        Console.WriteLine($"\rsent {sent:N0} observations");

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
