using System.Diagnostics;
using CaYaTrace.Collectors.Etw;
using CaYaTrace.Collectors.Snapshots;
using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;
using CaYaTrace.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CaYaTrace.Collectors;

public sealed class SessionOptions
{
    public SessionMode Mode { get; init; } = SessionMode.LaunchTarget;

    /// <summary>Program to launch and observe. Required for <see cref="SessionMode.LaunchTarget"/>.</summary>
    public string? TargetPath { get; init; }

    public string? TargetArguments { get; init; }

    public string? WorkingDirectory { get; init; }

    /// <summary>PID to attach to for <see cref="SessionMode.AttachExisting"/>.</summary>
    public uint AttachPid { get; init; }

    public string? Name { get; init; }

    /// <summary>Root directory for session folders.</summary>
    public required string SessionRoot { get; init; }

    public KernelCollectorOptions Kernel { get; init; } = KernelCollectorOptions.Default;

    /// <summary>
    /// Collect DNS, TLS metadata, and URLs from the Windows HTTP stacks. Non-invasive:
    /// no certificate authority, no proxy, nothing changed on the machine.
    /// </summary>
    public bool CollectNetworkMetadata { get; init; } = true;

    /// <summary>
    /// Watch Winsock, so conversations between processes on this machine are recorded.
    /// </summary>
    /// <remarks>
    /// On by default and cheap. It is the only source that sees loopback traffic at all:
    /// the packet monitor observes network adapters, and traffic that never leaves the
    /// machine crosses none of them.
    /// </remarks>
    public bool CollectLocalSockets { get; init; } = true;

    public NetworkCollectorOptions Network { get; init; } = NetworkCollectorOptions.Default;

    /// <summary>Capture packets with the Windows packet monitor. Off by default.</summary>
    public bool CapturePackets { get; init; }

    /// <summary>
    /// Consent callback for HTTPS interception. Interception is impossible without one:
    /// there is deliberately no boolean that turns it on, because something has to
    /// affirmatively answer for the trusted root it installs.
    /// </summary>
    public Func<CaYaTrace.Collectors.Proxy.InterceptionConsentRequest, bool>? InterceptionConsent { get; init; }

    public CaYaTrace.Collectors.Proxy.ProxyCollectorOptions ProxyOptions { get; init; }
        = CaYaTrace.Collectors.Proxy.ProxyCollectorOptions.Default;

    public CaYaTrace.Collectors.Network.PktmonOptions Pktmon { get; init; }
        = CaYaTrace.Collectors.Network.PktmonOptions.Default;

    /// <summary>
    /// Capture what programs on this machine say to each other, with their contents.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off by default, and for two reasons rather than one. It needs a packet driver this
    /// tool does not install, and turning it on changes what a recording contains: local
    /// conversations belonging to every process on the machine, not only the subject's.
    /// </para>
    /// <para>
    /// It is also the only way to see those contents at all. An established loopback
    /// connection never becomes a packet on any adapter, so without this a program talking
    /// to a local helper it installed appears as a connection to 127.0.0.1 carrying some
    /// number of bytes, and the bytes themselves are simply not recoverable afterwards.
    /// </para>
    /// </remarks>
    public bool CaptureLoopback { get; init; }

    public CaYaTrace.Collectors.Network.LoopbackOptions Loopback { get; init; }
        = CaYaTrace.Collectors.Network.LoopbackOptions.Default;

    /// <summary>Take before/after system inventories around the session.</summary>
    public bool CaptureSnapshots { get; init; } = true;

    /// <summary>
    /// Discard activity from processes outside the target tree at ingest. Cuts session
    /// size dramatically; the trade is that scope cannot be widened afterwards.
    /// </summary>
    public bool DropOutOfScope { get; init; }

    public ObservationSinkOptions Sink { get; init; } = ObservationSinkOptions.Default;
}

/// <summary>
/// Owns the lifecycle of one recording session: set up storage, start collectors,
/// launch the subject, and on stop turn everything into a queryable result.
/// </summary>
/// <remarks>
/// The ordering here is not incidental. Collectors start before the subject is
/// resumed, snapshots are taken before collectors so the baseline is not polluted by
/// our own activity, and the subject is created suspended so that not one of its
/// events is missed. Getting this sequence wrong is how a monitor ends up showing an
/// installer that mysteriously did nothing for its first 200 milliseconds — which is
/// exactly the window in which packers and droppers do their work.
/// </remarks>
public sealed class SessionOrchestrator : IAsyncDisposable
{
    private readonly SessionOptions _options;
    private readonly ILogger _logger;
    private readonly List<ICollector> _collectors = new();

    private SessionStore? _store;
    private ObservationSink? _sink;
    private CollectorContext? _ctx;
    private SnapshotEngine? _snapshots;
    private SuspendedProcess? _target;
    private bool _stopped;

    public SessionOrchestrator(SessionOptions options, ILogger? logger = null)
    {
        _options = options;
        _logger = logger ?? NullLogger.Instance;
    }

    public SessionInfo? Session { get; private set; }

    public string? SessionDirectory { get; private set; }

    public CollectorContext? Context => _ctx;

    /// <summary>Registers an additional collector. Must be called before <see cref="StartAsync"/>.</summary>
    public void AddCollector(ICollector collector) => _collectors.Add(collector);

    public async Task<SessionInfo> StartAsync(CancellationToken cancellationToken = default)
    {
        string sessionId = $"{DateTimeOffset.Now:yyyyMMdd_HHmmss}_{Environment.ProcessId:x}";
        SessionDirectory = Path.Combine(_options.SessionRoot, $"session_{sessionId}");
        Directory.CreateDirectory(SessionDirectory);

        _store = SessionStore.Create(Path.Combine(SessionDirectory, "session.ctdb"));
        _sink = new ObservationSink(_store, SessionDirectory, _options.Sink);

        PathNormalizer paths = PathNormalizer.CreateForCurrentMachine();

        var session = new SessionInfo
        {
            SessionId = sessionId,
            Name = _options.Name ?? BuildDefaultName(),
            Mode = _options.Mode,
            StartedAt = DateTimeOffset.UtcNow,
            TargetPath = _options.TargetPath,
            TargetArguments = _options.TargetArguments,
            WasElevated = IsElevated(),
            ToolVersion = typeof(SessionOrchestrator).Assembly.GetName().Version?.ToString() ?? "0.0.0",
            Machine = MachineProfiler.Describe(paths),
        };
        Session = session;

        _ctx = new CollectorContext
        {
            Session = session,
            Sink = _sink,
            Store = _store,
            SessionDirectory = SessionDirectory,
            Processes = new ProcessTable(),
            Flows = new FlowTable(),
            Paths = paths,
            Files = new FileObjectResolver(paths),
            Registry = new RegistryKeyResolver(userSidOverride: session.Machine.UserSid),
            Logger = _logger,
            DropOutOfScope = _options.DropOutOfScope,
        };

        _store.SaveSessionInfo(session);

        _ctx.Emit(new Observation
        {
            Timestamp = session.StartedAt,
            Category = EventCategory.Session,
            Action = EventAction.SessionStart,
            Target = session.Name,
            Source = EvidenceSource.Analyst,
            Status = EventStatus.Success,
        });

        // Baseline first: the inventory must describe the machine before our own
        // collectors and the subject have touched anything.
        if (_options.CaptureSnapshots)
        {
            _snapshots = new SnapshotEngine(_ctx);
            await _snapshots.CaptureAsync(SnapshotEngine.PhaseBefore, cancellationToken).ConfigureAwait(false);
            SeedRegistryBaseline(_ctx);
        }

        // The subject is created suspended before collectors start, so its PID is
        // known and can be scoped the moment the first event arrives.
        if (_options.Mode == SessionMode.LaunchTarget && !string.IsNullOrEmpty(_options.TargetPath))
        {
            _target = SuspendedProcess.Launch(
                _options.TargetPath,
                _options.TargetArguments,
                _options.WorkingDirectory ?? Path.GetDirectoryName(_options.TargetPath));

            if (_target is null)
                _ctx.ReportFault("launcher", $"could not start {_options.TargetPath}");
        }

        if (_collectors.Count == 0)
        {
            _collectors.Add(new KernelCollector(_options.Kernel));

            // A separate session: the kernel session accepts only kernel keywords, so
            // the user-mode name-resolution and HTTP providers cannot share it.
            if (_options.CollectNetworkMetadata)
                _collectors.Add(new NetworkCollector(_options.Network));

            // Winsock, which is the only place a conversation that never leaves the
            // machine is visible at all. The packet monitor watches network adapters and
            // loopback traffic crosses none, so without this a program talking to its own
            // local helper appears as a connection to 127.0.0.1 carrying zero bytes.
            if (_options.CollectLocalSockets)
            {
                _collectors.Add(new Network.WinsockCollector(new Network.WinsockCollectorOptions
                {
                    IncludeLoopback = true,

                    // The kernel network provider already reports external connections
                    // with the same attribution; recording both would count every one
                    // of them twice.
                    IncludeExternal = false,
                }));
            }

            // Off by default: a full-payload capture on a busy machine reaches
            // hundreds of megabytes in minutes, and most sessions do not need the
            // bytes on the wire to answer their question.
            if (_options.CapturePackets)
                _collectors.Add(new CaYaTrace.Collectors.Network.PktmonCollector(_options.Pktmon));

            // Off by default: it needs a driver this tool does not install, and it records
            // the whole machine's local conversations rather than only the subject's.
            if (_options.CaptureLoopback)
                _collectors.Add(new CaYaTrace.Collectors.Network.LoopbackCollector(_options.Loopback));

            if (_options.InterceptionConsent is { } consent)
                _collectors.Add(new Proxy.ProxyCollector(consent, _options.ProxyOptions));
        }

        foreach (ICollector collector in _collectors)
        {
            try
            {
                await collector.StartAsync(_ctx, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _ctx.ReportFault(collector.Name, "start failed", ex);
            }
        }

        // Give the kernel session a moment to install its providers before the subject
        // begins executing; resuming immediately races the first events.
        await Task.Delay(250, cancellationToken).ConfigureAwait(false);

        if (_target is not null)
        {
            RegisterTargetProcess(_target);
            _target.Resume();
        }
        else if (_options.Mode == SessionMode.AttachExisting && _options.AttachPid != 0)
        {
            AttachToExisting(_options.AttachPid);
        }

        _store.SaveSessionInfo(session);
        return session;
    }

    /// <summary>
    /// Feeds baseline registry values into the value-capture cache.
    /// </summary>
    /// <remarks>
    /// Without this, the first write to any value has no recorded predecessor, so an
    /// installer's registry activity reads as a list of establishments rather than
    /// the transitions an analyst wants ("Start changed from 3 to 2"). The autorun,
    /// persistence, and service snapshots already hold the current data for the keys
    /// where that distinction carries weight, so replaying them into the cache costs
    /// nothing beyond a JSON parse per row.
    /// </remarks>
    private static void SeedRegistryBaseline(CollectorContext ctx)
    {
        foreach (string kind in new[] { "autorun", "persistence", "service" })
        {
            Dictionary<string, string> rows = ctx.Store.ReadSnapshot(SnapshotEngine.PhaseBefore, kind, ctx.OriginId);

            foreach ((string identity, string payload) in rows)
            {
                // Identities are stored as "<key>::<value>"; anything without a value
                // component is a key-level row with no data to seed.
                (string keyPath, string? valueName) = Core.Naming.RegistryPath.SplitValue(identity);
                if (valueName is null) continue;

                // The autorun provider tags the 32-bit view in the identity so both
                // registry views stay distinguishable; the suffix is not part of the name.
                int viewTag = valueName.IndexOf(" (32-bit view)", StringComparison.Ordinal);
                if (viewTag >= 0) valueName = valueName[..viewTag];

                string? data = ExtractSeedValue(payload);
                if (data is not null) ctx.RegistryValues.Seed(keyPath, valueName, data);
            }
        }

        ctx.Logger.LogInformation("seeded {Count} registry values from the baseline snapshot",
            ctx.RegistryValues.Seeded);
    }

    private static string? ExtractSeedValue(string payload)
    {
        try
        {
            using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(payload);
            foreach (string field in new[] { "Command", "Value", "ImagePath", "Debugger" })
            {
                if (doc.RootElement.TryGetProperty(field, out System.Text.Json.JsonElement element)
                    && element.ValueKind == System.Text.Json.JsonValueKind.String)
                {
                    return element.GetString();
                }
            }
        }
        catch (System.Text.Json.JsonException)
        {
            // A malformed snapshot row is not worth failing session start over.
        }
        return null;
    }

    private void RegisterTargetProcess(SuspendedProcess target)
    {
        if (_ctx is null || Session is null) return;

        // A suspended process has not yet produced a kernel start event, so seed a
        // placeholder keyed on PID alone. Deliberately *without* a creation time:
        // stamping DateTimeOffset.UtcNow here would never match the timestamp the
        // kernel later reports, the two records would fail to unify, and the scope
        // flag would end up on this placeholder while every real event attached to
        // the kernel-keyed node — emptying the tree without any error.
        var node = new ProcessNode
        {
            Key = new ProcessKey(target.Pid, 0, 0),
            ImagePath = _ctx.Paths.Normalize(_options.TargetPath),
            CommandLine = _options.TargetArguments,
            StartTime = DateTimeOffset.UtcNow,
            InScope = true,
            ScopeReason = "root",
            OriginId = _ctx.OriginId,
        };

        ProcessNode stored = _ctx.Processes.AddOrUpdate(node);
        _ctx.Processes.MarkScope(stored.Key);
        Session.RootProcess = stored.Key;
        Session.TargetSha256 = null;
    }

    private void AttachToExisting(uint pid)
    {
        if (_ctx is null || Session is null) return;

        try
        {
            using Process process = Process.GetProcessById((int)pid);
            var node = new ProcessNode
            {
                Key = ProcessKey.FromCreateTime(pid, process.StartTime),
                ImagePath = _ctx.Paths.Normalize(SafeMainModule(process)),
                StartTime = process.StartTime,
                InScope = true,
                ScopeReason = "root",
                PreExisting = true,
                OriginId = _ctx.OriginId,
            };
            ProcessNode stored = _ctx.Processes.AddOrUpdate(node);
            _ctx.Processes.MarkScope(stored.Key);
            Session.RootProcess = stored.Key;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            _ctx.ReportFault("attach", $"process {pid} is not running");
        }
    }

    private static string SafeMainModule(Process process)
    {
        try { return process.MainModule?.FileName ?? string.Empty; }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Stops collection and finalizes the session: after-snapshot, diff, attribution,
    /// and a durable write of the correlation tables.
    /// </summary>
    public async Task<SessionInfo> StopAsync(CancellationToken cancellationToken = default)
    {
        if (_stopped && Session is not null) return Session;
        _stopped = true;

        if (_ctx is null || _store is null || _sink is null || Session is null)
            throw new InvalidOperationException("session was never started");

        foreach (ICollector collector in _collectors)
        {
            try { await collector.StopAsync(cancellationToken).ConfigureAwait(false); }
            catch (Exception ex) { _ctx.ReportFault(collector.Name, "stop failed", ex); }
        }

        Session.StoppedAt = DateTimeOffset.UtcNow;

        _ctx.Emit(new Observation
        {
            Timestamp = Session.StoppedAt.Value,
            Category = EventCategory.Session,
            Action = EventAction.SessionStop,
            Target = Session.Name,
            Source = EvidenceSource.Analyst,
            Status = EventStatus.Success,
        });

        await _sink.FlushAsync(cancellationToken).ConfigureAwait(false);

        // The root's identity may have been upgraded from a PID-only placeholder to
        // the kernel's start key while collection ran, so re-read it rather than
        // persisting the key we guessed at launch.
        ProcessNode? root = _ctx.Processes.Snapshot()
            .FirstOrDefault(static p => p.ScopeReason == "root");
        if (root is not null) Session.RootProcess = root.Key;

        // Processes and flows are written after collection so the stored rows reflect
        // every late-arriving fact — exit codes, hashes, resolved hostnames.
        _store.UpsertProcesses(_ctx.Processes.Snapshot());
        _store.UpsertFlows(_ctx.Flows.Snapshot());

        if (_snapshots is not null)
        {
            await _snapshots.CaptureAsync(SnapshotEngine.PhaseAfter, cancellationToken).ConfigureAwait(false);
            int changes = _snapshots.Diff();
            await _sink.FlushAsync(cancellationToken).ConfigureAwait(false);
            int attributed = _snapshots.AttributeFromLiveEvents();
            await _sink.FlushAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("snapshot diff produced {Changes} changes, {Attributed} attributed", changes, attributed);
        }

        _ctx.RefreshQuality();
        _store.SaveSessionInfo(Session);
        _store.Checkpoint();

        return Session;
    }

    private string BuildDefaultName()
        => _options.TargetPath is { Length: > 0 } path
            ? Path.GetFileName(path)
            : _options.Mode.ToString();

    private static bool IsElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_stopped && Session is not null)
        {
            try { await StopAsync(CancellationToken.None).ConfigureAwait(false); }
            catch (Exception) { /* disposal must not throw */ }
        }

        foreach (ICollector collector in _collectors)
        {
            try { await collector.DisposeAsync().ConfigureAwait(false); }
            catch (Exception) { /* ditto */ }
        }

        _target?.Dispose();
        if (_sink is not null) await _sink.DisposeAsync().ConfigureAwait(false);
        _store?.Dispose();
    }
}
