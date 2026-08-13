using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using CaYaTrace.Core.Model;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace CaYaTrace.Collectors.Network;

public sealed class WinsockCollectorOptions
{
    /// <summary>
    /// Report conversations that never left the machine.
    /// </summary>
    /// <remarks>
    /// The reason this collector exists. Everything else can be seen elsewhere.
    /// </remarks>
    public bool IncludeLoopback { get; init; } = true;

    /// <summary>
    /// Report conversations that did leave the machine.
    /// </summary>
    /// <remarks>
    /// Off by default because the kernel network provider already covers them with the
    /// same attribution, and recording both means every external connection is counted
    /// twice.
    /// </remarks>
    public bool IncludeExternal { get; init; }

    /// <summary>Bound on how many sockets are tracked at once.</summary>
    public int MaxSockets { get; init; } = 200_000;

    public static WinsockCollectorOptions Default { get; } = new();
}

/// <summary>
/// Watches Winsock itself, which is the only place a conversation that never leaves the
/// machine can be seen.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is separate from packet capture.</b> The Windows packet monitor observes
/// network adapters. Two processes on one machine talking over <c>127.0.0.1</c> cross no
/// adapter, so that traffic is invisible to it — measured: a subject that opened four
/// loopback connections showed four rows of <c>0 B / 0 B</c> and nothing else. The Ancillary
/// Function Driver sits above the network stack and every socket operation goes through
/// it, loopback included.
/// </para>
/// <para>
/// <b>What it can and cannot say.</b> It reports which process, which socket, which local
/// and remote address, how many bytes moved in each direction, and when. It does
/// <em>not</em> report the bytes: the provider's <c>Buffer</c> field is a pointer into the
/// calling process's address space, not a copy of the data. Following that pointer would
/// mean reading another process's memory while it runs — racy, invasive, and the kind of
/// thing this tool does not do. So a loopback conversation is reported completely except
/// for its contents, and the report says so rather than leaving a reader to assume
/// otherwise.
/// </para>
/// <para>
/// <b>Pairing.</b> Both ends of a loopback conversation are separate sockets in separate
/// processes, and both are seen here. Matching one end's remote endpoint against the
/// other end's local endpoint names the program on the other side — which is the actual
/// question when a program is talking to its own helper.
/// </para>
/// </remarks>
public sealed class WinsockCollector : ICollector
{
    private static readonly Guid Provider = new("E53C6823-7BB8-44BB-90DC-3F86090D48A6");

    private readonly WinsockCollectorOptions _options;
    private readonly string _sessionName;

    private TraceEventSession? _session;
    private Task? _processing;
    private CollectorContext? _ctx;
    private volatile bool _stopping;

    private readonly Dictionary<ulong, Socket> _sockets = new();
    private readonly List<Socket> _closed = new();

    /// <summary>Which process bound each port, so a connecting socket can name its peer.</summary>
    private readonly Dictionary<int, uint> _boundPorts = new();
    private long _dropped;
    private long _events;

    public WinsockCollector(WinsockCollectorOptions? options = null, string? sessionName = null)
    {
        _options = options ?? WinsockCollectorOptions.Default;
        _sessionName = sessionName ?? $"CaYaTrace-Winsock-{Environment.ProcessId}";
    }

    public string Name => "winsock-afd";

    public bool RequiresElevation => true;

    /// <summary>One socket, as Winsock sees it.</summary>
    private sealed class Socket
    {
        public ulong Endpoint;
        public uint Pid;
        public IPEndPoint? Local;
        public IPEndPoint? Remote;
        public TransportProtocol Protocol = TransportProtocol.Tcp;
        public long BytesSent;
        public long BytesReceived;
        public long Sends;
        public long Receives;
        public DateTimeOffset First = DateTimeOffset.MaxValue;
        public DateTimeOffset Last;
        public bool Accepted;
    }

    public Task<bool> StartAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        _ctx = context;

        if (!TraceEventSession.IsElevated().GetValueOrDefault())
        {
            context.ReportSkipped(Name, "watching Winsock requires an elevated process");
            return Task.FromResult(false);
        }

        try
        {
            // Ports that were already being listened on when recording started. Without
            // this, a program talking to a service that was up before the session shows
            // its conversation with no peer named — which is most of them, because most
            // local services are started at boot and the interesting subject is the thing
            // that connects to them.
            SeedExistingListeners();

            _session = new TraceEventSession(_sessionName) { StopOnDispose = true };
            _session.EnableProvider(Provider, TraceEventLevel.Verbose, ulong.MaxValue);

            Subscribe(context);

            _processing = Task.Run(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) when (!_stopping)
                {
                    context.ReportFault(Name, "winsock trace processing stopped unexpectedly", ex);
                }
            }, CancellationToken.None);

            context.Session.EnabledCollectors.Add(Name);
            return Task.FromResult(true);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            context.ReportSkipped(Name, $"could not watch Winsock: {ex.Message}");
            return Task.FromResult(false);
        }
        catch (Exception ex)
        {
            context.ReportFault(Name, "could not start the winsock session", ex);
            return Task.FromResult(false);
        }
    }

    private void Subscribe(CollectorContext context)
    {
        if (_session is null) return;

        _session.Source.Dynamic.All += data =>
        {
            _events++;
            string name = data.EventName ?? string.Empty;


            // Most operations are reported twice, on entry and on exit, and which one is
            // useful depends on the field being read.
            //
            //   * Addresses arrive on the *entry* event — the connect that names where it
            //     is going is the one going in. Filtering entries out cost every address
            //     in the session, and with no address there is no conversation to report.
            //
            //   * Byte counts must come from the *exit* event. On entry a receive reports
            //     the size of the buffer offered (17,408 bytes for a stock socket); on
            //     exit it reports what was actually read. Counting both would inflate
            //     every conversation by the capacity of its buffers.
            int phase = ReadPhase(data);

            ulong endpoint = Read(data, "Endpoint");
            if (endpoint == 0) return;

            if (name.StartsWith("AfdCreate", StringComparison.Ordinal))
            {
                Track(endpoint, (uint)data.ProcessID, data.TimeStamp, socket =>
                {
                    if (data.PayloadByName("SocketType") is int type)
                        socket.Protocol = type == 2 ? TransportProtocol.Udp : TransportProtocol.Tcp;
                });
                return;
            }

            if (name.StartsWith("AfdBindWithAddress", StringComparison.Ordinal))
            {
                IPEndPoint? bound = ReadAddress(data);
                Track(endpoint, (uint)data.ProcessID, data.TimeStamp, socket => socket.Local ??= bound);

                // Remembered separately, and this is what makes pairing work. A program
                // connecting out to 127.0.0.1:5600 never binds a local port explicitly,
                // so its socket has no local address to match against — but the process
                // that bound 5600 is the one it is talking to, and that is the question.
                if (bound is { Port: > 0 }) _boundPorts[bound.Port] = (uint)data.ProcessID;
                return;
            }

            if (name.StartsWith("AfdConnectWithAddress", StringComparison.Ordinal)
                || name.StartsWith("AfdConnectExWithAddress", StringComparison.Ordinal))
            {
                Track(endpoint, (uint)data.ProcessID, data.TimeStamp,
                    socket => socket.Remote ??= ReadAddress(data));
                return;
            }

            if (name.StartsWith("AfdAcceptWithAddress", StringComparison.Ordinal))
            {
                // The accepted connection is a *new* endpoint; the address belongs to
                // whoever connected in.
                ulong accepted = Read(data, "AcceptEndpoint");
                Track(accepted != 0 ? accepted : endpoint, (uint)data.ProcessID, data.TimeStamp, socket =>
                {
                    socket.Remote ??= ReadAddress(data);
                    socket.Accepted = true;
                });
                return;
            }

            // Sends nest, and receives do not. Measured, on a probe that sent exactly three
            // buffers of exactly ten bytes:
            //
            //     enter loc=3047  len=10     the send API is entered
            //     enter loc=3056  len=10     an inner path is entered
            //     exit  loc=3073  len=10     the inner path returns
            //     exit  loc=3051  len=10     the send API returns
            //
            // Counting every exit therefore reported six sends of sixty bytes for three
            // sends of thirty — every conversation in the session doubled, in the two
            // numbers an analyst reads first. A receive is a single pair (capacity on
            // enter, actual on exit) and is counted on its exit, unchanged.
            //
            // Sends are counted on the outermost *enter* instead, which for a send carries
            // the same length as its exit. "Outermost" needs no knowledge of those location
            // ids: it is simply an enter arriving while no send is open on this socket and
            // thread, and any exit closes it again. The outer pair is exactly matched in
            // the trace even where the inner one is not, so this cannot drift.
            if (name.StartsWith("AfdSend", StringComparison.Ordinal))
            {
                var site = (endpoint, data.ThreadID);

                if (phase != PhaseExit)
                {
                    if (!_openSends.Add(site)) return;

                    long bytes = ReadLength(data);
                    Track(endpoint, (uint)data.ProcessID, data.TimeStamp, socket =>
                    {
                        socket.BytesSent += bytes;
                        if (bytes > 0) socket.Sends++;
                        socket.Remote ??= ReadAddress(data);
                    });
                    return;
                }

                _openSends.Remove(site);

                // An exit still carries the peer address, which is worth having on a socket
                // that never produced one on the way in.
                Track(endpoint, (uint)data.ProcessID, data.TimeStamp,
                    socket => socket.Remote ??= ReadAddress(data));
                return;
            }

            if (name.StartsWith("AfdReceive", StringComparison.Ordinal))
            {
                long bytes = phase == PhaseExit ? ReadLength(data) : 0;
                Track(endpoint, (uint)data.ProcessID, data.TimeStamp, socket =>
                {
                    socket.BytesReceived += bytes;
                    if (bytes > 0) socket.Receives++;
                    socket.Remote ??= ReadAddress(data);
                });
                return;
            }

            // The kernel indicating data has arrived, which is the only report for a
            // socket whose owner reads it in a way the enter/exit pair does not cover.
            if (name.StartsWith("AfdDataIndication", StringComparison.Ordinal))
            {
                Track(endpoint, (uint)data.ProcessID, data.TimeStamp,
                    socket => socket.Remote ??= ReadAddress(data));
                return;
            }

            if (name.StartsWith("AfdClose", StringComparison.Ordinal)
                || name.StartsWith("AfdAbort", StringComparison.Ordinal))
            {
                if (_sockets.Remove(endpoint, out Socket? socket))
                {
                    socket.Last = data.TimeStamp;
                    _closed.Add(socket);
                }
            }
        };
    }

    /// <summary>
    /// Finds or creates the record for a socket and applies an update to it.
    /// </summary>
    /// <remarks>
    /// Single-threaded: ETW delivers on one processing thread per session, and everything
    /// that reads these records runs after that thread has finished.
    /// </remarks>
    private void Track(ulong endpoint, uint pid, DateTimeOffset when, Action<Socket> update)
    {
        if (!_sockets.TryGetValue(endpoint, out Socket? socket))
        {
            if (_sockets.Count >= _options.MaxSockets) { _dropped++; return; }

            socket = new Socket { Endpoint = endpoint, Pid = pid };
            _sockets[endpoint] = socket;
        }

        if (socket.Pid == 0) socket.Pid = pid;
        if (when < socket.First) socket.First = when;
        if (when > socket.Last) socket.Last = when;

        update(socket);
    }

    /// <summary>
    /// Records which process owns each listening port, from the live connection table.
    /// </summary>
    /// <remarks>
    /// Read once at start rather than watched, because a listener that already exists
    /// emits no bind event to observe. Failure here is not worth reporting: the peer is
    /// simply left unnamed, which is what would have happened anyway.
    /// </remarks>
    private void SeedExistingListeners()
    {
        const int AfInet = 2;
        const int TcpTableOwnerPidListener = 3;

        int size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidListener, 0);
        if (size <= 0) return;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidListener, 0) != 0) return;

            int rows = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<TcpRowOwnerPid>();

            for (int i = 0; i < rows; i++)
            {
                var row = Marshal.PtrToStructure<TcpRowOwnerPid>(buffer + 4 + (i * rowSize));

                // The port is stored in network order in the low half of a DWORD.
                int port = (int)(((row.LocalPort & 0xFF) << 8) | ((row.LocalPort >> 8) & 0xFF));
                if (port > 0) _boundPorts.TryAdd(port, row.OwningPid);
            }
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr table, ref int size, bool order, int addressFamily, int tableClass, int reserved);

    private const int PhaseEnter = 0;
    private const int PhaseExit = 1;

    /// <summary>
    /// Sockets and threads with a send already in progress, so the nested report of the
    /// same send is not counted a second time.
    /// </summary>
    /// <remarks>
    /// Keyed on the thread as well as the socket because a socket written to from two
    /// threads has two independent sends in flight, and one of them closing must not make
    /// the other's inner report look like a new send.
    /// </remarks>
    private readonly HashSet<(ulong Endpoint, int Thread)> _openSends = new();

    /// <summary>Whether this report is the operation going in or coming back.</summary>
    /// <remarks>
    /// The field is a small enumeration and the provider's manifest types it differently
    /// across builds, so it is read loosely rather than pattern-matched on one type —
    /// getting this wrong silently drops every event, which is exactly what happened.
    /// </remarks>
    private static int ReadPhase(TraceEvent data) => data.PayloadByName("EnterExit") switch
    {
        int v => v,
        byte v => v,
        uint v => (int)v,
        short v => v,
        ushort v => v,
        Enum e => Convert.ToInt32(e, System.Globalization.CultureInfo.InvariantCulture),
        _ => PhaseExit,
    };

    private static ulong Read(TraceEvent data, string field)
        => data.PayloadByName(field) switch
        {
            ulong v => v,
            long v => (ulong)v,
            int v => (ulong)v,
            uint v => v,
            _ => 0,
        };

    private static long ReadLength(TraceEvent data)
        => data.PayloadByName("BufferLength") switch
        {
            uint v => v,
            int v => v,
            ulong v => (long)v,
            long v => v,
            _ => 0,
        };

    /// <summary>
    /// Decodes the 16-byte socket address the provider carries.
    /// </summary>
    /// <remarks>
    /// A <c>SOCKADDR_IN</c>: family, then the port in network order, then the address.
    /// Bounds-checked because this is a payload field and a short one would otherwise
    /// throw inside a trace callback, which stops the session.
    /// </remarks>
    private static IPEndPoint? ReadAddress(TraceEvent data)
    {
        if (data.PayloadByName("Address") is not byte[] raw || raw.Length < 8) return null;

        ushort family = BinaryPrimitives.ReadUInt16LittleEndian(raw);
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(raw.AsSpan(2, 2));

        try
        {
            // AF_INET = 2, AF_INET6 = 23.
            if (family == 2) return new IPEndPoint(new IPAddress(raw.AsSpan(4, 4).ToArray()), port);
            if (family == 23 && raw.Length >= 24)
                return new IPEndPoint(new IPAddress(raw.AsSpan(8, 16).ToArray()), port);
        }
        catch (ArgumentException)
        {
        }

        return null;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _stopping = true;

        try { _session?.Source.StopProcessing(); }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException) { }

        if (_processing is not null)
        {
            try { await _processing.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false); }
            catch (Exception ex) when (ex is TimeoutException or OperationCanceledException) { }
        }

        Emit();
    }

    /// <summary>
    /// Turns the sockets into observations, pairing the two ends of local conversations.
    /// </summary>
    private void Emit()
    {
        if (_ctx is null) return;

        List<Socket> all = _closed.Concat(_sockets.Values).ToList();

        // Both ends of a loopback conversation are here. Indexing by local endpoint lets
        // one end name the other, which is the whole point: "it connected to
        // 127.0.0.1:53309" becomes "it connected to its own helper".
        var byLocal = new Dictionary<string, Socket>(StringComparer.Ordinal);
        foreach (Socket socket in all)
            if (socket.Local is not null) byLocal.TryAdd(socket.Local.ToString(), socket);

        int emitted = 0;
        int loopback = 0;

        foreach (Socket socket in all)
        {
            if (socket.Remote is null) continue;
            if (socket.BytesSent == 0 && socket.BytesReceived == 0 && !socket.Accepted) continue;

            bool isLoopback = IPAddress.IsLoopback(socket.Remote.Address);
            if (isLoopback && !_options.IncludeLoopback) continue;
            if (!isLoopback && !_options.IncludeExternal) continue;

            ProcessKey actor = _ctx.Processes.Resolve(socket.Pid, socket.First);

            string? peer = null;
            if (isLoopback)
            {
                uint peerPid = 0;

                // The socket at the other end, when both were seen with addresses.
                if (byLocal.TryGetValue(socket.Remote.ToString(), out Socket? other) && other != socket)
                    peerPid = other.Pid;

                // Otherwise, whoever bound the port being talked to. This is the usual
                // case: the connecting side has no local address of its own to match on.
                if (peerPid == 0) _boundPorts.TryGetValue(socket.Remote.Port, out peerPid);

                if (peerPid != 0 && peerPid != socket.Pid)
                {
                    ProcessNode? node = _ctx.Processes.Get(_ctx.Processes.Resolve(peerPid, socket.First));
                    peer = node is null ? $"pid {peerPid}" : $"{node.ImageName} ({node.Pid})";
                }
                else if (peerPid == socket.Pid)
                {
                    // Talking to itself — two sockets in one process, which is worth
                    // saying rather than leaving blank.
                    ProcessNode? node = _ctx.Processes.Get(_ctx.Processes.Resolve(peerPid, socket.First));
                    peer = node is null ? $"pid {peerPid}" : $"{node.ImageName} ({node.Pid}), itself";
                }
            }

            _ctx.Emit(new Observation
            {
                Timestamp = socket.First == DateTimeOffset.MaxValue ? socket.Last : socket.First,
                Category = EventCategory.Network,
                Action = socket.Accepted ? EventAction.Accept : EventAction.Connect,
                Actor = actor,
                Target = socket.Remote.ToString(),
                Target2 = peer,
                Bytes = socket.BytesSent + socket.BytesReceived,
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
                Status = EventStatus.Success,

                // Said explicitly, because a conversation reported with byte counts and
                // no contents would otherwise read as one that carried nothing.
                Details = System.Text.Json.JsonSerializer.Serialize(new
                {
                    scope = isLoopback ? "Loopback" : "Internet",
                    via = "winsock",
                    localPort = socket.Local?.Port ?? 0,
                    peerPort = socket.Remote.Port,
                    protocol = socket.Protocol.ToString(),
                    inbound = socket.Accepted,
                    sentBytes = socket.BytesSent,
                    receivedBytes = socket.BytesReceived,
                    sends = socket.Sends,
                    receives = socket.Receives,
                    peerProcess = peer,
                    contentsUnavailable = isLoopback,
                }),
            });

            emitted++;
            if (isLoopback) loopback++;
        }

        _ctx.Store.LogQuality(Name, "info",
            $"{emitted:N0} socket conversations recorded, {loopback:N0} of them between processes on this machine. "
            + "Winsock reports who talked to whom and how much, but not the bytes: the provider carries a pointer "
            + "into the sending process rather than a copy of the data.");

        // Counted separately so a session that reports nothing can be told apart from a
        // session that saw nothing — the two look identical from the outside and mean
        // completely different things.
        _ctx.Store.LogQuality(Name, "info",
            $"tracked {all.Count:N0} sockets, {all.Count(static s => s.Remote is not null):N0} with a peer address, "
            + $"{all.Count(static s => s.BytesSent + s.BytesReceived > 0):N0} that moved bytes, "
            + $"{_events:N0} winsock events seen");

        if (_dropped > 0)
        {
            _ctx.Store.LogQuality(Name, "warning",
                $"{_dropped:N0} sockets were not tracked because the table was full");
        }
    }

    public ValueTask DisposeAsync()
    {
        _stopping = true;
        _session?.Dispose();
        _session = null;
        return ValueTask.CompletedTask;
    }
}
