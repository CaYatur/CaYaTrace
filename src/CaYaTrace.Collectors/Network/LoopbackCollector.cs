using CaYaTrace.Core.Model;

namespace CaYaTrace.Collectors.Network;

public sealed class LoopbackOptions
{
    /// <summary>
    /// Bytes kept per packet. The default keeps whole packets, which is the entire point:
    /// a truncated capture of a local conversation is a byte count again, and byte counts
    /// were what this feature exists to replace.
    /// </summary>
    public int SnapLengthBytes { get; init; } = 262144;

    /// <summary>
    /// Where the capture stops. Loopback is not a trickle — a local database connection or
    /// a development server moves tens of megabytes a second across it — so a session left
    /// running on a busy machine would otherwise fill the disk.
    /// </summary>
    public int MaxFileSizeMB { get; init; } = 512;

    /// <summary>
    /// Leave out the tool's own loopback traffic.
    /// </summary>
    /// <remarks>
    /// On, because the workbench renders through an embedded browser and the interception
    /// proxy has a loopback leg, so a capture of this machine records CaYaTrace talking to
    /// CaYaTrace. It can be turned off for the one case where that matters: working out
    /// why the tool itself is behaving oddly.
    /// </remarks>
    public bool ExcludeOwnTraffic { get; init; } = true;

    public static LoopbackOptions Default { get; } = new();
}

/// <summary>
/// Records what programs on this machine say to each other.
/// </summary>
/// <remarks>
/// <para>
/// <b>The gap.</b> An established TCP connection over loopback is handled by a fastpath
/// inside the stack and never becomes a packet on any adapter. Measured twice with the
/// packet monitor Windows ships, told to capture every component: 5,276 events, not one of
/// them loopback. Everything else this tool has could therefore say that a program had
/// opened a connection to 127.0.0.1 and moved 4,096 bytes, and nothing at all about what
/// those bytes were — which is the worst possible place to be blind, because a program
/// coordinating with a local helper it installed is precisely the arrangement worth reading.
/// </para>
/// <para>
/// <b>What it uses.</b> Npcap's loopback adapter, which works through the Windows Filtering
/// Platform and so sits above the decision that makes loopback a fastpath. That is the same
/// kernel-callout mechanism this tool would otherwise have had to ship a driver of its own
/// to reach — except already written, signed, maintained by somebody else, and installed by
/// the same package Wireshark uses.
/// </para>
/// <para>
/// <b>Off by default, and honest when unavailable.</b> It needs a driver this tool does not
/// install, and turning it on changes what a recording contains: system-wide local traffic
/// from every process on the machine, not only the subject's. When the driver is missing the
/// session says so in as many words, because a capture that quietly produces nothing is
/// indistinguishable from a program that never talked to anything — and an analyst reading
/// the second when the first is true draws the opposite conclusion from the right one.
/// </para>
/// </remarks>
public sealed class LoopbackCollector : ICollector
{
    private readonly LoopbackOptions _options;

    private CollectorContext? _ctx;
    private LoopbackCapture? _capture;
    private string? _path;

    public LoopbackCollector(LoopbackOptions? options = null)
        => _options = options ?? LoopbackOptions.Default;

    public string Name => "loopback";

    public bool RequiresElevation => true;

    /// <summary>Where the capture ended up, once the session has stopped.</summary>
    public string? CapturePath => _path;

    public Task<bool> StartAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        _ctx = context;

        if (!LoopbackCapture.IsAvailable(out string why))
        {
            context.ReportSkipped(Name, why);
            return Task.FromResult(false);
        }

        string directory = Path.Combine(context.SessionDirectory, "network");
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "loopback.pcapng");

        _capture = new LoopbackCapture(_path, _options.SnapLengthBytes, _options.MaxFileSizeMB);

        if (!_capture.Start(out string error))
        {
            context.ReportSkipped(Name, error);
            _capture.Dispose();
            _capture = null;
            return Task.FromResult(false);
        }

        context.Session.EnabledCollectors.Add(Name);

        // Stated at the top of the session rather than left for the reader to work out.
        // Enabling this widens what was recorded, and a session file has to say so.
        context.Store.LogQuality(Name, "info",
            "loopback capture is on: local conversations between every process on this machine "
            + "are recorded with their contents, not only the subject's. " + why);

        return Task.FromResult(true);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (_capture is null || _ctx is null || _path is null) return Task.CompletedTask;

        // The driver hands packets over asynchronously, so a capture stopped the instant
        // the subject exits routinely loses the last of what it said.
        Thread.Sleep(500);

        long packets = _capture.PacketCount;
        long bytes = _capture.ByteCount;
        string? fault = _capture.Fault;
        bool capped = _capture.ReachedSizeLimit;

        _capture.Stop();
        _capture.Dispose();
        _capture = null;

        if (fault is { Length: > 0 })
            _ctx.Store.LogQuality(Name, capped ? "warning" : "error", fault);

        if (packets == 0)
        {
            // Said out loud. Nothing on this machine spoke over loopback during the
            // session is a real and unremarkable answer; a broken capture looks the same
            // from the outside, and the two must not be reported identically.
            _ctx.Store.LogQuality(Name, "info",
                "no loopback traffic was seen during this session — nothing on the machine "
                + "talked to anything else on it, or the conversation was already established "
                + "before recording started");
            return Task.CompletedTask;
        }

        _ctx.Emit(new Observation
        {
            Timestamp = DateTimeOffset.UtcNow,
            Category = EventCategory.Session,
            Action = EventAction.SnapshotTaken,
            Target = _path,
            Target2 = "loopback capture",
            Bytes = bytes,
            Source = EvidenceSource.PacketCapture,
            Status = EventStatus.Success,
        });

        CaptureCorrelator.Result result = CaptureCorrelator.Correlate(
            _ctx, Name, _path, EvidenceSource.PacketCapture, OwnPorts());

        _ctx.Store.LogQuality(Name, "info",
            $"{packets:N0} loopback packets ({bytes:N0} bytes) became {result.Conversations:N0} conversations, "
            + $"{result.WithContent:N0} with readable content, {result.Attributed:N0} attributed to a process"
            + (result.Skipped > 0 ? $"; {result.Skipped:N0} of this tool's own were left out" : string.Empty));

        // What this method cannot see, named rather than left as a silence. Two programs on
        // one machine also talk over Unix-domain sockets and named pipes, which are not IP
        // and cross no adapter real or virtual; and a local conversation inside TLS is
        // captured as the ciphertext it was. The sizes and the peers for those come from
        // the socket and file providers, and are in this session — the contents are not.
        _ctx.Store.LogQuality(Name, "info",
            "loopback capture covers TCP and UDP over 127.0.0.1 and ::1. Unix-domain sockets "
            + "and named pipes carry no IP and are recorded by the socket and file providers "
            + "as sizes without contents; a local conversation inside TLS is recorded as "
            + "ciphertext.");

        return Task.CompletedTask;
    }

    /// <summary>
    /// The loopback ports this process is holding, so its own chatter stays out.
    /// </summary>
    /// <remarks>
    /// Resolved at stop rather than at start: the embedded browser opens and closes local
    /// ports throughout a session, and the set that matters is the one that was in use.
    /// </remarks>
    private IReadOnlyCollection<ushort>? OwnPorts()
    {
        if (!_options.ExcludeOwnTraffic) return null;

        try
        {
            return LocalPortOwner.PortsOwnedBy((uint)Environment.ProcessId);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    public ValueTask DisposeAsync()
    {
        _capture?.Dispose();
        _capture = null;
        return ValueTask.CompletedTask;
    }
}
