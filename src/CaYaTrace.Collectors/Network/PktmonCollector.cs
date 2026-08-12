using System.Diagnostics;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Collectors.Network;

public sealed class PktmonOptions
{
    /// <summary>
    /// Bytes retained per packet. Zero keeps the whole packet, which is what makes
    /// cleartext protocols readable afterwards; the stock 128 truncates most payloads.
    /// </summary>
    public int PacketSizeBytes { get; init; }

    /// <summary>
    /// Capture file cap in MB. Circular, so a long session overwrites its oldest
    /// packets rather than filling the disk — an unbounded capture on a busy machine
    /// reaches gigabytes in minutes.
    /// </summary>
    public int MaxFileSizeMB { get; init; } = 512;

    /// <summary>Convert the capture to pcapng on stop so it opens in Wireshark.</summary>
    public bool ConvertToPcapng { get; init; } = true;

    public static PktmonOptions Default { get; } = new();
}

/// <summary>
/// Captures packets using the packet monitor built into Windows.
/// </summary>
/// <remarks>
/// <para>
/// No Npcap, no WinPcap, no driver to install — which matters for a portable tool that
/// is meant to leave nothing behind. The capture is written as an ETL and converted to
/// pcapng on stop, so the result opens in Wireshark like any other capture.
/// </para>
/// <para>
/// What it adds beyond a packet file is correlation. Packets carry no process, which is
/// the standing gap in capture-based tooling; feeding the recovered 5-tuples through the
/// flow table attaches the process attribution the kernel provider already established.
/// The bytes and the responsible program end up on the same record.
/// </para>
/// <para>
/// The tool is driven through its command line rather than its API. That is a
/// deliberate trade: the surface is stable and documented, and the alternative is a
/// substantial block of undocumented interop for a component whose ETL schema changes
/// between Windows releases.
/// </para>
/// </remarks>
public sealed class PktmonCollector : ICollector
{
    private readonly PktmonOptions _options;
    private CollectorContext? _ctx;
    private string? _etlPath;
    private string? _pcapngPath;
    private bool _started;

    public PktmonCollector(PktmonOptions? options = null)
        => _options = options ?? PktmonOptions.Default;

    public string Name => "pktmon";

    public bool RequiresElevation => true;

    /// <summary>Where the converted capture ended up, once the session has stopped.</summary>
    public string? CapturePath => _pcapngPath ?? _etlPath;

    public async Task<bool> StartAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        _ctx = context;

        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
        {
            context.ReportSkipped(Name, "packet monitor requires Windows 10 1809 or later");
            return false;
        }

        string directory = Path.Combine(context.SessionDirectory, "network");
        Directory.CreateDirectory(directory);
        _etlPath = Path.Combine(directory, "capture.etl");

        // A capture left running by a previous crash would otherwise refuse to start,
        // and would keep writing to a file nobody is reading.
        await RunAsync("stop", cancellationToken).ConfigureAwait(false);

        (int exitCode, string output) = await RunAsync(
            $"start --capture --pkt-size {_options.PacketSizeBytes} " +
            $"--file-name \"{_etlPath}\" --file-size {_options.MaxFileSizeMB} --log-mode circular",
            cancellationToken).ConfigureAwait(false);

        if (exitCode != 0)
        {
            context.ReportSkipped(Name, $"could not start packet capture: {Summarize(output)}");
            return false;
        }

        _started = true;
        context.Session.EnabledCollectors.Add(Name);
        return true;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (!_started || _ctx is null || _etlPath is null) return;
        _started = false;

        (int exitCode, string output) = await RunAsync("stop", cancellationToken).ConfigureAwait(false);
        if (exitCode != 0)
            _ctx.ReportFault(Name, $"packet capture did not stop cleanly: {Summarize(output)}");

        if (!File.Exists(_etlPath))
        {
            _ctx.ReportFault(Name, "no capture file was produced");
            return;
        }

        long etlBytes = new FileInfo(_etlPath).Length;

        if (_options.ConvertToPcapng)
        {
            _pcapngPath = Path.ChangeExtension(_etlPath, ".pcapng");
            (int convertExit, string convertOutput) = await RunAsync(
                $"etl2pcap \"{_etlPath}\" --out \"{_pcapngPath}\"", cancellationToken).ConfigureAwait(false);

            if (convertExit != 0 || !File.Exists(_pcapngPath))
            {
                _ctx.Store.LogQuality(Name, "warning",
                    $"the capture could not be converted to pcapng ({Summarize(convertOutput)}); " +
                    "the raw ETL is still in the session's network folder");
                _pcapngPath = null;
            }
        }

        _ctx.Emit(new Observation
        {
            Timestamp = DateTimeOffset.UtcNow,
            Category = EventCategory.Session,
            Action = EventAction.SnapshotTaken,
            Target = _pcapngPath ?? _etlPath,
            Target2 = "packet capture",
            Bytes = etlBytes,
            Source = EvidenceSource.PacketCapture,
            Status = EventStatus.Success,
        });

        if (_pcapngPath is not null)
            CorrelateCapture(_ctx, _pcapngPath);
    }

    /// <summary>
    /// Joins captured conversations to the flow table.
    /// </summary>
    /// <remarks>
    /// Flows the kernel provider already knows gain their true wire byte counts;
    /// conversations it missed appear with whatever attribution the 5-tuple can supply,
    /// and stay unattributed when it can supply none. Guessing an owner here would
    /// undo the point of tracking attribution confidence at all.
    /// </remarks>
    private void CorrelateCapture(CollectorContext ctx, string pcapngPath)
    {
        IReadOnlyList<CapturedFlow> captured;
        try
        {
            captured = PcapngReader.ReadFlows(pcapngPath);
        }
        catch (Exception ex) when (ex is IOException or EndOfStreamException or InvalidDataException)
        {
            ctx.Store.LogQuality(Name, "warning", $"the capture could not be read back: {ex.Message}");
            return;
        }

        int attributed = 0;

        foreach (CapturedFlow flow in captured)
        {
            Core.Correlation.FlowAttribution owner = ctx.Flows.Attribute(flow.Key, flow.Last);

            ctx.Flows.NoteBytes(flow.Key, flow.Last, sent: 0, received: 0,
                packetsSent: flow.Packets, packetsReceived: 0);

            NetworkFlow tracked = ctx.Flows.GetOrCreate(flow.Key, flow.First);
            if (tracked.BytesSent + tracked.BytesReceived < flow.Bytes)
            {
                // The wire total is authoritative over the kernel provider's, which
                // counts payload handed to the stack rather than bytes on the link.
                tracked.BytesSent = flow.Bytes;
            }

            if (owner.Owner != ProcessKey.None) attributed++;
        }

        ctx.Store.LogQuality(Name, "info",
            $"{captured.Count:N0} conversations recovered from the capture, {attributed:N0} attributed to a process");
    }

    private static async Task<(int ExitCode, string Output)> RunAsync(string arguments, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo("pktmon.exe", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        try
        {
            using Process? process = Process.Start(startInfo);
            if (process is null) return (-1, "could not start pktmon.exe");

            string output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            string error = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);

            // Bounded: conversion of a large capture can take a while, but a wedged
            // child process must not hold session shutdown open indefinitely.
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMinutes(5));
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);

            return (process.ExitCode, string.IsNullOrWhiteSpace(output) ? error : output);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException
                                       or OperationCanceledException)
        {
            return (-1, ex.Message);
        }
    }

    private static string Summarize(string output)
    {
        string flat = output.ReplaceLineEndings(" ").Trim();
        return flat.Length <= 200 ? flat : flat[..200] + "…";
    }

    public async ValueTask DisposeAsync()
    {
        // A capture surviving the process would keep writing to a file nobody owns.
        if (_started) await StopAsync(CancellationToken.None).ConfigureAwait(false);
    }
}
