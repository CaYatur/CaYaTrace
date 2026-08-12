using CaYaTrace.Collectors;
using CaYaTrace.Collectors.Etw;
using CaYaTrace.Core.Model;

namespace CaYaTrace.App.Cli;

/// <summary>Headless recording, for scripted and sandbox-automation use.</summary>
public static class TraceCommand
{
    public static int Run(CommandLine cmd)
    {
        string sessionRoot = cmd.Get("out") ?? Path.Combine(Environment.CurrentDirectory, "sessions");

        SessionMode mode =
            cmd.Flag("system-wide") ? SessionMode.SystemWide
            : cmd.Has("attach") ? SessionMode.AttachExisting
            : SessionMode.LaunchTarget;

        if (mode == SessionMode.LaunchTarget && !cmd.Has("target"))
            throw new CommandLineException("--target is required unless --system-wide or --attach is given");

        string? target = cmd.Get("target");
        if (target is not null)
        {
            target = Path.GetFullPath(target);
            if (!File.Exists(target))
                throw new CommandLineException($"target not found: {target}");
        }

        if (!Privilege.IsElevated())
        {
            Console.Error.WriteLine(
                "warning: not elevated — kernel tracing will be skipped and only " +
                "snapshot-based evidence will be collected.");
            Console.Error.WriteLine("         Re-run from an administrator prompt for full coverage.");
        }

        var options = new SessionOptions
        {
            Mode = mode,
            TargetPath = target,
            TargetArguments = cmd.Get("args"),
            AttachPid = (uint)cmd.Int("attach", 0),
            SessionRoot = sessionRoot,
            Name = cmd.Get("name"),
            CaptureSnapshots = !cmd.Flag("no-snapshots"),
            DropOutOfScope = cmd.Flag("scoped-only"),
            CapturePackets = cmd.Flag("packets"),

            // A callback, not a flag. --intercept-https alone is not consent; it only
            // makes the question get asked.
            InterceptionConsent = ResolveInterceptionConsent(cmd),
            Pktmon = new Collectors.Network.PktmonOptions
            {
                MaxFileSizeMB = cmd.Int("packet-cap-mb", 512),
            },
            Kernel = new KernelCollectorOptions
            {
                BufferSizeMB = cmd.Int("buffer-mb", 256),
                CollectReads = cmd.Flag("reads"),
            },
        };

        return RunAsync(options, cmd).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Decides how consent for HTTPS interception will be obtained, if at all.
    /// </summary>
    /// <remarks>
    /// Two paths, both affirmative. Interactively the operator types a word after
    /// reading what will change. For sandbox automation — where a pipeline runs a
    /// sample in a disposable VM and no human is present at the moment of the run —
    /// <c>--intercept-https-consent</c> stands in, and its name is deliberately long
    /// enough that nobody types it by accident or without meaning it.
    /// </remarks>
    private static Func<Collectors.Proxy.InterceptionConsentRequest, bool>? ResolveInterceptionConsent(CommandLine cmd)
    {
        if (cmd.Flag("intercept-https-consent"))
        {
            return request =>
            {
                Console.Error.WriteLine(request.Describe());
                Console.Error.WriteLine();
                Console.Error.WriteLine("Consent was given on the command line with --intercept-https-consent.");
                return true;
            };
        }

        return cmd.Flag("intercept-https") ? AskForInterceptionConsent : null;
    }

    /// <summary>
    /// Asks the operator to confirm HTTPS interception.
    /// </summary>
    /// <remarks>
    /// Requires typing a word rather than pressing a key. This installs a trusted root
    /// certificate authority, and a prompt that a reflexive Enter clears is not consent
    /// to that. Declining is the default on anything unexpected, including a
    /// non-interactive console where nobody could have read the question.
    /// </remarks>
    private static bool AskForInterceptionConsent(Collectors.Proxy.InterceptionConsentRequest request)
    {
        Console.Error.WriteLine();
        Console.Error.WriteLine(request.Describe());
        Console.Error.WriteLine();

        if (Console.IsInputRedirected)
        {
            Console.Error.WriteLine(
                "Input is not interactive, so consent cannot be given. HTTPS interception is off.");
            return false;
        }

        Console.Error.Write("Type INTERCEPT to continue, or anything else to decline: ");
        string? answer = Console.ReadLine();

        bool agreed = string.Equals(answer?.Trim(), "INTERCEPT", StringComparison.Ordinal);
        if (!agreed) Console.Error.WriteLine("Declined. Continuing without HTTPS interception.");
        return agreed;
    }

    private static async Task<int> RunAsync(SessionOptions options, CommandLine cmd)
    {
        await using var orchestrator = new SessionOrchestrator(options);
        using var stopRequested = new CancellationTokenSource();

        Console.CancelKeyPress += (_, e) =>
        {
            // Ctrl+C must stop the session properly rather than killing the process:
            // an abrupt exit skips the after-snapshot and leaves the ETW session
            // registered with the kernel, where it keeps consuming buffers.
            e.Cancel = true;
            Console.Error.WriteLine("\nstopping session…");
            stopRequested.Cancel();
        };

        // Ctrl+C is not the only way this window goes away. Closing it, logging off, or
        // software that kills console hosts to shake off whatever is watching it all end
        // the process outright, and Windows allows a handful of seconds to react first.
        // Without this, a recording that ran for an hour is a database with no session
        // record in it and an ETW session still registered with the kernel.
        ConsoleHost.FinaliseOnClose(() =>
        {
            stopRequested.Cancel();
            orchestrator.StopAsync(CancellationToken.None).GetAwaiter().GetResult();
        });

        SessionInfo session = await orchestrator.StartAsync(CancellationToken.None).ConfigureAwait(false);

        Console.WriteLine($"session   {session.SessionId}");
        Console.WriteLine($"directory {orchestrator.SessionDirectory}");
        Console.WriteLine($"machine   {session.Machine.MachineName} ({session.Machine.OsBuild})" +
                          (session.Machine.IsVirtualMachine ? $" [{session.Machine.Hypervisor}]" : string.Empty));
        Console.WriteLine($"elevated  {session.WasElevated}");
        if (options.TargetPath is not null) Console.WriteLine($"target    {options.TargetPath}");
        Console.WriteLine();
        Console.WriteLine("recording… press Ctrl+C to stop");

        int duration = cmd.Int("duration", 0);
        try
        {
            if (duration > 0)
                await Task.Delay(TimeSpan.FromSeconds(duration), stopRequested.Token).ConfigureAwait(false);
            else
                await Task.Delay(Timeout.Infinite, stopRequested.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected: either Ctrl+C or the duration elapsed.
        }

        SessionInfo finished = await orchestrator.StopAsync(CancellationToken.None).ConfigureAwait(false);

        Console.WriteLine();
        Console.WriteLine($"duration  {finished.Duration.TotalSeconds:F1}s");
        Console.WriteLine($"events    {finished.Quality.EventsCollected:N0}");

        string? degraded = finished.Quality.Summarize();
        if (degraded is not null)
        {
            // Reported prominently and on stderr. A session that lost data looks
            // exactly like a program that did less than it did, and an analyst who
            // does not know the difference draws the wrong conclusion.
            Console.Error.WriteLine();
            Console.Error.WriteLine($"DATA QUALITY: {degraded}");
        }

        foreach (string skipped in finished.Quality.SkippedForPrivilege)
            Console.Error.WriteLine($"skipped: {skipped}");

        Console.WriteLine();
        Console.WriteLine($"Render it with:  CaYaTrace report --session \"{orchestrator.SessionDirectory}\"");
        return 0;
    }
}
