using CaYaTrace.App.Cli;
using CaYaTrace.App.Modes;
using CaYaTrace.Collectors.Proxy;

namespace CaYaTrace.App;

/// <summary>
/// Single entry point for every mode CaYaTrace runs in.
/// </summary>
/// <remarks>
/// <para>
/// The product ships as one portable executable that behaves differently depending on
/// how it is invoked. This keeps distribution to a single file the user downloads once,
/// while still allowing purpose-built artifacts to be exported from it:
/// </para>
/// <list type="bullet">
///   <item><description><b>No arguments</b> — the analyst workbench (WebView2 UI).</description></item>
///   <item><description><b><c>trace</c></b> — headless recording, for scripted and CI use.</description></item>
///   <item><description><b><c>report</c></b> — render a recorded session without collecting.</description></item>
///   <item><description>
///     <b><c>remediate</c></b> — apply a removal package on a machine that has never run
///     the full tool. Paired with a <c>.ctpkg</c> sidecar.
///   </description></item>
///   <item><description>
///     <b><c>agent</c></b> — collect on behalf of a remote host during multi-VM analysis.
///     Idle until a host it has been paired with connects.
///   </description></item>
/// </list>
/// <para>
/// A sidecar package next to the executable switches the default mode, which is how an
/// exported remediator opens straight into its own workflow. Payloads are <em>not</em>
/// embedded into the executable itself: patching resources into a .NET single-file
/// bundle truncates and corrupts it — measured, not assumed. See
/// docs/PACKAGE-FORMAT.md.
/// </para>
/// </remarks>
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // Box-drawing characters in the tree and non-ASCII paths both need UTF-8.
        // Setting it fails when no console is attached (a detached GUI launch), which
        // is not an error worth aborting over.
        try { Console.OutputEncoding = System.Text.Encoding.UTF8; }
        catch (IOException) { }
        catch (System.Security.SecurityException) { }

        try
        {
            CommandLine parsed = CommandLine.Parse(args);

            // Resolved once, here, so every mode — workbench, CLI output, exported
            // report — speaks the same language in the same run. An explicit --lang wins
            // over a remembered preference, which wins over the system UI language.
            UserSettings settings = UserSettings.Load();
            Strings.Language = Strings.Resolve(parsed.Get("lang"), settings.Language);

            // Before anything else this launch was asked to do. An earlier run that was
            // killed mid-session can leave the machine pointing at a proxy that no longer
            // exists, and a machine in that state cannot reach the network at all — so
            // repairing it comes before the work, not after it.
            SweepMachineChanges();

            return parsed.Verb switch
            {
                "trace" => TraceCommand.Run(parsed),
                "report" => ReportCommand.Run(parsed),
                "remediate" => RemediateCommand.Run(parsed),
                "compare" => CompareCommand.Run(parsed),
                "explain" => ExplainCommand.Run(parsed),
                "agent" => AgentCommand.Run(parsed),
                "version" => PrintVersion(),
                "help" => CommandLine.PrintUsage(),
                _ => WorkbenchMode.Run(parsed, settings),
            };
        }
        catch (CommandLineException ex)
        {
            Console.Error.WriteLine($"cayatrace: {ex.Message}");
            CommandLine.PrintUsage();
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"cayatrace: unhandled error: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Undoes any machine change an earlier run was killed before undoing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two changes can outlive a session: a trusted root, which expires by itself within
    /// twelve hours, and the system proxy configuration, which does not expire at all. The
    /// second is the dangerous one. A machine left pointing at a dead loopback port loses
    /// every HTTP client on it — browsers, updaters, installers — and fails with errors
    /// that name no cause, so nobody has any reason to suspect a forensics tool they ran
    /// last week.
    /// </para>
    /// <para>
    /// Deliberately unconditional. This used to live inside the proxy collector, which
    /// meant the promise the consent dialog makes — <em>removed again on the next launch</em>
    /// — was only kept for an operator who happened to switch interception on a second
    /// time. Anyone who ran it once, was bitten, and never touched the feature again was
    /// exactly the person it never reached.
    /// </para>
    /// <para>
    /// Nothing here is allowed to stop the launch. A tool that refuses to start because it
    /// could not tidy up after itself is worse than one that says so and carries on.
    /// </para>
    /// </remarks>
    private static void SweepMachineChanges()
    {
        ProxyRestorePoint.SweepResult result;

        try
        {
            result = ProxyRestorePoint.Sweep();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"cayatrace: could not check for leftover machine changes: {ex.Message}");
            return;
        }

        if (!result.DidAnything && !result.NeedsAttention) return;

        var lines = result.MessageKeys().Select(Strings.T).ToList();
        foreach (string line in lines) Console.Error.WriteLine($"cayatrace: {line}");

        // A GUI launch has no console to read, and the two things this can report — the
        // machine cannot reach the network, or a certificate authority is still trusted —
        // are both too serious to leave in a stream nobody is looking at.
        if (result.NeedsAttention)
        {
            try
            {
                MessageBox.Show(
                    string.Join("\n\n", lines), "CaYaTrace",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
            }
        }
    }

    private static int PrintVersion()
    {
        Console.WriteLine($"CaYaTrace {BuildInfo.Version}");
        Console.WriteLine($"  runtime  {Environment.Version}");
        Console.WriteLine($"  os       {Environment.OSVersion.VersionString}");
        Console.WriteLine($"  elevated {Privilege.IsElevated()}");
        Console.WriteLine($"  language {Strings.Language}  (available: {string.Join(", ", Strings.Available)})");
        return 0;
    }
}

public static class BuildInfo
{
    public static string Version =>
        typeof(BuildInfo).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    public const string Product = "CaYaTrace";
    public const string Repository = "https://github.com/CaYatur/CaYaTrace";
}

public static class Privilege
{
    public static bool IsElevated()
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

    /// <summary>
    /// Relaunches the current executable elevated, forwarding the same arguments.
    /// </summary>
    /// <remarks>
    /// Called only at the point a privileged capability is actually requested, never
    /// at startup — a tool that demands administrator rights before showing what it
    /// intends to do teaches users to click through UAC without reading it.
    /// </remarks>
    public static bool TryRelaunchElevated(string[] args)
    {
        try
        {
            string? exe = Environment.ProcessPath;
            if (exe is null) return false;

            var startInfo = new System.Diagnostics.ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = string.Join(' ', args.Select(Quote)),
            };
            System.Diagnostics.Process.Start(startInfo);
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // The user declined the UAC prompt. That is an answer, not an error.
            return false;
        }
    }

    private static string Quote(string value)
        => value.Contains(' ', StringComparison.Ordinal) ? $"\"{value}\"" : value;
}
