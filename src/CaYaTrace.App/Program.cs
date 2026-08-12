using CaYaTrace.App.Cli;
using CaYaTrace.App.Modes;

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
