using CaYaTrace.App.Cli;

namespace CaYaTrace.App.Modes;

/// <summary>
/// The analyst workbench: a WebView2-hosted UI over the same engine the CLI drives.
/// </summary>
/// <remarks>
/// <para>
/// A web UI inside a native shell rather than WPF, for three reasons specific to this
/// product. The causal tree is a deeply nested, heavily virtualized view that HTML
/// handles better than any XAML control. The HTML export the user needs — a
/// self-contained report a non-technical reader can open — is then the same rendering
/// code rather than a second implementation that drifts. And the CaYaDev visual
/// language the rest of the product line uses is already expressed in CSS.
/// </para>
/// <para>
/// WebView2 is the Evergreen runtime shipped with Windows 11 and pushed to Windows 10;
/// when it is genuinely absent the app degrades to the CLI rather than failing.
/// </para>
/// </remarks>
public static class WorkbenchMode
{
    public static int Run(CommandLine cmd, UserSettings settings)
    {
        if (!WebViewRuntime.IsAvailable(out string? version))
        {
            Console.Error.WriteLine(
                "cayatrace: the WebView2 runtime is not installed, so the workbench cannot open.");
            Console.Error.WriteLine(
                "           Install it from https://developer.microsoft.com/microsoft-edge/webview2/");
            Console.Error.WriteLine();
            CommandLine.PrintUsage();
            return 4;
        }

        // The console exists because this is a console-subsystem binary (so the CLI
        // composes properly). In GUI mode it is noise, so hide it rather than leaving
        // an empty black window behind the workbench.
        HideConsoleWindow();

        System.Windows.Forms.Application.EnableVisualStyles();
        System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);

        string? session = cmd.Get("session") ?? cmd.Positional.FirstOrDefault();

        // --view opens straight into a section. Useful for a shortcut that always lands
        // on Capture, and it is what makes the workbench screenshottable without
        // driving the mouse.
        using var window = new WorkbenchWindow(session, settings) { InitialView = cmd.Get("view") };
        System.Windows.Forms.Application.Run(window);
        return 0;
    }

    private static void HideConsoleWindow()
    {
        try
        {
            IntPtr handle = GetConsoleWindow();
            if (handle != IntPtr.Zero) ShowWindow(handle, SW_HIDE);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // No console to hide — launched detached. Nothing to do.
        }
    }

    private const int SW_HIDE = 0;

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}

internal static class WebViewRuntime
{
    public static bool IsAvailable(out string? version)
    {
        version = null;
        try
        {
            version = Microsoft.Web.WebView2.Core.CoreWebView2Environment.GetAvailableBrowserVersionString();
            return !string.IsNullOrEmpty(version);
        }
        catch (Exception ex) when (ex is WebView2RuntimeNotFoundExceptionShim or DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
        catch (Exception)
        {
            // The runtime reports its absence through a typed exception, but a broken
            // or partially removed install can surface almost anything. Treating any
            // failure as "unavailable" degrades to the CLI instead of crashing.
            return false;
        }
    }
}

/// <summary>
/// Placeholder so the catch clause above names the concrete WebView2 exception type
/// without the shell taking a hard dependency on its exact assembly identity.
/// </summary>
internal sealed class WebView2RuntimeNotFoundExceptionShim : Exception;

/// <summary>
/// Resolves the writable location WebView2 uses for its user-data folder.
/// </summary>
/// <remarks>
/// WebView2 defaults to creating this folder beside the executable, which fails the
/// moment CaYaTrace is run the way it is meant to be run: from a read-only share, a
/// write-protected USB stick, or an evidence drive mounted read-only. Setting it
/// explicitly to LocalAppData is the difference between the portable story working
/// and not.
/// </remarks>
public static class WebViewPaths
{
    public static string UserDataFolder
    {
        get
        {
            string root = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData,
                Environment.SpecialFolderOption.Create);
            string path = Path.Combine(root, "CaYaDev", "CaYaTrace", "WebView2");
            Directory.CreateDirectory(path);
            return path;
        }
    }
}
