using System.Runtime.InteropServices;

namespace CaYaTrace.App;

/// <summary>
/// The tool's relationship with the console it was started from.
/// </summary>
/// <remarks>
/// <para>
/// CaYaTrace is a console-subsystem binary so that its command-line verbs compose
/// properly — piping, exit codes, and a shell that waits for it all depend on that. The
/// workbench does not want a console, and more importantly it must not <em>depend</em> on one.
/// </para>
/// <para>
/// <b>Why detaching matters.</b> A console-attached process shares the lifetime of a
/// console host it does not own. Anything that closes that console — a user closing the
/// window, a logoff, or software that kills console hosts as a way of shaking off
/// whatever is watching it — delivers a control event that ends the process by default.
/// A monitoring tool that can be stopped by closing a window is a monitoring tool that
/// can be stopped by the thing it is monitoring, and it would take the recording with it.
/// </para>
/// <para>
/// <b>Why detaching rather than hiding.</b> The window was previously hidden, which had a
/// second problem: <c>GetConsoleWindow</c> returns the <em>inherited</em> console when the tool is
/// started from an existing terminal, so hiding it hid the operator's own shell window
/// and left them with a process they could not see and a prompt that had vanished.
/// Detaching leaves an inherited console alone and disposes of an owned one.
/// </para>
/// </remarks>
public static class ConsoleHost
{
    private static ConsoleCtrlDelegate? _handler;

    /// <summary>
    /// Lets go of the console, so nothing that happens to it can happen to this process.
    /// </summary>
    /// <remarks>
    /// After this, writing to <see cref="Console"/> goes nowhere — which is why it is
    /// called only on the workbench path, where every message has somewhere better to go.
    /// </remarks>
    public static void Detach()
    {
        try
        {
            if (GetConsoleWindow() == IntPtr.Zero) return;
            FreeConsole();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // No console subsystem to detach from. Nothing to do, and nothing wrong.
        }
    }

    /// <summary>
    /// Hides the console window without detaching, for when output still has to go somewhere.
    /// </summary>
    /// <remarks>
    /// Only used when the operator asked to keep the console — otherwise
    /// <see cref="Detach"/> is the right answer. It deliberately refuses to hide a console
    /// this process did not create, because that console belongs to the shell the
    /// operator is standing in.
    /// </remarks>
    public static void HideIfOwned()
    {
        try
        {
            IntPtr window = GetConsoleWindow();
            if (window == IntPtr.Zero) return;

            // A console with exactly one attached process is ours; anything else means we
            // inherited it and the window is somebody else's.
            var pids = new uint[4];
            if (GetConsoleProcessList(pids, pids.Length) != 1) return;

            ShowWindow(window, SwHide);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
        }
    }

    /// <summary>
    /// Runs <paramref name="finalise"/> when the console is closed, instead of dying.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For the command-line verbs, which keep their console because that is the point of
    /// them. Windows gives a control handler a few seconds before terminating the process
    /// on a close or logoff, which is enough to flush a session and let it be opened
    /// afterwards. Without this, closing the window mid-recording leaves a database with
    /// no session record in it — a recording that ran for an hour and reads as empty.
    /// </para>
    /// <para>
    /// The delegate is held in a static field on purpose. Windows keeps only the function
    /// pointer, so a collected delegate becomes a crash the moment the user presses
    /// Ctrl+C — and it is the kind that only happens under memory pressure, months later,
    /// on someone else's machine.
    /// </para>
    /// </remarks>
    public static void FinaliseOnClose(Action finalise)
    {
        _handler = type =>
        {
            switch (type)
            {
                case CtrlCEvent:
                case CtrlBreakEvent:
                case CtrlCloseEvent:
                case CtrlLogoffEvent:
                case CtrlShutdownEvent:
                    try { finalise(); }
                    catch (Exception ex) when (ex is IOException or InvalidOperationException)
                    {
                        // Already shutting down. Nothing useful left to try.
                    }

                    // Ctrl+C is handled and the process continues its own shutdown; the
                    // rest are terminal and Windows ends us as soon as this returns.
                    return type is CtrlCEvent or CtrlBreakEvent;

                default:
                    return false;
            }
        };

        try { SetConsoleCtrlHandler(_handler, true); }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
        }
    }

    private const int SwHide = 0;
    private const uint CtrlCEvent = 0;
    private const uint CtrlBreakEvent = 1;
    private const uint CtrlCloseEvent = 2;
    private const uint CtrlLogoffEvent = 5;
    private const uint CtrlShutdownEvent = 6;

    private delegate bool ConsoleCtrlDelegate(uint controlType);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleProcessList(uint[] processList, int count);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleCtrlHandler(ConsoleCtrlDelegate handler, bool add);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr window, int command);
}
