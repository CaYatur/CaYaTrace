using System.Runtime.InteropServices;
using System.Text;

namespace CaYaTrace.Collectors;

/// <summary>
/// Starts a program suspended so that monitoring is fully in place before its first
/// instruction executes.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="System.Diagnostics.Process.Start(string)"/> cannot do this, and the gap
/// matters more than it sounds. Between "process started" and "our ETW session began
/// delivering events" there is typically a 50–300ms window. Installers unpack in that
/// window; droppers write and execute their payload in it. A tool that misses it
/// produces a tree that begins in the middle of the story.
/// </para>
/// <para>
/// Creating the process suspended also yields the PID before anything runs, so the
/// scope root is known in advance rather than being inferred from the first event
/// that happens to look right.
/// </para>
/// </remarks>
public sealed class SuspendedProcess : IDisposable
{
    private IntPtr _processHandle;
    private IntPtr _threadHandle;
    private bool _resumed;

    public uint Pid { get; }

    private SuspendedProcess(IntPtr processHandle, IntPtr threadHandle, uint pid)
    {
        _processHandle = processHandle;
        _threadHandle = threadHandle;
        Pid = pid;
    }

    public static SuspendedProcess? Launch(string executablePath, string? arguments, string? workingDirectory)
    {
        // CreateProcess mutates the command-line buffer, so it must be writable and
        // must include argv[0] — quoted, or a path with spaces is parsed as several
        // arguments.
        var commandLine = new StringBuilder();
        commandLine.Append('"').Append(executablePath).Append('"');
        if (!string.IsNullOrWhiteSpace(arguments)) commandLine.Append(' ').Append(arguments);

        var startupInfo = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };

        bool created = CreateProcessW(
            lpApplicationName: executablePath,
            lpCommandLine: commandLine,
            lpProcessAttributes: IntPtr.Zero,
            lpThreadAttributes: IntPtr.Zero,
            bInheritHandles: false,
            dwCreationFlags: CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            lpEnvironment: IntPtr.Zero,
            lpCurrentDirectory: string.IsNullOrEmpty(workingDirectory) ? null : workingDirectory,
            lpStartupInfo: ref startupInfo,
            lpProcessInformation: out PROCESS_INFORMATION info);

        if (!created) return null;

        return new SuspendedProcess(info.hProcess, info.hThread, info.dwProcessId);
    }

    /// <summary>Releases the initial thread. Safe to call more than once.</summary>
    public void Resume()
    {
        if (_resumed || _threadHandle == IntPtr.Zero) return;
        ResumeThread(_threadHandle);
        _resumed = true;
    }

    /// <summary>
    /// Terminates the subject. Used when an analyst aborts a session and does not
    /// want the program to keep running on the machine.
    /// </summary>
    public bool Terminate(uint exitCode = 1)
        => _processHandle != IntPtr.Zero && TerminateProcess(_processHandle, exitCode);

    public bool WaitForExit(TimeSpan timeout)
        => _processHandle != IntPtr.Zero
           && WaitForSingleObject(_processHandle, (uint)timeout.TotalMilliseconds) == 0;

    public void Dispose()
    {
        // A process left suspended would hang forever holding its files open, so
        // release it rather than leaking a frozen process onto the machine.
        if (!_resumed) Resume();

        if (_threadHandle != IntPtr.Zero) { CloseHandle(_threadHandle); _threadHandle = IntPtr.Zero; }
        if (_processHandle != IntPtr.Zero) { CloseHandle(_processHandle); _processHandle = IntPtr.Zero; }
    }

    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string? lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}
