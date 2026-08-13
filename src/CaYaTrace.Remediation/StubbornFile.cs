using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using CaYaTrace.Collectors.Live;

namespace CaYaTrace.Remediation;

/// <summary>How hard a removal is allowed to try.</summary>
/// <remarks>
/// Two levels, because the escalation is not free. Stopping the process holding a file
/// costs whatever that process was doing, and taking ownership of a file changes a
/// permission the operator did not ask to change — both are right when the alternative is
/// leaving a program installed, and neither should happen because a file was momentarily
/// open in a text editor.
/// </remarks>
public enum RemovalForce
{
    /// <summary>Ask nicely; clear the attributes that are only bookkeeping; stop there.</summary>
    Standard = 0,

    /// <summary>Stop what is holding it, take ownership, and finish at the next restart.</summary>
    Insistent = 1,
}

/// <summary>One rung of the ladder, and what happened on it.</summary>
public readonly record struct RemovalAttempt(string Method, bool Succeeded, string Detail);

/// <summary>A process with the file open, as the Restart Manager describes it.</summary>
/// <param name="Service">
/// The service's short name, when the holder is a service. Not the display name: stopping
/// a service needs the name the service control manager knows it by, and the Restart
/// Manager reports the two in different fields.
/// </param>
/// <param name="Critical">
/// Set when Windows says stopping this would take the machine with it.
/// </param>
public readonly record struct FileHolder(uint Pid, string Name, string? Service, bool Critical)
{
    public override string ToString() => Service is { Length: > 0 }
        ? $"{Name} (service {Service}, {Pid})"
        : $"{Name} ({Pid})";
}

/// <summary>
/// What to do about a file that will not move.
/// </summary>
/// <remarks>
/// <para>
/// A removal that reports "in use or locked" and stops has told the operator nothing they
/// can act on. The file is held by <em>something</em>, and the machine knows what: the
/// Restart Manager exists to answer exactly that question and every Windows installer uses
/// it. Naming the holder is worth more than any of the forcing below, because most of the
/// time it is a file explorer preview pane and closing it costs nothing.
/// </para>
/// <para>
/// When that is not enough, the rungs are, in order: clear the attributes, stop what is
/// holding it, take ownership, and — for a file that cannot be moved while Windows is
/// running at all — hand it to the session manager to move before anything else starts at
/// the next boot. The last one is how a file locked by the kernel is removed, and it is the
/// only rung whose effect is not immediate.
/// </para>
/// <para>
/// Nothing here deletes. The reboot-time operation moves the file into quarantine exactly
/// as the immediate path does, so a removal that finishes after a restart is as reversible
/// as one that finishes straight away.
/// </para>
/// </remarks>
public static class StubbornFile
{
    /// <summary>
    /// Names the processes holding a file open.
    /// </summary>
    /// <remarks>
    /// Through the Restart Manager rather than by enumerating handles: it is a documented
    /// API, it needs no debug privilege, and it is what the file is really for. An empty
    /// list means either that nothing holds it or that the manager could not be asked —
    /// the two are reported apart by <paramref name="detail"/>, because "nothing holds this
    /// and it still will not move" points somewhere completely different.
    /// </remarks>
    public static IReadOnlyList<FileHolder> WhoIsHolding(string path, out string detail)
    {
        detail = string.Empty;

        var key = new StringBuilder(CchRmSessionKey + 1);
        int result = RmStartSession(out uint session, 0, key);
        if (result != 0)
        {
            detail = $"the restart manager could not be started (error {result})";
            return Array.Empty<FileHolder>();
        }

        try
        {
            result = RmRegisterResources(session, 1, new[] { path }, 0, null, 0, null);
            if (result != 0)
            {
                detail = $"the restart manager would not take this path (error {result})";
                return Array.Empty<FileHolder>();
            }

            uint needed = 0;
            uint count = 0;
            uint reasons = 0;

            result = RmGetList(session, out needed, ref count, null, ref reasons);

            if (result == ErrorMoreData && needed > 0)
            {
                var info = new RM_PROCESS_INFO[needed];
                count = needed;
                result = RmGetList(session, out needed, ref count, info, ref reasons);

                if (result == 0)
                {
                    var holders = new List<FileHolder>((int)count);
                    for (int i = 0; i < count; i++)
                    {
                        bool isService = info[i].ApplicationType == RmService
                                         && info[i].strServiceShortName is { Length: > 0 };

                        holders.Add(new FileHolder(
                            (uint)info[i].Process.dwProcessId,
                            info[i].strAppName,
                            isService ? info[i].strServiceShortName : null,
                            info[i].ApplicationType == RmCritical));
                    }

                    return holders;
                }
            }

            if (result != 0) detail = $"the restart manager could not list holders (error {result})";
            return Array.Empty<FileHolder>();
        }
        finally
        {
            RmEndSession(session);
        }
    }

    /// <summary>
    /// Clears the attributes that stop a move without meaning anything.
    /// </summary>
    /// <remarks>
    /// Read-only, hidden and system are bookkeeping bits, not protection. A program that
    /// sets them on its own files is not securing them, it is hiding them, and refusing to
    /// move a file because it is marked hidden is refusing to do the one thing asked.
    /// </remarks>
    public static RemovalAttempt ClearAttributes(string path)
    {
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            FileAttributes cleared = attributes
                                     & ~FileAttributes.ReadOnly
                                     & ~FileAttributes.Hidden
                                     & ~FileAttributes.System;

            if (cleared == attributes)
                return new RemovalAttempt("attributes", false, "nothing was set that would stop a move");

            File.SetAttributes(path, cleared);
            return new RemovalAttempt("attributes", true, $"cleared {attributes & ~cleared}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return new RemovalAttempt("attributes", false, ex.Message);
        }
    }

    /// <summary>
    /// Stops the processes holding a file, refusing anything the machine needs.
    /// </summary>
    /// <remarks>
    /// Delegated to the same control path the rest of the tool uses, so "is this safe to
    /// stop" has one answer rather than two. Anything critical is refused there and
    /// reported here.
    /// </remarks>
    public static RemovalAttempt StopHolders(IReadOnlyList<FileHolder> holders)
    {
        if (holders.Count == 0)
            return new RemovalAttempt("holders", false, "nothing was holding it");

        var stopped = new List<string>();
        var refused = new List<string>();

        uint self = (uint)Environment.ProcessId;

        foreach (FileHolder holder in holders)
        {
            if (holder.Pid == self)
            {
                refused.Add("this tool is holding it, which is a bug rather than a lock");
                continue;
            }

            // Windows says the machine goes down with it. Nothing on this ladder is worth
            // that, and the rung below — finishing at the next restart — exists for
            // exactly this file.
            if (holder.Critical)
            {
                refused.Add($"{holder.Name} is critical to the machine and was left alone");
                continue;
            }

            ControlResult result = holder.Service is { Length: > 0 } service
                ? ProcessControl.StopService(service)
                : ProcessControl.Stop(holder.Pid, null, force: true);

            if (result.Succeeded) stopped.Add(result.Message);
            else refused.Add(result.Message);
        }

        return new RemovalAttempt(
            "holders",
            stopped.Count > 0,
            stopped.Count > 0 ? string.Join("; ", stopped) : string.Join("; ", refused));
    }

    /// <summary>
    /// Takes ownership and grants the administrators group full control.
    /// </summary>
    /// <remarks>
    /// The answer to a file whose access list denies everyone, which is a thing programs do
    /// to their own components specifically so this step is needed. Ownership is taken
    /// first because an owner can always rewrite the access list and a non-owner facing a
    /// deny entry cannot do anything at all.
    /// </remarks>
    public static RemovalAttempt TakeOwnership(string path)
    {
        if (!TryEnable("SeTakeOwnershipPrivilege", out string why))
            return new RemovalAttempt("ownership", false, why);

        TryEnable("SeRestorePrivilege", out _);

        try
        {
            var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            var owner = new FileSecurity();
            owner.SetOwner(administrators);
            new FileInfo(path).SetAccessControl(owner);

            var grant = new FileSecurity();
            grant.AddAccessRule(new FileSystemAccessRule(
                administrators, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(grant);

            return new RemovalAttempt("ownership", true, "taken by the administrators group");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException
                                       or InvalidOperationException or PlatformNotSupportedException)
        {
            return new RemovalAttempt("ownership", false, ex.Message);
        }
    }

    /// <summary>
    /// Hands the move to the session manager, to run before anything else at the next boot.
    /// </summary>
    /// <remarks>
    /// The last rung, and the only one that works on a file the kernel itself has mapped —
    /// a loaded driver, a paging file, a DLL held by a process that cannot be stopped. The
    /// destination is the quarantine folder, not nothing, so the file survives and the
    /// removal stays reversible.
    /// </remarks>
    public static RemovalAttempt ScheduleForRestart(string source, string destination)
    {
        try
        {
            string? parent = Path.GetDirectoryName(destination);
            if (parent is { Length: > 0 }) Directory.CreateDirectory(parent);

            if (MoveFileEx(source, destination, MovefileDelayUntilReboot | MovefileReplaceExisting))
            {
                return new RemovalAttempt("restart", true,
                    "the session manager will move it before anything starts at the next restart");
            }

            return new RemovalAttempt("restart", false, new Win32Exception(Marshal.GetLastWin32Error()).Message);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return new RemovalAttempt("restart", false, ex.Message);
        }
    }

    // -------------------------------------------------------------- privilege

    private static bool TryEnable(string privilege, out string why)
    {
        why = string.Empty;

        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out IntPtr token))
        {
            why = "this process's token could not be opened";
            return false;
        }

        try
        {
            if (!LookupPrivilegeValue(null, privilege, out LUID luid))
            {
                why = $"{privilege} is not a privilege this system knows";
                return false;
            }

            var state = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SePrivilegeEnabled,
            };

            if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero))
            {
                why = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                return false;
            }

            // A token adjustment reports success even when it changed nothing, so the
            // only honest check is the error code it leaves behind.
            if (Marshal.GetLastWin32Error() == ErrorNotAllAssigned)
            {
                why = $"{privilege} is not held — this needs to run as an administrator";
                return false;
            }

            return true;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    // ---------------------------------------------------------------- interop

    private const int CchRmSessionKey = 32;
    private const int ErrorMoreData = 234;
    private const int ErrorNotAllAssigned = 1300;

    // RM_APP_TYPE. Worth writing out, because getting one of these wrong is not a
    // compile error and not obviously a bug either: a console program was read as a
    // service, the run tried to stop a service by that name, the service control
    // manager said it had never heard of it, and the file was scheduled for removal at
    // the next restart instead of simply being unlocked.
    private const uint RmService = 3;
    private const uint RmCritical = 1000;

    private const uint MovefileReplaceExisting = 0x1;
    private const uint MovefileDelayUntilReboot = 0x4;

    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SePrivilegeEnabled = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strAppName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string strServiceShortName;

        public uint ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;

        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint sessionHandle, int flags, StringBuilder sessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(
        uint sessionHandle,
        uint files, string[]? filenames,
        uint applications, RM_UNIQUE_PROCESS[]? rgApplications,
        uint services, string[]? serviceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(
        uint sessionHandle,
        out uint needed,
        ref uint count,
        [In, Out] RM_PROCESS_INFO[]? processes,
        ref uint rebootReasons);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint sessionHandle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string existing, string? destination, uint flags);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr token,
        [MarshalAs(UnmanagedType.Bool)] bool disableAll,
        ref TOKEN_PRIVILEGES state,
        uint previousLength,
        IntPtr previous,
        IntPtr returnLength);
}
