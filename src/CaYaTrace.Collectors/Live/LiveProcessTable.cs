using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace CaYaTrace.Collectors.Live;

/// <summary>One process as the live view sees it.</summary>
public sealed record LiveProcess
{
    public required uint Pid { get; init; }
    public uint ParentPid { get; init; }
    public required string Name { get; init; }
    public string? Path { get; init; }
    public string? CommandLine { get; init; }
    public string? User { get; init; }
    public DateTimeOffset? Started { get; init; }
    public long WorkingSetBytes { get; init; }
    public int ThreadCount { get; init; }

    /// <summary>
    /// Stopping this process takes the machine down with it.
    /// </summary>
    /// <remarks>
    /// Asked of the kernel rather than guessed from a name where possible: a process with
    /// <c>BreakOnTermination</c> set bugchecks the machine when it exits, and that is the
    /// property that actually matters. The name list is the fallback for the processes
    /// whose handles cannot be opened to ask — which, being protected, are exactly the
    /// ones that matter most.
    /// </remarks>
    public bool IsCritical { get; init; }

    /// <summary>Services hosted in this process, empty when it hosts none.</summary>
    public string? ServiceNames { get; init; }
}

/// <summary>
/// A snapshot of what is running, cheap enough to poll.
/// </summary>
/// <remarks>
/// <para>
/// Separate from the ETW process table on purpose. That one is a record of a session and
/// is only as complete as the trace; this one answers "what is running on this machine
/// right now", which is the question an operator asks when a machine has started
/// behaving strangely and they have not recorded anything yet.
/// </para>
/// <para>
/// The base list comes from the toolhelp snapshot, which costs a couple of milliseconds.
/// Command lines and owners come from WMI, which costs a few hundred, so they are only
/// gathered when something actually asked to see them.
/// </para>
/// </remarks>
public static class LiveProcessTable
{
    /// <summary>
    /// Processes the machine cannot continue without, for when the kernel cannot be asked.
    /// </summary>
    /// <remarks>
    /// <c>svchost</c> is deliberately absent. It hosts services, and a service worth
    /// stopping is a real reason to stop one — the caller is warned that it is
    /// system-owned instead of being refused outright.
    /// </remarks>
    private static readonly HashSet<string> CriticalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "Memory Compression", "MemCompression",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsaiso.exe", "ntoskrnl.exe",
    };

    private static readonly ConcurrentDictionary<uint, bool> CriticalCache = new();

    /// <summary>Reads the process list. <paramref name="detailed"/> adds command lines and owners.</summary>
    public static List<LiveProcess> Read(bool detailed = false)
    {
        Dictionary<uint, (uint Parent, string Name, int Threads)> basics = ReadToolhelp();
        Dictionary<uint, string> services = ReadServiceHosts();
        Dictionary<uint, WmiFacts> wmi = detailed ? ReadWmi() : new Dictionary<uint, WmiFacts>();

        var result = new List<LiveProcess>(basics.Count);

        foreach ((uint pid, (uint parent, string name, int threads)) in basics)
        {
            wmi.TryGetValue(pid, out WmiFacts? facts);

            long workingSet = 0;
            DateTimeOffset? started = null;
            try
            {
                using Process p = Process.GetProcessById((int)pid);
                workingSet = p.WorkingSet64;
                started = p.StartTime;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception)
            {
                // Exited between the snapshot and here, or protected. Neither is an error:
                // the row is still worth showing, just without those two numbers.
            }

            result.Add(new LiveProcess
            {
                Pid = pid,
                ParentPid = facts?.ParentPid ?? parent,
                Name = name,
                Path = facts?.Path ?? TryReadPath(pid),
                CommandLine = facts?.CommandLine,
                User = facts?.User,
                Started = facts?.Started ?? started,
                WorkingSetBytes = workingSet,
                ThreadCount = threads,
                IsCritical = IsCritical(pid, name),
                ServiceNames = services.GetValueOrDefault(pid),
            });
        }

        return result.OrderBy(static p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Every descendant of a process, deepest first.</summary>
    /// <remarks>
    /// Ordered deepest first because that is the order they have to be stopped in. A
    /// parent stopped before its children leaves them running and reparented, which is
    /// how software that watches its own children survives being stopped.
    /// </remarks>
    public static List<LiveProcess> Descendants(uint pid, IReadOnlyList<LiveProcess>? table = null)
    {
        List<LiveProcess> all = table?.ToList() ?? Read();

        var byParent = new Dictionary<uint, List<LiveProcess>>();
        foreach (LiveProcess p in all)
        {
            if (!byParent.TryGetValue(p.ParentPid, out List<LiveProcess>? kids))
                byParent[p.ParentPid] = kids = new List<LiveProcess>();
            kids.Add(p);
        }

        var ordered = new List<LiveProcess>();
        var seen = new HashSet<uint> { pid };

        void Walk(uint parent, int depth)
        {
            // A cycle is impossible in a real process tree, but pid reuse can fabricate
            // one in a snapshot taken while processes are exiting. Bounded so a stale
            // reading cannot spin.
            if (depth > 32) return;
            if (!byParent.TryGetValue(parent, out List<LiveProcess>? kids)) return;

            foreach (LiveProcess kid in kids)
            {
                if (!seen.Add(kid.Pid)) continue;
                Walk(kid.Pid, depth + 1);
                ordered.Add(kid);
            }
        }

        Walk(pid, 0);
        return ordered;
    }

    private sealed record WmiFacts(
        uint ParentPid, string? Path, string? CommandLine, string? User, DateTimeOffset? Started);

    private static Dictionary<uint, WmiFacts> ReadWmi()
    {
        var result = new Dictionary<uint, WmiFacts>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate FROM Win32_Process");

            foreach (ManagementBaseObject row in searcher.Get())
            {
                using (row)
                {
                    uint pid = Convert.ToUInt32(row["ProcessId"] ?? 0u);
                    DateTimeOffset? started = null;

                    if (row["CreationDate"] is string created && created.Length > 0)
                    {
                        try { started = ManagementDateTimeConverter.ToDateTime(created); }
                        catch (ArgumentOutOfRangeException) { }
                    }

                    result[pid] = new WmiFacts(
                        Convert.ToUInt32(row["ParentProcessId"] ?? 0u),
                        row["ExecutablePath"] as string,
                        row["CommandLine"] as string,
                        null,
                        started);
                }
            }
        }
        catch (ManagementException)
        {
            // WMI is disabled or broken on this machine. The toolhelp list still works,
            // so the view degrades to fewer columns rather than showing nothing.
        }
        catch (COMException)
        {
        }

        return result;
    }

    /// <summary>Maps process ids to the services they host.</summary>
    private static Dictionary<uint, string> ReadServiceHosts()
    {
        var result = new Dictionary<uint, string>();

        try
        {
            foreach (ServiceController service in ServiceController.GetServices())
            {
                using (service)
                {
                    try
                    {
                        if (service.Status != ServiceControllerStatus.Running) continue;

                        uint pid = QueryServicePid(service.ServiceName);
                        if (pid == 0) continue;

                        result[pid] = result.TryGetValue(pid, out string? existing)
                            ? $"{existing}, {service.ServiceName}"
                            : service.ServiceName;
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
                    {
                    }
                }
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
        }

        return result;
    }

    private static bool IsCritical(uint pid, string name)
    {
        if (pid <= 4) return true;
        if (CriticalNames.Contains(name)) return true;

        return CriticalCache.GetOrAdd(pid, static id =>
        {
            IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, id);
            if (handle == IntPtr.Zero) return false;

            try
            {
                uint breakOnTermination = 0;
                int status = NtQueryInformationProcess(
                    handle, ProcessBreakOnTermination, ref breakOnTermination, sizeof(uint), out _);

                return status == 0 && breakOnTermination != 0;
            }
            finally
            {
                CloseHandle(handle);
            }
        });
    }

    private static string? TryReadPath(uint pid)
    {
        if (pid <= 4) return null;

        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return null;

        try
        {
            var buffer = new System.Text.StringBuilder(1024);
            int size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString() : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static Dictionary<uint, (uint Parent, string Name, int Threads)> ReadToolhelp()
    {
        var result = new Dictionary<uint, (uint, string, int)>();

        IntPtr snapshot = CreateToolhelp32Snapshot(Th32CsSnapProcess, 0);
        if (snapshot == InvalidHandle) return result;

        try
        {
            var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32First(snapshot, ref entry)) return result;

            do
            {
                result[entry.th32ProcessID] =
                    (entry.th32ParentProcessID, entry.szExeFile ?? string.Empty, (int)entry.cntThreads);
            }
            while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return result;
    }

    private static uint QueryServicePid(string name)
    {
        IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero) return 0;

        try
        {
            IntPtr service = OpenService(manager, name, ServiceQueryStatus);
            if (service == IntPtr.Zero) return 0;

            try
            {
                var status = new SERVICE_STATUS_PROCESS();
                int size = Marshal.SizeOf<SERVICE_STATUS_PROCESS>();
                IntPtr buffer = Marshal.AllocHGlobal(size);

                try
                {
                    if (!QueryServiceStatusEx(service, ScStatusProcessInfo, buffer, size, out _)) return 0;
                    status = Marshal.PtrToStructure<SERVICE_STATUS_PROCESS>(buffer);
                    return status.dwProcessId;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    // --------------------------------------------------------------- interop

    private const uint Th32CsSnapProcess = 0x00000002;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int ProcessBreakOnTermination = 29;
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;

    private static readonly IntPtr InvalidHandle = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32First(IntPtr snapshot, ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32Next(IntPtr snapshot, ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process, uint flags, System.Text.StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr process, int infoClass, ref uint info, int length, out int returned);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(
        IntPtr service, int infoLevel, IntPtr buffer, int size, out int needed);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
