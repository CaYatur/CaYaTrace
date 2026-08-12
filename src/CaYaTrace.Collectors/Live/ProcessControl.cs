using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;

namespace CaYaTrace.Collectors.Live;

/// <summary>What happened when something was asked to stop.</summary>
public sealed record ControlResult(bool Succeeded, string Message, IReadOnlyList<string> Affected)
{
    public static ControlResult Refused(string why) => new(false, why, Array.Empty<string>());
}

/// <summary>
/// Stops programs and services, carefully.
/// </summary>
/// <remarks>
/// <para>
/// Every method here refuses before it acts, and the refusals are the point. Stopping a
/// process the kernel has marked as critical bugchecks the machine; stopping a service
/// other services depend on can leave a machine that does not boot. Both are easy to do
/// by accident from a list of names, and neither is undoable.
/// </para>
/// <para>
/// Nothing here starts anything. The operations are stop, stop-with-children, stop a
/// service, and stop a service coming back — deliberately a closed set, because this is
/// reachable from the fleet channel and "run this" is not something a remote host should
/// be able to ask for.
/// </para>
/// </remarks>
public static class ProcessControl
{
    /// <summary>
    /// How long a program is given to close on its own before it is stopped outright.
    /// </summary>
    /// <remarks>
    /// Asking first matters for the ordinary case: a program told to close flushes what
    /// it was writing, and one that is terminated does not. Software that is resisting
    /// removal ignores the request, which costs this long and nothing else.
    /// </remarks>
    private static readonly TimeSpan GracePeriod = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Stops one process, asking politely first.
    /// </summary>
    /// <param name="expectedName">
    /// The name the caller believed it was acting on. Checked against the live process
    /// before anything happens, because process ids are recycled: a list drawn a few
    /// seconds ago can name a pid that now belongs to something else entirely, and
    /// terminating the wrong program is not recoverable by retrying.
    /// </param>
    public static ControlResult Stop(uint pid, string? expectedName = null, bool force = false)
    {
        if (pid <= 4) return ControlResult.Refused("the system and idle processes cannot be stopped");

        Process process;
        try
        {
            process = Process.GetProcessById((int)pid);
        }
        catch (ArgumentException)
        {
            return new ControlResult(true, $"pid {pid} was already gone", Array.Empty<string>());
        }

        using (process)
        {
            string name = SafeName(process);

            if (expectedName is { Length: > 0 }
                && !name.Equals(expectedName, StringComparison.OrdinalIgnoreCase)
                && !name.Equals(Path.GetFileNameWithoutExtension(expectedName), StringComparison.OrdinalIgnoreCase))
            {
                return ControlResult.Refused(
                    $"pid {pid} is now {name}, not {expectedName} — the id was reused, nothing was stopped");
            }

            if (IsCritical(pid))
                return ControlResult.Refused($"{name} ({pid}) is critical to the machine and was not stopped");

            try
            {
                if (!force && process.MainWindowHandle != IntPtr.Zero && process.CloseMainWindow())
                {
                    if (process.WaitForExit((int)GracePeriod.TotalMilliseconds))
                        return new ControlResult(true, $"{name} ({pid}) closed", new[] { $"{name} ({pid})" });
                }

                process.Kill(entireProcessTree: false);
                process.WaitForExit((int)GracePeriod.TotalMilliseconds);

                return new ControlResult(true, $"{name} ({pid}) stopped", new[] { $"{name} ({pid})" });
            }
            catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
            {
                return new ControlResult(false, $"could not stop {name} ({pid}): {ex.Message}", Array.Empty<string>());
            }
        }
    }

    /// <summary>
    /// Stops a process and everything it started.
    /// </summary>
    /// <remarks>
    /// Children first, and the whole tree is read once up front. Stopping a parent before
    /// its children leaves the children running and reparented, which is precisely how a
    /// watchdog pair survives being stopped — one of them dies, notices, and the survivor
    /// starts it again.
    /// </remarks>
    public static ControlResult StopTree(uint pid, string? expectedName = null)
    {
        List<LiveProcess> table = LiveProcessTable.Read();
        List<LiveProcess> descendants = LiveProcessTable.Descendants(pid, table);

        LiveProcess? root = table.FirstOrDefault(p => p.Pid == pid);
        if (root is null) return new ControlResult(true, $"pid {pid} was already gone", Array.Empty<string>());

        if (expectedName is { Length: > 0 }
            && !root.Name.Equals(expectedName, StringComparison.OrdinalIgnoreCase))
        {
            return ControlResult.Refused(
                $"pid {pid} is now {root.Name}, not {expectedName} — the id was reused, nothing was stopped");
        }

        var stopped = new List<string>();
        var problems = new List<string>();

        foreach (LiveProcess child in descendants)
        {
            if (child.IsCritical)
            {
                problems.Add($"{child.Name} ({child.Pid}) is critical and was left running");
                continue;
            }

            ControlResult result = Stop(child.Pid, child.Name, force: true);
            if (result.Succeeded) stopped.AddRange(result.Affected);
            else problems.Add(result.Message);
        }

        ControlResult last = Stop(pid, root.Name, force: true);
        if (last.Succeeded) stopped.AddRange(last.Affected);
        else problems.Add(last.Message);

        string message = problems.Count == 0
            ? $"stopped {stopped.Count} process(es)"
            : $"stopped {stopped.Count} process(es); {string.Join("; ", problems)}";

        return new ControlResult(problems.Count == 0, message, stopped);
    }

    /// <summary>Stops a service through the service control manager.</summary>
    /// <remarks>
    /// Through the manager rather than by killing the hosting process, because a service
    /// killed rather than stopped is a service the manager still believes is running, and
    /// its recovery actions fire.
    /// </remarks>
    public static ControlResult StopService(string name)
    {
        if (ProtectedServices.Contains(name))
            return ControlResult.Refused($"{name} is a Windows service the machine needs and was not stopped");

        try
        {
            using var service = new ServiceController(name);

            if (service.Status == ServiceControllerStatus.Stopped)
                return new ControlResult(true, $"{name} was already stopped", new[] { name });

            // Anything depending on this has to go first, or the manager refuses.
            var dependents = new List<string>();
            foreach (ServiceController dependent in service.DependentServices)
            {
                using (dependent)
                {
                    if (dependent.Status == ServiceControllerStatus.Stopped) continue;
                    if (ProtectedServices.Contains(dependent.ServiceName))
                    {
                        return ControlResult.Refused(
                            $"{name} is required by {dependent.ServiceName}, which the machine needs");
                    }

                    dependent.Stop();
                    dependent.WaitForStatus(ServiceControllerStatus.Stopped, GracePeriod);
                    dependents.Add(dependent.ServiceName);
                }
            }

            if (!service.CanStop)
                return ControlResult.Refused($"{name} reports that it cannot be stopped");

            service.Stop();
            service.WaitForStatus(ServiceControllerStatus.Stopped, GracePeriod);

            var affected = new List<string>(dependents) { name };
            return new ControlResult(true, $"{name} stopped", affected);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or System.ServiceProcess.TimeoutException)
        {
            return new ControlResult(false, $"could not stop {name}: {ex.Message}", Array.Empty<string>());
        }
    }

    /// <summary>
    /// Stops a service starting itself again.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two things bring a stopped service back, and both are disarmed here: the start type,
    /// which starts it at boot, and the recovery actions, which restart it seconds after
    /// it stops. Software that resists removal configures the second one, and a removal
    /// that only sets the start type looks like it worked until the machine is watched for
    /// a minute.
    /// </para>
    /// <para>
    /// Set to manual rather than disabled. Disabled is what an operator does deliberately;
    /// manual leaves the service startable by someone who decides it should be, which
    /// matters when this turns out to have been the wrong call.
    /// </para>
    /// </remarks>
    public static ControlResult DisableAutostart(string name)
    {
        if (ProtectedServices.Contains(name))
            return ControlResult.Refused($"{name} is a Windows service the machine needs and was left alone");

        var changed = new List<string>();

        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{name}", writable: true);

            if (key is null)
                return new ControlResult(false, $"{name} has no service key", Array.Empty<string>());

            if (key.GetValue("Start") is int start && start != ServiceStartManual)
            {
                key.SetValue("Start", ServiceStartManual, RegistryValueKind.DWord);
                changed.Add($"{name} start type {start} → manual");
            }

            if (key.GetValue("FailureActions") is byte[])
            {
                key.DeleteValue("FailureActions", throwOnMissingValue: false);
                changed.Add($"{name} recovery actions removed");
            }

            if (key.GetValue("FailureCommand") is string)
            {
                key.DeleteValue("FailureCommand", throwOnMissingValue: false);
                changed.Add($"{name} recovery command removed");
            }

            return changed.Count == 0
                ? new ControlResult(true, $"{name} was not set to start on its own", Array.Empty<string>())
                : new ControlResult(true, string.Join("; ", changed), changed);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return new ControlResult(false, $"could not change {name}: {ex.Message}", changed);
        }
    }

    private const int ServiceStartManual = 3;

    /// <summary>
    /// Services the machine needs, which this never stops whatever it is asked.
    /// </summary>
    /// <remarks>
    /// Shared shape with the removal policy's list but kept separate on purpose: that one
    /// governs what may be deleted, this one governs what may be stopped, and they are not
    /// the same question. A service can be safe to leave configured and unsafe to stop
    /// while the machine is running.
    /// </remarks>
    private static readonly HashSet<string> ProtectedServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "PlugPlay", "Power", "Winmgmt",
        "EventLog", "Schedule", "ProfSvc", "SamSs", "gpsvc", "BFE", "MpsSvc",
        "Dhcp", "Dnscache", "NlaSvc", "netprofm", "nsi", "Tcpip", "Afd", "TermService",
        "CryptSvc", "Themes", "AudioSrv", "AudioEndpointBuilder", "UserManager",
        "SystemEventsBroker", "StateRepository", "CoreMessagingRegistrar", "camsvc",
        "TrustedInstaller", "msiserver", "WinDefend", "SecurityHealthService", "wscsvc",
    };

    private static bool IsCritical(uint pid)
    {
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
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
    }

    private static string SafeName(Process process)
    {
        try { return process.ProcessName; }
        catch (InvalidOperationException) { return $"pid {process.Id}"; }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int ProcessBreakOnTermination = 29;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr process, int infoClass, ref uint info, int length, out int returned);
}
