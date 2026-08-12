using System.ComponentModel;
using System.Diagnostics;
using System.ServiceProcess;
using CaYaTrace.Collectors.Live;
using CaYaTrace.Core.Naming;
using Microsoft.Win32;

namespace CaYaTrace.Remediation;

/// <summary>Something that would bring a removal target back, or block it.</summary>
public sealed record Defence
{
    public required DefenceKind Kind { get; init; }

    /// <summary>The service name or process this concerns.</summary>
    public required string Subject { get; init; }

    /// <summary>What was found, in plain words.</summary>
    public required string Description { get; init; }

    /// <summary>What would be done about it, or why nothing can be.</summary>
    public required string Response { get; init; }

    /// <summary>False when this is reported but cannot be dealt with.</summary>
    public bool CanDisarm { get; init; } = true;
}

public enum DefenceKind
{
    /// <summary>A service configured to restart itself after it stops.</summary>
    ServiceRecovery,

    /// <summary>A service that starts again at boot.</summary>
    ServiceAutostart,

    /// <summary>A process holding a file the removal needs to move.</summary>
    RunningProcess,

    /// <summary>Two processes that restart each other when one stops.</summary>
    WatchdogPair,

    /// <summary>A process the kernel will not let anything stop.</summary>
    ProtectedProcess,
}

/// <summary>What a disarming run did.</summary>
public sealed record DisarmResult(
    IReadOnlyList<Defence> Found,
    IReadOnlyList<string> Actions,
    IReadOnlyList<string> Failures)
{
    public bool Clear => Failures.Count == 0;
}

/// <summary>
/// Finds and disables the things that make software come back.
/// </summary>
/// <remarks>
/// <para>
/// A removal that deletes files while the program is running and configured to restart
/// itself is a removal that appears to work and has not. Windows offers software three
/// standard ways to survive being stopped, and all three are ordinary features that
/// legitimate products use too:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>Service recovery actions.</b> The service control manager restarts the service
///     seconds after it stops. Configured in the registry, invisible in the services list.
///   </description></item>
///   <item><description>
///     <b>Automatic start.</b> Stopping a service does nothing about the next boot.
///   </description></item>
///   <item><description>
///     <b>A watchdog pair.</b> Two processes that each notice the other's absence. Killing
///     either one is undone by the survivor within seconds, and killing them in the wrong
///     order looks exactly like killing them in the right order until you look again.
///   </description></item>
/// </list>
/// <para>
/// <b>What this deliberately will not do.</b> It does not stop processes the kernel has
/// marked critical, does not touch services Windows needs, and does not attempt anything
/// clever against code that has put itself somewhere it cannot be reached from user mode.
/// Those are reported as found-and-not-disarmed. A tool that fights for control of a
/// machine can lose, and losing halfway through a removal leaves the operator worse off
/// than not starting — the honest outcome is to say what is in the way.
/// </para>
/// </remarks>
public sealed class SelfProtection
{
    private readonly PathNormalizer _paths;

    public SelfProtection(PathNormalizer? paths = null)
        => _paths = paths ?? PathNormalizer.CreateForCurrentMachine();

    /// <summary>
    /// Looks at a plan and reports what would fight it.
    /// </summary>
    /// <remarks>
    /// Read-only. The operator sees this before deciding to apply anything, because
    /// "this program will restart itself unless I also disable its recovery actions" is
    /// exactly the sort of thing worth knowing before starting rather than after.
    /// </remarks>
    public IReadOnlyList<Defence> Inspect(IReadOnlyList<RemovalItem> items)
    {
        var found = new List<Defence>();

        foreach (RemovalItem item in items.Where(static i => i.Kind == RemovalKind.Service))
            found.AddRange(InspectService(item.Target));

        List<LiveProcess> live = SafeReadProcesses();
        found.AddRange(InspectProcesses(items, live));
        found.AddRange(InspectWatchdogs(items, live));

        return found;
    }

    private IEnumerable<Defence> InspectService(string name)
    {
        RegistryKey? key = null;
        try
        {
            key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}", writable: false);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
        }

        if (key is null) yield break;

        using (key)
        {
            if (key.GetValue("FailureActions") is byte[] blob)
            {
                Analysis.Persistence.ServiceRecovery? recovery =
                    Analysis.Persistence.ServiceFailureActions.Decode(blob);

                if (recovery is not null && recovery.RestartsOnFailure)
                {
                    yield return new Defence
                    {
                        Kind = DefenceKind.ServiceRecovery,
                        Subject = name,
                        Description = $"{name} will {Analysis.Persistence.ServiceFailureActions.Describe(recovery)}",
                        Response = "its recovery actions will be removed before it is stopped",
                    };
                }
            }

            if (key.GetValue("Start") is int start && start is 0 or 1 or 2)
            {
                yield return new Defence
                {
                    Kind = DefenceKind.ServiceAutostart,
                    Subject = name,
                    Description = $"{name} {Analysis.Persistence.ServiceStartType.Describe(start)}",
                    Response = "it will be set to manual start before it is stopped",
                };
            }
        }
    }

    /// <summary>Processes running from a path the plan is going to move.</summary>
    private IEnumerable<Defence> InspectProcesses(IReadOnlyList<RemovalItem> items, List<LiveProcess> live)
    {
        List<string> targets = items
            .Where(static i => i.Kind is RemovalKind.File or RemovalKind.Directory)
            .Select(i => _paths.Expand(i.Target))
            .Where(static p => p.Length > 0)
            .ToList();

        if (targets.Count == 0) yield break;

        foreach (LiveProcess process in live)
        {
            if (process.Path is not { Length: > 0 } path) continue;

            bool inside = targets.Any(t =>
                path.Equals(t, StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(t.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));

            if (!inside) continue;

            yield return process.IsCritical
                ? new Defence
                {
                    Kind = DefenceKind.ProtectedProcess,
                    Subject = $"{process.Name} ({process.Pid})",
                    Description = $"{process.Name} is running from a path this plan removes, and the kernel will not allow it to be stopped",
                    Response = "it will be left running, and its files will be skipped",
                    CanDisarm = false,
                }
                : new Defence
                {
                    Kind = DefenceKind.RunningProcess,
                    Subject = $"{process.Name} ({process.Pid})",
                    Description = $"{process.Name} is running from {path}",
                    Response = "it and anything it started will be stopped before its files are moved",
                };
        }
    }

    /// <summary>
    /// Two processes from the same install, each capable of restarting the other.
    /// </summary>
    /// <remarks>
    /// Detected structurally rather than by watching: two or more running processes whose
    /// images live in the same directory the plan is removing, where at least one is not
    /// a descendant of the other. That is the shape of a watchdog arrangement, and the
    /// response — stop them as one group rather than one at a time — is correct whether or
    /// not they actually watch each other. Guessing wrong here costs nothing; guessing the
    /// other way costs a removal that silently did not work.
    /// </remarks>
    private IEnumerable<Defence> InspectWatchdogs(IReadOnlyList<RemovalItem> items, List<LiveProcess> live)
    {
        List<string> directories = items
            .Where(static i => i.Kind == RemovalKind.Directory)
            .Select(i => _paths.Expand(i.Target).TrimEnd('\\'))
            .Where(static p => p.Length > 0)
            .ToList();

        foreach (string directory in directories)
        {
            List<LiveProcess> inside = live
                .Where(p => p.Path is { Length: > 0 } path
                            && path.StartsWith(directory + "\\", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (inside.Count < 2) continue;

            var pids = new HashSet<uint>(inside.Select(static p => p.Pid));
            bool independent = inside.Any(p => !pids.Contains(p.ParentPid));
            if (!independent) continue;

            yield return new Defence
            {
                Kind = DefenceKind.WatchdogPair,
                Subject = directory,
                Description =
                    $"{inside.Count} processes are running from {directory} without a common parent: "
                    + string.Join(", ", inside.Select(static p => $"{p.Name} ({p.Pid})")),
                Response = "they will be stopped as one group, so a survivor cannot restart the others",
            };
        }
    }

    /// <summary>
    /// Disarms what can be disarmed, in the order that works.
    /// </summary>
    /// <remarks>
    /// The order is the whole thing. Recovery actions come off before the service is
    /// stopped, or the manager restarts it. Autostart is cleared before the stop, or a
    /// reboot mid-removal undoes the work. Watchdog groups are stopped together, youngest
    /// first, before any single process is stopped on its own.
    /// </remarks>
    public DisarmResult Disarm(IReadOnlyList<RemovalItem> items, Action<string>? report = null)
    {
        IReadOnlyList<Defence> found = Inspect(items);
        var actions = new List<string>();
        var failures = new List<string>();

        void Say(string message)
        {
            actions.Add(message);
            report?.Invoke(message);
        }

        // 1. Stop services coming back, then stop them.
        foreach (string service in found
                     .Where(static d => d.Kind is DefenceKind.ServiceRecovery or DefenceKind.ServiceAutostart)
                     .Select(static d => d.Subject)
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ControlResult disarmed = ProcessControl.DisableAutostart(service);
            if (disarmed.Succeeded) Say(disarmed.Message);
            else failures.Add(disarmed.Message);

            ControlResult stopped = ProcessControl.StopService(service);
            if (stopped.Succeeded) Say(stopped.Message);
            else failures.Add(stopped.Message);
        }

        // 2. Watchdog groups as groups, before anything is stopped individually.
        foreach (Defence watchdog in found.Where(static d => d.Kind == DefenceKind.WatchdogPair))
        {
            List<LiveProcess> group = SafeReadProcesses()
                .Where(p => p.Path is { Length: > 0 } path
                            && path.StartsWith(watchdog.Subject + "\\", StringComparison.OrdinalIgnoreCase))
                .ToList();

            // Deepest first so a parent cannot notice a child dying and act on it.
            foreach (LiveProcess process in group.OrderByDescending(static p => p.Pid))
            {
                if (process.IsCritical) continue;

                ControlResult result = ProcessControl.Stop(process.Pid, process.Name, force: true);
                if (result.Succeeded) Say(result.Message);
                else failures.Add(result.Message);
            }
        }

        // 3. Anything still running from a path being removed.
        foreach (Defence running in found.Where(static d => d.Kind == DefenceKind.RunningProcess))
        {
            uint pid = ParsePid(running.Subject);
            if (pid == 0) continue;

            ControlResult result = ProcessControl.StopTree(pid);
            if (result.Succeeded) Say(result.Message);
            else failures.Add(result.Message);
        }

        foreach (Defence blocked in found.Where(static d => !d.CanDisarm))
            failures.Add(blocked.Description);

        return new DisarmResult(found, actions, failures);
    }

    private static uint ParsePid(string subject)
    {
        int open = subject.LastIndexOf('(');
        int close = subject.LastIndexOf(')');
        return open >= 0 && close > open && uint.TryParse(subject[(open + 1)..close], out uint pid) ? pid : 0;
    }

    private static List<LiveProcess> SafeReadProcesses()
    {
        try { return LiveProcessTable.Read(detailed: false); }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return new List<LiveProcess>();
        }
    }
}
