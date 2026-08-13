using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;
using Microsoft.Win32;

namespace CaYaTrace.Remediation;

public enum ItemOutcome
{
    Pending = 0,
    NotPresent = 1,
    Removed = 2,
    SkippedByPolicy = 3,
    SkippedFingerprintMismatch = 4,
    SkippedByOperator = 5,
    Failed = 6,

    /// <summary>
    /// Handed to the session manager, which will move it before anything else starts.
    /// </summary>
    /// <remarks>
    /// Distinct from both <see cref="Removed"/> and <see cref="Failed"/> because it is
    /// neither: the file is still there, and it will not be after the next restart. An
    /// operator told "removed" would go looking for it and find it, and one told "failed"
    /// would try again for no reason.
    /// </remarks>
    PendingRestart = 7,
}

public sealed record ItemResult(
    RemovalItem Item,
    ItemOutcome Outcome,
    string Detail,
    string? QuarantinePath = null);

/// <summary>
/// Applies a removal package, or shows what applying it would do.
/// </summary>
/// <remarks>
/// <para>
/// Four properties are structural rather than optional, because this code runs on a
/// machine the operator may not be able to reimage:
/// </para>
/// <list type="number">
///   <item><description>
///     <b>Dry run is the default.</b> Producing the plan and applying it are separate
///     decisions, and the first never implies the second.
///   </description></item>
///   <item><description>
///     <b>Nothing is deleted.</b> Files move to a quarantine folder, registry keys are
///     exported to <c>.reg</c> before removal. Every destructive step is preceded by
///     capturing what it destroys.
///   </description></item>
///   <item><description>
///     <b>Identity is re-verified where the recording captured one.</b> An item whose live
///     fingerprint contradicts what was recorded is skipped and reported, never removed on
///     the strength of its path. Not every item carries a fingerprint — the program's own
///     binaries are recognised by having been loaded rather than by having been created, and
///     nothing hashed them — so for those the check reports that identity is unconfirmed and
///     the operator's approval of the list is what stands behind the removal.
///   </description></item>
///   <item><description>
///     <b>A rollback journal is written as it goes</b>, not at the end, so an
///     interrupted run is still reversible.
///   </description></item>
/// </list>
/// </remarks>
public sealed class RemediationRunner : IDisposable
{
    private readonly PathNormalizer _paths;
    private readonly SafetyPolicy _policy;
    private readonly string _quarantineRoot;
    private readonly bool _apply;
    private StreamWriter? _journal;

    /// <summary>
    /// Called for each item that policy permits but that needs a human decision.
    /// Returning false skips the item. The CLI supplies a prompt; the workbench
    /// supplies a checkbox list approved before the run starts.
    /// </summary>
    public Func<RemovalItem, FingerprintMatch, string, bool>? ConfirmationHandler { get; init; }

    /// <summary>
    /// Called as each item is dealt with, before moving to the next.
    /// </summary>
    /// <remarks>
    /// A removal is the one operation here that changes the operator's machine, and it
    /// used to run with no indication of where it had got to. That matters beyond
    /// comfort: when something goes wrong partway through, the difference between "it
    /// failed" and "it failed after moving these eleven files" is the difference between
    /// a recoverable situation and a guess.
    /// </remarks>
    public Action<RemediationProgress>? Progress { get; init; }

    /// <summary>
    /// How hard this run may try when something will not move.
    /// </summary>
    /// <remarks>
    /// Standard on the first pass. The escalation past naming the holder changes things
    /// the operator did not ask to change — a running process, a file's owner, the state
    /// of the machine until it next restarts — so it happens on a second pass they asked
    /// for, against the items the first pass could not finish.
    /// </remarks>
    public RemovalForce Force { get; init; } = RemovalForce.Standard;

    public RemediationRunner(string quarantineRoot, bool apply, PathNormalizer? paths = null)
    {
        _paths = paths ?? PathNormalizer.CreateForCurrentMachine();
        _policy = new SafetyPolicy(_paths);
        _quarantineRoot = quarantineRoot;
        _apply = apply;

        if (_apply)
        {
            Directory.CreateDirectory(_quarantineRoot);

            // Shared, and released when this runner is done with it.
            //
            // It used to be an exclusive handle held for the object's lifetime, which
            // made the second run against a quarantine folder throw before it had done
            // anything — and the second run is the one that retries what the first could
            // not finish, so the feature that needed it most was the one it broke.
            var stream = new FileStream(
                Path.Combine(_quarantineRoot, "rollback-journal.jsonl"),
                FileMode.Append, FileAccess.Write, FileShare.ReadWrite);

            _journal = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };
        }
    }

    /// <summary>Closes the rollback journal.</summary>
    public void Dispose()
    {
        _journal?.Dispose();
        _journal = null;
    }

    public List<ItemResult> Execute(IReadOnlyList<RemovalItem> items)
    {
        var results = new List<ItemResult>(items.Count);

        // Ordering matters for correctness, not just tidiness: a service must be
        // stopped before its binary can be moved, and a directory can only go once
        // its contents have.
        List<RemovalItem> ordered = items
            .OrderBy(static i => i.Order)
            .ThenByDescending(static i => i.Target.Length)
            .ToList();

        int index = 0;
        foreach (RemovalItem item in ordered)
        {
            index++;
            Progress?.Invoke(new RemediationProgress(
                index, ordered.Count, item.Kind, item.Target, null, null, item.ValueName, item));

            ItemResult result;
            try
            {
                result = Process(item);
            }
            catch (Exception ex)
            {
                result = new ItemResult(item, ItemOutcome.Failed, $"{ex.GetType().Name}: {ex.Message}");
            }

            results.Add(result);
            Progress?.Invoke(new RemediationProgress(
                index, ordered.Count, item.Kind, item.Target, result.Outcome, result.Detail, item.ValueName, item));
        }

        return results;
    }

    /// <summary>
    /// Disarms whatever would undo this removal, then runs it.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="Execute"/> so the plain path stays plain and so a caller
    /// can choose to look before acting. The disarming step stops services from restarting
    /// themselves, clears their autostart, and stops processes running from the paths
    /// about to be moved — in that order, because any other order lets the thing being
    /// removed put itself back while the removal is still running.
    /// </remarks>
    public (DisarmResult Disarmed, List<ItemResult> Results) ExecuteProtected(IReadOnlyList<RemovalItem> items)
    {
        var protection = new SelfProtection(_paths);

        DisarmResult disarmed = _apply
            ? protection.Disarm(items, message => Progress?.Invoke(
                new RemediationProgress(0, items.Count, null, message, null, null)))
            : new DisarmResult(protection.Inspect(items), Array.Empty<string>(), Array.Empty<string>());

        return (disarmed, Execute(items));
    }

    private ItemResult Process(RemovalItem item) => item.Kind switch
    {
        RemovalKind.File or RemovalKind.Directory => ProcessFileSystem(item),
        RemovalKind.RegistryValue => ProcessRegistryValue(item),
        RemovalKind.RegistryKey => ProcessRegistryKey(item),
        RemovalKind.Service => ProcessService(item),
        RemovalKind.ScheduledTask => ProcessScheduledTask(item),
        RemovalKind.AutorunEntry => ProcessRegistryValue(item),
        _ => new ItemResult(item, ItemOutcome.SkippedByPolicy,
            $"{item.Kind} removal is not implemented in this build"),
    };

    // ------------------------------------------------------------ file system

    private ItemResult ProcessFileSystem(RemovalItem item)
    {
        string path = _paths.Expand(item.Target);

        SafetyDecision decision = _policy.EvaluateFile(path, item.Created);
        if (decision.Verdict == SafetyVerdict.Forbidden)
            return new ItemResult(item, ItemOutcome.SkippedByPolicy, decision.Reason);

        bool isDirectory = Directory.Exists(path);
        bool isFile = File.Exists(path);

        if (!isDirectory && !isFile)
        {
            // The exact path is absent, but the artifact may be here under a different
            // run-specific name. This is the case a package built on one VM and applied
            // to another exists to handle.
            string? viaPattern = ResolveThroughPattern(item, decision);
            if (viaPattern is null)
                return new ItemResult(item, ItemOutcome.NotPresent, "not present on this machine");

            path = viaPattern;
            isDirectory = Directory.Exists(path);
            isFile = File.Exists(path);
        }

        FingerprintMatch match = FingerprintMatch.Unknown;
        if (isFile)
        {
            ArtifactFingerprint live = InspectFile(path);
            match = item.Fingerprint.Compare(live);

            if (match == FingerprintMatch.Conflict)
            {
                return new ItemResult(item, ItemOutcome.SkippedFingerprintMismatch,
                    $"a different file occupies this path (recorded {Short(item.Fingerprint.Sha256)}, " +
                    $"found {Short(live.Sha256)})");
            }

            SafetyDecision signerDecision = SafetyPolicy.EvaluateSigner(live.Signer, live.Signature);
            if (signerDecision.Verdict == SafetyVerdict.RequiresConfirmation && !Confirm(item, match, signerDecision.Reason))
                return new ItemResult(item, ItemOutcome.SkippedByOperator, signerDecision.Reason);
        }

        if (decision.Verdict == SafetyVerdict.RequiresConfirmation && !Confirm(item, match, decision.Reason))
            return new ItemResult(item, ItemOutcome.SkippedByOperator, decision.Reason);

        if (match is FingerprintMatch.Unknown or FingerprintMatch.Partial
            && !Confirm(item, match, "identity could not be confirmed against the recording"))
        {
            return new ItemResult(item, ItemOutcome.SkippedByOperator, "identity unconfirmed");
        }

        if (!_apply)
            return new ItemResult(item, ItemOutcome.Removed, $"would quarantine ({match.ToString().ToLowerInvariant()} match)");

        string destination = QuarantinePathFor(path);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

        if (isDirectory)
        {
            // A folder goes only when it is empty, which is the whole guarantee behind
            // listing a program's directory alongside its files: whatever the operator
            // decided to keep is still in there, and keeps the folder.
            try
            {
                if (Directory.EnumerateFileSystemEntries(path).Any())
                {
                    return new ItemResult(item, ItemOutcome.SkippedByPolicy,
                        Describe(path, "something in it was not part of this plan, or was kept"));
                }

                Directory.Move(path, destination);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return new ItemResult(item, ItemOutcome.Failed, ex.Message);
            }

            Journal("filesystem", item.Target, new { original = path, quarantined = destination, isDirectory = true });
            return new ItemResult(item, ItemOutcome.Removed, "moved to quarantine", destination);
        }

        (bool moved, string detail, bool deferred) = MoveWithEscalation(path, destination);

        if (!moved)
            return new ItemResult(item, ItemOutcome.Failed, detail);

        Journal("filesystem", item.Target, new { original = path, quarantined = destination, isDirectory = false });

        return deferred
            ? new ItemResult(item, ItemOutcome.PendingRestart, detail, destination)
            : new ItemResult(item, ItemOutcome.Removed, detail, destination);
    }

    /// <summary>
    /// Moves a file, and when it will not move, works out why and does something about it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The rungs are climbed in order of what they cost. The plain move costs nothing.
    /// Clearing read-only costs nothing that matters. Naming the holder costs nothing and
    /// is usually the answer on its own — an operator told "Explorer has it open" closes
    /// the preview pane, and nothing else was ever needed.
    /// </para>
    /// <para>
    /// Everything past that point costs something real and only happens when the operator
    /// asked for it: stopping a process ends whatever it was doing, taking ownership
    /// rewrites a permission, and scheduling the move for the next restart leaves the file
    /// in place until then. So the first pass stops at naming the holder and reports it,
    /// and the operator decides whether to try harder.
    /// </para>
    /// </remarks>
    private (bool Moved, string Detail, bool Deferred) MoveWithEscalation(string path, string destination)
    {
        var log = new List<string>();

        if (TryMove(path, destination, out string first)) return (true, "moved to quarantine", false);
        log.Add(first);

        RemovalAttempt attributes = StubbornFile.ClearAttributes(path);
        if (attributes.Succeeded)
        {
            log.Add($"cleared attributes ({attributes.Detail})");
            if (TryMove(path, destination, out _)) return (true, string.Join("; ", log), false);
        }

        IReadOnlyList<FileHolder> holders = StubbornFile.WhoIsHolding(path, out string lookup);

        if (holders.Count > 0)
            log.Add("held by " + string.Join(", ", holders.Select(static h => h.ToString())));
        else if (lookup.Length > 0)
            log.Add(lookup);
        else
            log.Add("nothing has it open");

        if (Force == RemovalForce.Standard)
        {
            log.Add(holders.Count > 0
                ? "close it and retry, or retry insisting"
                : "retry insisting to take ownership and finish at the next restart");

            return (false, string.Join("; ", log), false);
        }

        if (holders.Count > 0)
        {
            RemovalAttempt stopped = StubbornFile.StopHolders(holders);
            log.Add(stopped.Detail);
            if (stopped.Succeeded && TryMove(path, destination, out _))
                return (true, string.Join("; ", log), false);
        }

        RemovalAttempt owned = StubbornFile.TakeOwnership(path);
        log.Add(owned.Succeeded ? "took ownership" : $"ownership: {owned.Detail}");
        if (owned.Succeeded && TryMove(path, destination, out _))
            return (true, string.Join("; ", log), false);

        RemovalAttempt scheduled = StubbornFile.ScheduleForRestart(path, destination);
        log.Add(scheduled.Detail);

        return (scheduled.Succeeded, string.Join("; ", log), scheduled.Succeeded);
    }

    private static bool TryMove(string path, string destination, out string why)
    {
        try
        {
            File.Move(path, destination, overwrite: false);
            why = string.Empty;
            return true;
        }
        catch (IOException ex)
        {
            why = $"in use or locked: {ex.Message}";
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            why = $"access denied: {ex.Message}";
            return false;
        }
    }

    private static string Describe(string path, string why)
    {
        try
        {
            string[] left = Directory.GetFileSystemEntries(path);
            string sample = string.Join(", ", left.Take(4).Select(Path.GetFileName));
            string more = left.Length > 4 ? $" and {left.Length - 4} more" : string.Empty;
            return $"{left.Length} still in it ({sample}{more}) — {why}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return why;
        }
    }

    /// <summary>
    /// Finds an artifact that is present under a different run-specific name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Gated hard, because widening what a removal matches is exactly how an
    /// uninstaller starts deleting things it was never shown. Four conditions must all
    /// hold before a pattern match is even offered:
    /// </para>
    /// <list type="number">
    ///   <item><description>The item carries a pattern with a variable slot.</description></item>
    ///   <item><description>Expansion finds exactly one candidate. Several means the
    ///   pattern is too loose to act on, and guessing between them is worse than
    ///   reporting the item as absent.</description></item>
    ///   <item><description>The candidate's fingerprint matches what was recorded.
    ///   A path shaped like the artifact is not the artifact.</description></item>
    ///   <item><description>The operator confirms — always, and regardless of whether
    ///   the pattern was measured or guessed.</description></item>
    /// </list>
    /// </remarks>
    private string? ResolveThroughPattern(RemovalItem item, SafetyDecision decision)
    {
        if (item.TargetPattern is not { Length: > 0 }) return null;

        Analysis.PathTemplate template = Analysis.PathTemplater.Infer(item.TargetPattern);
        if (!item.TargetPattern.Contains("{*}", StringComparison.Ordinal)) return null;

        // Rebuild the template from the stored pattern so the variable slots are the
        // ones the package recorded, not ones re-guessed here.
        var segments = item.TargetPattern
            .Split('\\', StringSplitOptions.RemoveEmptyEntries)
            .Select(static s => s == "{*}"
                ? new Analysis.PathSegment(s, Analysis.SegmentKind.Variable)
                : new Analysis.PathSegment(s, Analysis.SegmentKind.Literal))
            .ToList();

        template = new Analysis.PathTemplate(segments, item.PatternEvidence);

        IReadOnlyList<string> candidates = Analysis.PathTemplater.Expand(template, _paths);
        if (candidates.Count != 1) return null;

        string candidate = candidates[0];

        if (_policy.EvaluateFile(candidate).Verdict == SafetyVerdict.Forbidden) return null;

        // The fingerprint check is what separates "the same artifact under another
        // name" from "an unrelated file in a similarly shaped path".
        if (File.Exists(candidate))
        {
            ArtifactFingerprint live = InspectFile(candidate);
            if (item.Fingerprint.Compare(live) != FingerprintMatch.Exact) return null;
        }
        else if (item.Fingerprint.Sha256 is { Length: > 0 })
        {
            // A file was recorded but a directory is present. Not the same thing.
            return null;
        }

        string reason =
            $"not at the recorded path, but {candidate} matches the pattern {item.TargetPattern} " +
            $"({item.PatternEvidence.ToString().ToLowerInvariant()}) and its contents match the recording";

        _ = decision;
        return Confirm(item, FingerprintMatch.Exact, reason) ? candidate : null;
    }

    // -------------------------------------------------------------- registry

    private ItemResult ProcessRegistryValue(RemovalItem item)
    {
        // The target is split first, whatever ValueName says.
        //
        // Autorun entries arrive from the snapshot differ as "key::value" *and* carry a
        // ValueName, and taking the ValueName branch left the "::value" suffix inside
        // the key path. OpenSubKey then returned null and the item was reported as "key
        // not present on this machine" — a wrong answer that happens to be safe, which
        // is the kind that survives to a release.
        (string splitKey, string? splitValue) = RegistryPath.SplitValue(item.Target);
        (string keyPath, string? valueName) = splitValue is not null
            ? (splitKey, splitValue)
            : (item.Target, item.ValueName);

        SafetyDecision decision = _policy.EvaluateRegistryValue(keyPath, valueName);
        if (decision.Verdict == SafetyVerdict.Forbidden)
            return new ItemResult(item, ItemOutcome.SkippedByPolicy, decision.Reason);

        (RegistryHive? hive, string subKey) = SplitHive(keyPath);
        if (hive is null)
            return new ItemResult(item, ItemOutcome.SkippedByPolicy, $"unrecognised registry hive in {keyPath}");

        using RegistryKey root = RegistryKey.OpenBaseKey(hive.Value, RegistryView.Registry64);
        using RegistryKey? key = root.OpenSubKey(subKey, writable: _apply);
        if (key is null)
            return new ItemResult(item, ItemOutcome.NotPresent, "key not present on this machine");

        object? current = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (current is null)
            return new ItemResult(item, ItemOutcome.NotPresent, "value not present on this machine");

        var live = new ArtifactFingerprint { ValueData = current.ToString() };
        FingerprintMatch match = item.Fingerprint.Compare(live);

        if (match == FingerprintMatch.Conflict)
        {
            return new ItemResult(item, ItemOutcome.SkippedFingerprintMismatch,
                $"value holds different data than recorded (recorded '{Short(item.Fingerprint.ValueData)}', " +
                $"found '{Short(live.ValueData)}')");
        }

        if (decision.Verdict == SafetyVerdict.RequiresConfirmation && !Confirm(item, match, decision.Reason))
            return new ItemResult(item, ItemOutcome.SkippedByOperator, decision.Reason);

        if (!_apply)
            return new ItemResult(item, ItemOutcome.Removed, $"would delete value ({match.ToString().ToLowerInvariant()} match)");

        // The .reg export happens before the delete, so an interrupted run still
        // leaves the operator able to put the value back.
        string backup = ExportRegistryValue(keyPath, valueName, current, key.GetValueKind(valueName));

        try
        {
            key.DeleteValue(valueName ?? string.Empty, throwOnMissingValue: false);
        }
        catch (UnauthorizedAccessException ex)
        {
            return new ItemResult(item, ItemOutcome.Failed, $"access denied: {ex.Message}");
        }

        Journal("registry-value", item.Target, new { keyPath, valueName, backup });
        return new ItemResult(item, ItemOutcome.Removed, "value deleted; previous data exported", backup);
    }

    private ItemResult ProcessRegistryKey(RemovalItem item)
    {
        SafetyDecision decision = _policy.EvaluateRegistryKey(item.Target);
        if (decision.Verdict == SafetyVerdict.Forbidden)
            return new ItemResult(item, ItemOutcome.SkippedByPolicy, decision.Reason);

        (RegistryHive? hive, string subKey) = SplitHive(item.Target);
        if (hive is null)
            return new ItemResult(item, ItemOutcome.SkippedByPolicy, $"unrecognised registry hive in {item.Target}");

        using RegistryKey root = RegistryKey.OpenBaseKey(hive.Value, RegistryView.Registry64);
        using (RegistryKey? probe = root.OpenSubKey(subKey, writable: false))
        {
            if (probe is null)
                return new ItemResult(item, ItemOutcome.NotPresent, "key not present on this machine");
        }

        if (decision.Verdict == SafetyVerdict.RequiresConfirmation
            && !Confirm(item, FingerprintMatch.Unknown, decision.Reason))
        {
            return new ItemResult(item, ItemOutcome.SkippedByOperator, decision.Reason);
        }

        if (!_apply)
            return new ItemResult(item, ItemOutcome.Removed, "would delete key and its subtree");

        string backup = ExportRegistrySubtree(hive.Value, subKey, item.Target);

        try
        {
            root.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
        }
        catch (UnauthorizedAccessException ex)
        {
            return new ItemResult(item, ItemOutcome.Failed, $"access denied: {ex.Message}");
        }

        Journal("registry-key", item.Target, new { backup });
        return new ItemResult(item, ItemOutcome.Removed, "key deleted; subtree exported", backup);
    }

    // --------------------------------------------------------------- service

    private ItemResult ProcessService(RemovalItem item)
    {
        string serviceName = item.Target;

        SafetyDecision decision = _policy.EvaluateService(serviceName);
        if (decision.Verdict == SafetyVerdict.Forbidden)
            return new ItemResult(item, ItemOutcome.SkippedByPolicy, decision.Reason);

        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: false);

        if (key is null)
            return new ItemResult(item, ItemOutcome.NotPresent, "service not registered on this machine");

        string? imagePath = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        var live = new ArtifactFingerprint { CommandLine = imagePath };
        FingerprintMatch match = item.Fingerprint.Compare(live);

        if (match == FingerprintMatch.Conflict)
        {
            return new ItemResult(item, ItemOutcome.SkippedFingerprintMismatch,
                $"a different service occupies this name (recorded '{Short(item.Fingerprint.CommandLine)}', " +
                $"found '{Short(imagePath)}')");
        }

        if (!_apply)
            return new ItemResult(item, ItemOutcome.Removed, $"would stop and unregister ({match.ToString().ToLowerInvariant()} match)");

        string backup = ExportRegistrySubtree(
            RegistryHive.LocalMachine,
            $@"SYSTEM\CurrentControlSet\Services\{serviceName}",
            $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}");

        string stopDetail = StopService(serviceName);

        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}", throwOnMissingSubKey: false);
        }
        catch (UnauthorizedAccessException ex)
        {
            return new ItemResult(item, ItemOutcome.Failed, $"access denied unregistering service: {ex.Message}");
        }

        Journal("service", serviceName, new { backup, imagePath });
        return new ItemResult(item, ItemOutcome.Removed, $"{stopDetail}; registration exported and removed", backup);
    }

    private static string StopService(string name)
    {
        try
        {
            using var controller = new System.ServiceProcess.ServiceController(name);
            if (controller.Status == System.ServiceProcess.ServiceControllerStatus.Stopped)
                return "already stopped";

            if (!controller.CanStop) return "could not be stopped (service reports it does not accept stop)";

            controller.Stop();
            controller.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            return "stopped";
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception
                                       or System.ServiceProcess.TimeoutException)
        {
            // The service may not be running, may already be marked for deletion, or
            // may be wedged. Removing the registration is still the right next step.
            return $"stop attempt inconclusive ({ex.GetType().Name})";
        }
    }

    // -------------------------------------------------------- scheduled task

    private ItemResult ProcessScheduledTask(RemovalItem item)
    {
        SafetyDecision decision = _policy.EvaluateScheduledTask(item.Target);
        if (decision.Verdict == SafetyVerdict.Forbidden)
            return new ItemResult(item, ItemOutcome.SkippedByPolicy, decision.Reason);

        string relative = item.Target.TrimStart('\\');
        string taskFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks", relative);

        if (!File.Exists(taskFile))
            return new ItemResult(item, ItemOutcome.NotPresent, "task not registered on this machine");

        if (!_apply)
            return new ItemResult(item, ItemOutcome.Removed, "would unregister the task");

        // The definition is preserved before the task is unregistered, so it can be
        // re-imported with schtasks /create /xml if the removal turns out to be wrong.
        string backup = Path.Combine(_quarantineRoot, "tasks", relative + ".xml");
        Directory.CreateDirectory(Path.GetDirectoryName(backup)!);

        try
        {
            File.Copy(taskFile, backup, overwrite: true);
            File.Delete(taskFile);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new ItemResult(item, ItemOutcome.Failed, $"could not remove task file: {ex.Message}");
        }

        // The Task Scheduler also keeps registration state in the registry; leaving it
        // behind produces a phantom task entry in the UI.
        RemoveTaskRegistryTrace(relative);

        Journal("scheduled-task", item.Target, new { taskFile, backup });
        return new ItemResult(item, ItemOutcome.Removed, "task unregistered; definition preserved", backup);
    }

    private static void RemoveTaskRegistryTrace(string relativePath)
    {
        try
        {
            using RegistryKey? tree = Registry.LocalMachine.OpenSubKey(
                $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{relativePath}",
                writable: false);
            if (tree?.GetValue("Id") is not string id) return;

            Registry.LocalMachine.DeleteSubKeyTree(
                $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{relativePath}", false);
            Registry.LocalMachine.DeleteSubKeyTree(
                $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{id}", false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            // The task file is gone, which is the part that matters. A leftover cache
            // entry is cosmetic and is reported by the residue scan.
        }
    }

    // ---------------------------------------------------------------- helpers

    private bool Confirm(RemovalItem item, FingerprintMatch match, string reason)
        => ConfirmationHandler?.Invoke(item, match, reason) ?? false;

    private string QuarantinePathFor(string original)
    {
        // Preserve enough of the original layout that an operator can tell quarantined
        // items apart, while flattening the drive letter so the tree stays valid.
        string relative = original.Replace(":", string.Empty, StringComparison.Ordinal).TrimStart('\\');
        string candidate = Path.Combine(_quarantineRoot, "files", relative);

        int suffix = 1;
        while (File.Exists(candidate) || Directory.Exists(candidate))
            candidate = Path.Combine(_quarantineRoot, "files", relative + $".{suffix++}");

        return candidate;
    }

    private static ArtifactFingerprint InspectFile(string path)
    {
        try
        {
            var info = new FileInfo(path);
            string? sha = null;

            if (info.Length <= 256L * 1024 * 1024)
            {
                using FileStream fs = File.OpenRead(path);
                sha = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
            }

            string? signer = null;
            SignatureState state = SignatureState.Unchecked;
            try
            {
                using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path));
                signer = cert.GetNameInfo(
                    System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, forIssuer: false);
                state = SignatureState.SignedValid;
            }
            catch (CryptographicException)
            {
                state = SignatureState.Unsigned;
            }

            return new ArtifactFingerprint { Sha256 = sha, Size = info.Length, Signer = signer, Signature = state };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new ArtifactFingerprint();
        }
    }

    private string ExportRegistryValue(string keyPath, string? valueName, object data, RegistryValueKind kind)
    {
        string safeName = Sanitize($"{keyPath}__{valueName ?? "default"}");
        string file = Path.Combine(_quarantineRoot, "registry", safeName + ".reg");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);

        var sb = new StringBuilder();
        sb.AppendLine("Windows Registry Editor Version 5.00");
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"[{RegistryPath.ToLongForm(keyPath)}]");
        sb.AppendLine(FormatRegValue(valueName, data, kind));

        File.WriteAllText(file, sb.ToString(), new UTF8Encoding(false));
        return file;
    }

    private string ExportRegistrySubtree(RegistryHive hive, string subKey, string displayPath)
    {
        string file = Path.Combine(_quarantineRoot, "registry", Sanitize(displayPath) + ".reg");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);

        var sb = new StringBuilder();
        sb.AppendLine("Windows Registry Editor Version 5.00");
        sb.AppendLine();

        using RegistryKey root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        ExportRecursive(root, subKey, RegistryPath.ToLongForm(displayPath), sb, depth: 0);

        File.WriteAllText(file, sb.ToString(), new UTF8Encoding(false));
        return file;
    }

    private static void ExportRecursive(RegistryKey root, string subKey, string displayPath, StringBuilder sb, int depth)
    {
        // Bounded: a malformed or hostile key tree should not turn the backup step
        // into an unbounded recursion.
        if (depth > 32) return;

        RegistryKey? key;
        try { key = root.OpenSubKey(subKey, writable: false); }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return;
        }

        if (key is null) return;

        using (key)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"[{displayPath}]");

            foreach (string name in key.GetValueNames())
            {
                try
                {
                    object? data = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (data is not null) sb.AppendLine(FormatRegValue(name, data, key.GetValueKind(name)));
                }
                catch (Exception ex) when (ex is System.Security.SecurityException or IOException) { }
            }

            sb.AppendLine();

            foreach (string child in key.GetSubKeyNames())
                ExportRecursive(root, $@"{subKey}\{child}", $@"{displayPath}\{child}", sb, depth + 1);
        }
    }

    private static string FormatRegValue(string? name, object data, RegistryValueKind kind)
    {
        string key = string.IsNullOrEmpty(name) ? "@" : $"\"{Escape(name)}\"";

        return kind switch
        {
            RegistryValueKind.String => $"{key}=\"{Escape(data.ToString() ?? string.Empty)}\"",
            RegistryValueKind.ExpandString => $"{key}=hex(2):{HexBytes(Encoding.Unicode.GetBytes((data.ToString() ?? string.Empty) + "\0"))}",
            RegistryValueKind.MultiString when data is string[] items =>
                $"{key}=hex(7):{HexBytes(Encoding.Unicode.GetBytes(string.Join('\0', items) + "\0\0"))}",
            RegistryValueKind.DWord => $"{key}=dword:{Convert.ToUInt32(data, CultureInfo.InvariantCulture):x8}",
            RegistryValueKind.QWord => $"{key}=hex(b):{HexBytes(BitConverter.GetBytes(Convert.ToUInt64(data, CultureInfo.InvariantCulture)))}",
            RegistryValueKind.Binary when data is byte[] bytes => $"{key}=hex:{HexBytes(bytes)}",
            _ => $"{key}=\"{Escape(data.ToString() ?? string.Empty)}\"",
        };
    }

    private static string HexBytes(byte[] bytes)
        => string.Join(",", bytes.Select(static b => b.ToString("x2", CultureInfo.InvariantCulture)));

    private static string Escape(string value)
        => value.Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("\"", "\\\"", StringComparison.Ordinal);

    private static string Sanitize(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
            sb.Append(Path.GetInvalidFileNameChars().Contains(c) ? '_' : c);
        return sb.Length > 120 ? sb.ToString(0, 120) : sb.ToString();
    }

    private static (RegistryHive?, string) SplitHive(string path)
    {
        (string hive, string subKey) = RegistryPath.Split(RegistryPath.Normalize(path));
        RegistryHive? mapped = hive.ToUpperInvariant() switch
        {
            "HKLM" => RegistryHive.LocalMachine,
            "HKCU" => RegistryHive.CurrentUser,
            "HKCR" => RegistryHive.ClassesRoot,
            "HKU" => RegistryHive.Users,
            "HKCC" => RegistryHive.CurrentConfig,
            _ => null,
        };
        return (mapped, subKey);
    }

    private void Journal(string kind, string target, object payload)
    {
        _journal?.WriteLine(JsonSerializer.Serialize(new
        {
            at = DateTimeOffset.UtcNow,
            kind,
            target,
            payload,
        }));
    }

    private static string Short(string? value)
        => value is null ? "(none)" : value.Length <= 32 ? value : value[..32] + "…";

    /// <summary>CLI entry point: read a package, plan or apply it, and report.</summary>
    public static int Run(string packagePath, string quarantineRoot, bool apply)
    {
        (PackageManifest manifest, List<RemovalItem> items, bool integrityOk) = RemovalPackage.Read(packagePath);

        Console.WriteLine($"package   {manifest.PackageId}");
        Console.WriteLine($"subject   {manifest.SubjectName}");
        Console.WriteLine($"created   {manifest.CreatedAt:u} by CaYaTrace {manifest.ToolVersion}");
        Console.WriteLine($"items     {items.Count}");
        Console.WriteLine($"origins   {string.Join(", ", manifest.Origins.Select(static o => $"{o.MachineName} ({o.OsBuild})"))}");

        if (!integrityOk)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("REFUSING TO PROCEED: the plan does not match the hash recorded in the manifest.");
            Console.Error.WriteLine("The package was modified or damaged after it was created.");
            return 5;
        }

        if (apply && !IsElevated())
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("Removal needs administrator rights. Re-run from an elevated prompt.");
            return 6;
        }

        Console.WriteLine();
        Console.WriteLine(apply
            ? $"APPLYING — items move to {Path.GetFullPath(quarantineRoot)}, nothing is deleted outright."
            : "DRY RUN — nothing will be changed. Add --apply to perform the removal.");
        Console.WriteLine();

        // Registry items name a value under a key, and printing only the key made two
        // different values look like the same line twice.
        static string Name(RemovalItem item)
            => item.ValueName is { Length: > 0 } && !item.Target.Contains("::", StringComparison.Ordinal)
                ? $"{item.Target}::{item.ValueName}"
                : item.Target;

        var runner = new RemediationRunner(quarantineRoot, apply)
        {
            ConfirmationHandler = (item, match, reason) =>
            {
                if (!apply)
                {
                    Console.WriteLine($"  ? {item.Kind} {Name(item)}");
                    Console.WriteLine($"      needs confirmation: {reason}");
                    return true;   // dry run reports what would be asked
                }

                Console.WriteLine();
                Console.WriteLine($"  {item.Kind}: {Name(item)}");
                Console.WriteLine($"  rationale: {item.Rationale}");
                Console.WriteLine($"  match:     {match}");
                Console.WriteLine($"  caution:   {reason}");
                Console.Write("  remove it? [y/N] ");
                string? answer = Console.ReadLine();
                return answer?.Trim().StartsWith('y') == true;
            },
        };

        List<ItemResult> results = runner.Execute(items);

        Console.WriteLine();
        foreach (IGrouping<ItemOutcome, ItemResult> group in results.GroupBy(static r => r.Outcome).OrderBy(static g => g.Key))
        {
            Console.WriteLine($"{group.Key} ({group.Count()})");
            foreach (ItemResult r in group.Take(200))
                Console.WriteLine($"  {r.Item.Kind,-16} {Name(r.Item)}   — {r.Detail}");
            if (group.Count() > 200) Console.WriteLine($"  … {group.Count() - 200} more");
            Console.WriteLine();
        }

        int failed = results.Count(static r => r.Outcome == ItemOutcome.Failed);
        int mismatched = results.Count(static r => r.Outcome == ItemOutcome.SkippedFingerprintMismatch);

        if (mismatched > 0)
        {
            Console.WriteLine($"{mismatched} item(s) were left alone because what is on this machine does not");
            Console.WriteLine("match what was recorded. Review them before forcing anything.");
        }

        if (apply)
        {
            Console.WriteLine($"Quarantine and rollback journal: {Path.GetFullPath(quarantineRoot)}");
            Console.WriteLine("Nothing was deleted. Verify the machine, then remove the quarantine folder yourself.");
        }

        return failed > 0 ? 7 : 0;
    }

    private static bool IsElevated()
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
}
