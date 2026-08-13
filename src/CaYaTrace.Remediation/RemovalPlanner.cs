using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;
using CaYaTrace.Storage;

namespace CaYaTrace.Remediation;

public sealed class RemovalPlannerOptions
{
    /// <summary>
    /// Only include artifacts created by processes inside the observed tree. Off means
    /// every persistent change in the session becomes a candidate, which is right for
    /// a system-wide recording and wrong for a targeted install.
    /// </summary>
    public bool ScopedOnly { get; init; } = true;

    /// <summary>
    /// Include files that were written but not created. A program that appends to a
    /// shared log has not taken ownership of it, and removing it would be wrong.
    /// </summary>
    public bool IncludeModifiedFiles { get; init; }

    /// <summary>
    /// Drop artifacts under temp directories. They are usually installer scratch that
    /// Windows clears anyway, and including them bloats the plan.
    /// </summary>
    public bool ExcludeTemporary { get; init; } = true;

    /// <summary>
    /// Require an artifact to have been seen on at least this many machines. Above 1
    /// this filters out per-machine randomness during multi-VM analysis.
    /// </summary>
    public int MinimumOriginAgreement { get; init; } = 1;

    public static RemovalPlannerOptions Default { get; } = new();
}

/// <summary>
/// Turns a recorded session into a proposed removal plan.
/// </summary>
/// <remarks>
/// <para>
/// The planner is conservative on purpose. It proposes only artifacts the subject
/// <em>brought into existence</em> — files it created, keys it added, services it
/// registered — and never things it merely touched. A program that opened a shared
/// configuration file, wrote to an existing log, or read a registry key has not taken
/// ownership of it, and a plan that says otherwise damages the machine while claiming
/// to clean it.
/// </para>
/// <para>
/// Everything it produces is a <em>proposal</em>. <see cref="RemediationRunner"/> re-checks
/// each item against the machine it runs on, and the operator approves before anything
/// moves.
/// </para>
/// </remarks>
public sealed class RemovalPlanner
{
    private readonly SessionStore _store;
    private readonly PathNormalizer _paths;
    private readonly RemovalPlannerOptions _options;

    public RemovalPlanner(SessionStore store, PathNormalizer? paths = null, RemovalPlannerOptions? options = null)
    {
        _store = store;
        _paths = paths ?? PathNormalizer.CreateForCurrentMachine();
        _options = options ?? RemovalPlannerOptions.Default;
    }

    /// <summary>One thing the plan deliberately left out, and why.</summary>
    public readonly record struct ExcludedItem(RemovalKind Kind, string Target, string Reason);

    /// <summary>
    /// What the last <see cref="Build"/> refused to make a candidate.
    /// </summary>
    /// <remarks>
    /// Kept so the count can be shown without the rows. An operator comparing the plan
    /// against their machine needs to know the difference between something the tool never
    /// found and something it declined to touch — but they need it as one line, not as a
    /// hundred rows of Windows' own registry keys.
    /// </remarks>
    public List<ExcludedItem> Excluded { get; } = new();

    /// <summary>
    /// What the last <see cref="Build"/> decided the program itself consists of.
    /// </summary>
    /// <remarks>
    /// Exposed so the loader search probes it rejected can be inspected. The rule that
    /// separates a component from a probe is the difference between a plan that names the
    /// program's executable and one that offers to delete <c>cmd.exe</c>, and a rule that
    /// important should be checkable against a real recording.
    /// </remarks>
    public SubjectFootprint Footprint { get; private set; } = new();

    public List<RemovalItem> Build(SessionInfo session)
    {
        Excluded.Clear();

        Dictionary<ProcessKey, ProcessNode> processes = _store.LoadProcesses().ToDictionary(static p => p.Key);

        var byTarget = new Dictionary<string, RemovalItem>(StringComparer.OrdinalIgnoreCase);
        var originsByTarget = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        // Deletions cancel creations: a file the installer wrote and then removed
        // itself is not a residue and must not appear in the plan.
        var deleted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Observation o in _store.Query(new ObservationQuery()))
        {
            if (o.Action is EventAction.FileDelete or EventAction.DirectoryDelete)
                deleted.Add(o.Target);
            if (o.Action is EventAction.KeyDelete)
                deleted.Add(o.Target);
        }

        foreach (Observation o in _store.Query(new ObservationQuery { PersistentChangesOnly = true }))
        {
            if (_options.ScopedOnly && !IsDelegated(o) && !IsInScope(o, processes, session)) continue;

            RemovalItem? item = Translate(o, processes);
            if (item is null) continue;
            if (deleted.Contains(item.Target)) continue;
            if (_options.ExcludeTemporary && IsTemporary(item.Target)) continue;

            // A startup entry and a registry value under the same key are the same
            // deletion, so they share a key and collapse into one item.
            RemovalKind folded = item.Kind == RemovalKind.AutorunEntry ? RemovalKind.RegistryValue : item.Kind;
            string key = $"{folded}|{item.Target}|{item.ValueName}";

            if (!originsByTarget.TryGetValue(key, out HashSet<string>? origins))
            {
                origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                originsByTarget[key] = origins;
            }
            origins.Add(o.OriginId ?? session.Machine.MachineId);

            if (byTarget.TryGetValue(key, out RemovalItem? existing))
            {
                if (existing.Evidence.Count < 64) existing.Evidence.Add(o.Seq);
                continue;
            }

            byTarget[key] = item;
        }

        // The safety policy is applied here, at plan time, not only at apply time.
        //
        // A plan is a document an operator reads and approves, and one that lists items
        // the runner will silently refuse is a document that describes something other
        // than what will happen. It also drowns the real findings: a 30-second recording
        // of an installer produced 141 items, of which 119 were registry keys Windows
        // wrote because the program had run at all.
        var policy = new SafetyPolicy(_paths);

        var plan = new List<RemovalItem>();
        foreach ((string key, RemovalItem item) in byTarget)
        {
            HashSet<string> origins = originsByTarget[key];
            if (origins.Count < _options.MinimumOriginAgreement) continue;

            SafetyDecision decision = policy.Evaluate(item);

            // Something the runner will never touch is not a candidate, and listing it as
            // one was a mistake I made trying to fix a different complaint.
            //
            // The reasoning was that a refusal should be visible rather than silent. It
            // should — but not as a row in the plan. A recording of one program produced
            // 107 registry keys under SystemCertificates, every one of them Windows'
            // own, every one of them reading "protected — will not be touched". That is
            // not transparency, it is the real findings buried under a hundred rows the
            // operator cannot act on and did not ask about.
            //
            // They are counted and reported instead, so the number is available without
            // the noise.
            if (decision.Verdict == SafetyVerdict.Forbidden)
            {
                Excluded.Add(new ExcludedItem(item.Kind, item.Target, decision.Reason));
                continue;
            }

            item.ObservedOn.AddRange(origins);
            plan.Add(AttachTemplate(item));
        }

        AddSubjectFootprint(session, processes, plan, policy);

        plan = SeparateDirectoriesFromFiles(plan);

        return plan.OrderBy(static i => i.Order).ThenBy(static i => i.Target, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Re-types the entries that turned out to be folders.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The kernel reports a directory being made as a <em>file</em> create — a directory
    /// is a file with a flag set — so a program that unpacks itself into a new folder
    /// produces one create for the folder and one for each thing in it, all identical in
    /// shape. The plan then listed the folder as a file, which reads wrong and, worse,
    /// orders wrong: files are removed before folders precisely so a folder is empty by
    /// the time its turn comes, and a folder disguised as a file loses that.
    /// </para>
    /// <para>
    /// Which ones are folders can be read straight off the evidence rather than off the
    /// disk: anything that other recorded paths sit inside is a folder. That answer is the
    /// same on the machine that recorded the session and on the machine that applies the
    /// plan, which a disk check would not be — by then the folder may be gone, or may
    /// never have existed there.
    /// </para>
    /// </remarks>
    private static List<RemovalItem> SeparateDirectoriesFromFiles(List<RemovalItem> plan)
    {
        var paths = new HashSet<string>(
            plan.Where(static i => i.Kind is RemovalKind.File or RemovalKind.Directory)
                .Select(static i => i.Target.TrimEnd('\\')),
            StringComparer.OrdinalIgnoreCase);

        var parents = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string path in paths)
        {
            for (int cut = path.LastIndexOf('\\'); cut > 0; cut = path.LastIndexOf('\\', cut - 1))
            {
                string parent = path[..cut];
                if (paths.Contains(parent)) parents.Add(parent);
            }
        }

        if (parents.Count == 0) return plan;

        return plan
            .Select(item => item.Kind == RemovalKind.File && parents.Contains(item.Target.TrimEnd('\\'))
                ? item with { Kind = RemovalKind.Directory }
                : item)
            .ToList();
    }

    /// <summary>
    /// Adds the program itself: its binaries, and the files sitting beside them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything above this comes from watching the recording, so it can only ever
    /// contain what the subject <em>created while being watched</em>. That misses the
    /// program itself. A subject is normally downloaded, unpacked and then recorded, so
    /// its own executable and the folder it unpacked into already existed when the
    /// recording started and no event ever names them as created.
    /// </para>
    /// <para>
    /// The result was a plan that removed a program's registry footprint and left the
    /// program on disk. Measured, on a recording of one: two registry values, and not one
    /// of the executables that had done all the work.
    /// </para>
    /// <para>
    /// Removing a program means removing the program. The subject's image, every image its
    /// process tree ran, and the contents of the directory those sit in are candidates
    /// whether or not the recording watched them appear — which is the same thing a
    /// dedicated uninstaller does when it is pointed at an installation directory.
    /// </para>
    /// <para>
    /// <b>Listed file by file.</b> The directory itself is only offered when everything in
    /// it belongs to the program, because a folder is a container and a container can hold
    /// something the operator wants: a subject unpacked into Downloads must never take
    /// Downloads with it, and one unpacked into its own folder should take the folder.
    /// </para>
    /// </remarks>
    private void AddSubjectFootprint(
        SessionInfo session,
        Dictionary<ProcessKey, ProcessNode> processes,
        List<RemovalItem> plan,
        SafetyPolicy policy)
    {
        Footprint = SubjectFootprint.Collect(_store, session, _paths, processes);

        var known = new HashSet<string>(
            plan.Select(static i => $"{i.Kind}|{i.Target}"), StringComparer.OrdinalIgnoreCase);

        foreach (SubjectFootprint.Component part in Footprint.Components)
            Offer(RemovalKind.File, part.Path, part.Why, part.Evidence, part.Created);

        // A process image is still worth having when the process table resolved one: a
        // program that spawned a helper out of a second directory is named there and
        // nowhere else.
        foreach (ProcessNode node in processes.Values)
        {
            if (node.ImagePath is not { Length: > 0 } image) continue;

            // A name is not a path. The process table holds a bare image name whenever the
            // full path was never resolved, and "cmd.exe" passes every check written to
            // recognise a system location — so cmd.exe and conhost.exe arrived in the plan
            // as things to delete, which is a machine lost rather than a program removed.
            if (!image.Contains('\\', StringComparison.Ordinal)) continue;

            // Never something Windows signed, in either kind of recording. A program that
            // launches cmd.exe has not made cmd.exe its own, and being inside the
            // subject's process tree does not transfer ownership of the binary.
            if (node.IsMicrosoftSigned()) continue;
            if (session.RootProcess != ProcessKey.None && !node.InScope) continue;
            if (_paths.IsSystemPath(image)) continue;

            Offer(RemovalKind.File, _paths.Tokenize(image), "the program's own executable", 0, false);
        }

        // The directory last, and only when the program's own file is in it.
        //
        // Offering it is safe because the runner refuses to move a directory that still
        // has anything in it: everything the operator kept holds the folder open, and the
        // folder only goes when nothing of theirs is left. That is the behaviour asked
        // for — file by file, and the folder as well when the folder was the program's.
        if (Footprint.Directory is { Length: > 0 } home
            && !Footprint.DirectoryIsShared
            && !IsWellKnownFolder(home)
            && !_paths.IsSystemPath(home))
        {
            Offer(RemovalKind.Directory, home,
                "the directory the program ran from; removed only once everything in it has been", 0, false);
        }

        void Offer(RemovalKind kind, string token, string why, long evidence, bool created)
        {
            if (!known.Add($"{kind}|{token}")) return;

            var item = new RemovalItem { Kind = kind, Target = token, Rationale = why, Created = created };
            if (evidence > 0) item.Evidence.Add(evidence);

            SafetyDecision decision = policy.Evaluate(item);
            if (decision.Verdict == SafetyVerdict.Forbidden)
            {
                Excluded.Add(new ExcludedItem(kind, token, decision.Reason));
                return;
            }

            plan.Add(item);
        }
    }

    /// <summary>
    /// Marks run-specific path segments so the item can still be found on a machine
    /// where the program chose different random names.
    /// </summary>
    /// <remarks>
    /// Only file-system items get one — a registry path's variability is a different
    /// problem with different rules. From a single session the variables can only be
    /// inferred, so the template is recorded as a guess and the runner treats it as
    /// one: it is consulted only when the exact path is absent, and never acts without
    /// a fingerprint match and an explicit confirmation.
    /// </remarks>
    private static RemovalItem AttachTemplate(RemovalItem item)
    {
        if (item.Kind is not (RemovalKind.File or RemovalKind.Directory)) return item;

        Analysis.PathTemplate template = Analysis.PathTemplater.Infer(item.Target);
        if (!template.HasVariables) return item;

        return item with
        {
            TargetPattern = template.Pattern,
            PatternEvidence = template.Evidence,
            Rationale = $"{item.Rationale}; path contains run-specific segments ({template.Pattern})",
        };
    }

    /// <summary>
    /// True for the things Windows does on a program's behalf rather than letting it do.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A program does not install a service — it asks the service control manager to, and
    /// the change is therefore attributed to <c>services.exe</c>. A scheduled task is
    /// registered by the task scheduler service. Narrowing a plan to the subject's own
    /// process tree therefore discards exactly the artifacts that matter most.
    /// </para>
    /// <para>
    /// Measured: a recording of a program that installed a service with recovery actions
    /// and registered a scheduled task produced a plan containing its files and its
    /// startup entry and neither of the other two, while the analysis found all three
    /// from the same recording. The plan and the report disagreed about what had been
    /// installed.
    /// </para>
    /// <para>
    /// Widening scope here is safe because these categories are the most heavily governed
    /// by the safety policy: Windows' own services, its scheduled tasks, and the shared
    /// surfaces around them are refused outright and never reach a plan.
    /// </para>
    /// </remarks>
    private static bool IsDelegated(Observation o)
        => o.Category is EventCategory.Service or EventCategory.ScheduledTask
            or EventCategory.Autorun or EventCategory.Driver;

    private bool IsInScope(Observation o, Dictionary<ProcessKey, ProcessNode> processes, SessionInfo session)
    {
        // A recording with no subject has no scope to be outside of, so scope cannot be
        // the filter — and using it as one emptied the plan. Measured, on a real recording
        // of an installer: 759,179 file operations and 1,048,112 registry operations went
        // in, and two items came out, because scope is marked relative to a root process
        // and a system-wide recording has none.
        //
        // What replaces it is the signature of whatever made the change. Windows is busy
        // during any recording — Delivery Optimization counters, Explorer's pane state,
        // Defender's timestamps, the input stack's window positions — and none of it
        // belongs in a plan to remove a program. Every one of those is written by
        // something Microsoft signed, and nothing a third-party installer drops is.
        //
        // So the machine's own housekeeping is excluded by who did it rather than by
        // where it landed, which needs no list of paths to maintain and does not
        // accidentally exclude a program that installs itself somewhere unusual.
        if (session.RootProcess == ProcessKey.None)
        {
            if (o.Actor == ProcessKey.None) return o.Source == EvidenceSource.SnapshotDiff;

            return !processes.TryGetValue(o.Actor, out ProcessNode? actor) || !actor.IsMicrosoftSigned();
        }

        // Snapshot-derived changes carry no actor by construction. Excluding them
        // would drop exactly the persistence that live capture is worst at seeing.
        if (o.Actor == ProcessKey.None) return o.Source == EvidenceSource.SnapshotDiff;

        return processes.TryGetValue(o.Actor, out ProcessNode? node) && node.InScope;
    }

    /// <summary>
    /// Folders that belong to Windows or to the operator, never to a program.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Written as tokens rather than as paths, and compared against the tokenised target.
    /// That is the only form that works: a session is routinely recorded on one machine
    /// and read on another, so resolving <c>Documents</c> against the reading machine
    /// compares <c>C:\Users\A\Documents</c> with <c>C:\Users\B\Documents</c> and decides
    /// they are different — which is precisely how the operator's Documents folder ended
    /// up in a plan, ticked, after a guard had been written to stop it.
    /// </para>
    /// <para>
    /// The tokeniser already resolves a redirected profile to <c>%USERPROFILE%</c>, so
    /// matching on tokens keeps the property the path comparison was reaching for and
    /// drops the machine dependence.
    /// </para>
    /// </remarks>
    internal static readonly string[] WellKnownFolderTokens =
    {
        "%USERPROFILE%", "%APPDATA%", "%LOCALAPPDATA%", "%PROGRAMDATA%",
        "%PROGRAMFILES%", "%PROGRAMFILES(X86)%", "%WINDIR%", "%SYSTEM32%", "%SYSWOW64%",
        "%TEMP%", "%DESKTOP%", "%STARTMENU%", "%PUBLIC%", "%USERSROOT%", "%SYSTEMDRIVE%",

        // The shell folders inside a profile. A program reading any of these produces a
        // create event for it, and every one of them holds the operator's own data.
        @"%USERPROFILE%\Documents", @"%USERPROFILE%\Desktop", @"%USERPROFILE%\Downloads",
        @"%USERPROFILE%\Pictures", @"%USERPROFILE%\Music", @"%USERPROFILE%\Videos",
        @"%USERPROFILE%\Favorites", @"%USERPROFILE%\Links", @"%USERPROFILE%\Contacts",
        @"%USERPROFILE%\Searches", @"%USERPROFILE%\Saved Games", @"%USERPROFILE%\OneDrive",
        @"%USERPROFILE%\AppData", @"%USERPROFILE%\AppData\Local", @"%USERPROFILE%\AppData\Roaming",

        // Caches Windows keeps on every program's behalf. Touched by anything that makes
        // a web request, owned by none of them.
        @"%LOCALAPPDATA%\Microsoft", @"%LOCALAPPDATA%\Microsoft\Windows",
        @"%LOCALAPPDATA%\Microsoft\Windows\History",
        @"%LOCALAPPDATA%\Microsoft\Windows\INetCache",
        @"%LOCALAPPDATA%\Microsoft\Windows\INetCookies",
        @"%LOCALAPPDATA%\Microsoft\Windows\Temporary Internet Files",
        @"%LOCALAPPDATA%\Microsoft\Windows\WebCache",
        @"%LOCALAPPDATA%\Microsoft\Windows\Explorer",
        @"%LOCALAPPDATA%\Temp", @"%LOCALAPPDATA%\Packages",
        @"%APPDATA%\Microsoft", @"%APPDATA%\Microsoft\Windows",
        @"%APPDATA%\Microsoft\Windows\Recent",
        @"%APPDATA%\Microsoft\Windows\SendTo",
        @"%APPDATA%\Microsoft\Windows\Start Menu",
        @"%APPDATA%\Microsoft\Windows\Templates",
        @"%APPDATA%\Microsoft\Windows\Network Shortcuts",
        @"%APPDATA%\Microsoft\Windows\Printer Shortcuts",
    };

    /// <summary>
    /// True when a tokenised path names a folder Windows or the operator owns.
    /// </summary>
    /// <remarks>
    /// Exact match only. Something <em>inside</em> one of these is exactly what a program
    /// installing itself creates, and excluding a whole subtree would leave the program's
    /// own directory behind — which is the opposite failure and just as bad.
    /// </remarks>
    internal static bool IsWellKnownFolder(string tokenized)
    {
        if (string.IsNullOrWhiteSpace(tokenized)) return false;

        string trimmed = tokenized.TrimEnd('\\', '/');

        foreach (string known in WellKnownFolderTokens)
        {
            if (string.Equals(trimmed, known, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    private RemovalItem? Translate(Observation o, Dictionary<ProcessKey, ProcessNode> processes)
    {
        string who = Describe(o, processes);

        switch (o.Action)
        {
            case EventAction.FileCreate:
            case EventAction.HardLinkCreate:
                // Opening a directory is a create at the kernel level, and the file
                // provider reports it here rather than as a directory create — which is
                // how %USERPROFILE%\Documents arrived in the plan as a *file*, ticked,
                // when the program had done nothing but read it.
                if (IsWellKnownFolder(_paths.Tokenize(o.Target))) return null;

                return new RemovalItem
                {
                    Kind = RemovalKind.File,
                    Target = _paths.Tokenize(o.Target),
                    Rationale = $"created by {who}",
                    Created = true,
                    Fingerprint = new ArtifactFingerprint(),
                    Evidence = { o.Seq },
                };

            case EventAction.FileWrite when _options.IncludeModifiedFiles:
                return new RemovalItem
                {
                    Kind = RemovalKind.File,
                    Target = _paths.Tokenize(o.Target),
                    Rationale = $"written by {who} (modified, not created — verify before removing)",
                    Evidence = { o.Seq },
                };

            case EventAction.DirectoryCreate:
                // A directory the operating system already had is never "created by" the
                // subject, whatever the kernel reported. The create disposition fires when
                // a program *opens* a directory that exists, so a program that merely
                // looked in Documents produced an event indistinguishable from one that
                // made it — and the plan then offered to delete the operator's Documents
                // folder, ticked, with "created by …" as the reason.
                //
                // Judged on whether the path is a shell folder rather than on the event,
                // because the event cannot tell the two apart.
                if (IsWellKnownFolder(_paths.Tokenize(o.Target))) return null;

                return new RemovalItem
                {
                    Kind = RemovalKind.Directory,
                    Target = _paths.Tokenize(o.Target),
                    Rationale = $"created by {who}",
                    Created = true,
                    Evidence = { o.Seq },
                };

            case EventAction.FileRename:
                // The destination is what exists afterwards; the source no longer does.
                return o.Target2 is { Length: > 0 }
                    ? new RemovalItem
                    {
                        Kind = RemovalKind.File,
                        Target = _paths.Tokenize(o.Target2),
                        Rationale = $"renamed into place by {who}",
                        Created = true,
                        Evidence = { o.Seq },
                    }
                    : null;

            case EventAction.ValueSet:
            case EventAction.AutorunAdd:
            case EventAction.AutorunModify:
            {
                // The inventory writes a startup entry as one "key::value" string while a
                // registry event reports the key and the value name separately. Both
                // describe the same value and both produce the same deletion, so they are
                // reduced to one shape here — otherwise one Run entry appears twice on a
                // document the operator reads and approves, which inflates the count and
                // invites them to wonder what the difference is.
                string target = o.Target;
                string? valueName = o.Target2;

                if (o.Category == EventCategory.Autorun)
                {
                    int marker = target.IndexOf("::", StringComparison.Ordinal);
                    if (marker >= 0)
                    {
                        valueName = target[(marker + 2)..];
                        target = target[..marker];
                    }
                }

                return new RemovalItem
                {
                    Kind = o.Category == EventCategory.Autorun ? RemovalKind.AutorunEntry : RemovalKind.RegistryValue,
                    Target = target,
                    ValueName = valueName,
                    Rationale = o.OldValue is null
                        ? $"set by {who}"
                        : $"changed by {who} from '{Truncate(o.OldValue)}'",
                    Fingerprint = new ArtifactFingerprint { ValueData = o.NewValue },
                    Evidence = { o.Seq },
                };
            }

            case EventAction.KeyCreate:
                return new RemovalItem
                {
                    Kind = RemovalKind.RegistryKey,
                    Target = o.Target,
                    Rationale = $"created by {who}",
                    Evidence = { o.Seq },
                };

            case EventAction.ServiceInstall:
            case EventAction.ServiceModify:
                return new RemovalItem
                {
                    Kind = RemovalKind.Service,
                    Target = o.Target,
                    Rationale = o.Source == EvidenceSource.SnapshotDiff
                        ? "appeared between the before and after inventories"
                        : $"registered by {who}",
                    Fingerprint = new ArtifactFingerprint { CommandLine = ExtractCommand(o) },
                    Evidence = { o.Seq },
                };

            case EventAction.TaskRegister:
            case EventAction.TaskModify:
                return new RemovalItem
                {
                    Kind = RemovalKind.ScheduledTask,
                    Target = o.Target,
                    Rationale = o.Source == EvidenceSource.SnapshotDiff
                        ? "appeared between the before and after inventories"
                        : $"registered by {who}",
                    Evidence = { o.Seq },
                };

            case EventAction.DriverLoad:
                return new RemovalItem
                {
                    Kind = RemovalKind.Service,
                    Target = o.Target,
                    Rationale = "kernel driver registered during the session",
                    Evidence = { o.Seq },
                };

            default:
                return null;
        }
    }

    private static string? ExtractCommand(Observation o)
    {
        if (o.NewValue is { Length: > 0 }) return o.NewValue;
        if (o.Details is not { Length: > 0 }) return null;

        try
        {
            using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(o.Details);
            return doc.RootElement.TryGetProperty("ImagePath", out System.Text.Json.JsonElement image)
                   && image.ValueKind == System.Text.Json.JsonValueKind.String
                ? image.GetString()
                : null;
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }

    private static string Describe(Observation o, Dictionary<ProcessKey, ProcessNode> processes)
    {
        if (o.Source == EvidenceSource.SnapshotDiff) return "the session (snapshot diff)";
        return processes.TryGetValue(o.Actor, out ProcessNode? node)
            ? $"{node.ImageName} ({node.Pid})"
            : "an unidentified process";
    }

    private bool IsTemporary(string tokenizedPath)
        => tokenizedPath.StartsWith("%TEMP%", StringComparison.OrdinalIgnoreCase)
           || tokenizedPath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)
           || tokenizedPath.Contains(@"\INetCache\", StringComparison.OrdinalIgnoreCase)
           || tokenizedPath.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase);

    private static string Truncate(string value)
        => value.Length <= 60 ? value : value[..60] + "…";

    /// <summary>
    /// Builds a plan from a comparison of the same program across several machines.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the package worth carrying to a third machine. With one recording the
    /// variable parts of a path can only be guessed; with two they are <em>measured</em>, and the
    /// resulting pattern still matches on a machine that names its per-install
    /// directories differently again.
    /// </para>
    /// <para>
    /// Shared by the <c>compare</c> verb and the workbench so the two cannot produce
    /// different packages from the same comparison.
    /// </para>
    /// </remarks>
    public static List<RemovalItem> FromComparison(Analysis.MergeReport report, int minimumOrigins)
    {
        var items = new List<RemovalItem>();

        // One artifact per thing, not per verb. A file that was created and then written
        // produces two merged artifacts, and a plan listing both would ask the operator
        // to approve the same removal twice.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Analysis.MergedArtifact artifact in report.Artifacts)
        {
            if (artifact.SeenOn < minimumOrigins) continue;

            RemovalKind kind = MapKind(artifact);
            string target = artifact.ByOrigin.Values.First();

            // Volume roots and device paths reach here when a program opens a raw volume
            // handle. The safety policy would refuse them at apply time, but proposing
            // them at all makes a plan look reckless and buries the real items.
            if (!LooksRemovable(kind, target)) continue;
            if (!seen.Add($"{kind}|{artifact.Template.Pattern}")) continue;

            var item = new RemovalItem
            {
                Kind = kind,
                Target = target,
                Rationale = $"observed on {artifact.SeenOn} of {artifact.TotalOrigins} machines",
                TargetPattern = artifact.Template.HasVariables ? artifact.Template.Pattern : null,
                PatternEvidence = artifact.Template.Evidence,
                Fingerprint = new ArtifactFingerprint { ValueData = artifact.NewValue },
            };

            item.ObservedOn.AddRange(artifact.ByOrigin.Keys);
            item.Evidence.AddRange(artifact.Evidence.Take(32));
            items.Add(item);
        }

        return items;
    }

    /// <summary>Rejects targets that are not things a removal plan can act on.</summary>
    private static bool LooksRemovable(RemovalKind kind, string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;

        if (kind is RemovalKind.RegistryKey or RemovalKind.RegistryValue)
            return target.StartsWith("HK", StringComparison.OrdinalIgnoreCase);

        if (kind is RemovalKind.File or RemovalKind.Directory)
        {
            // A raw device or volume path, not a file.
            if (target.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return false;
            if (target.StartsWith(@"\\.\", StringComparison.Ordinal)) return false;

            // Must name something inside a directory, not a root.
            return target.Contains('\\', StringComparison.Ordinal);
        }

        return true;
    }

    private static RemovalKind MapKind(Analysis.MergedArtifact artifact) => artifact.Category switch
    {
        EventCategory.File => artifact.Action == EventAction.DirectoryCreate
            ? RemovalKind.Directory
            : RemovalKind.File,
        EventCategory.Registry => artifact.Action == EventAction.KeyCreate
            ? RemovalKind.RegistryKey
            : RemovalKind.RegistryValue,
        EventCategory.Service => RemovalKind.Service,
        EventCategory.ScheduledTask => RemovalKind.ScheduledTask,
        EventCategory.Autorun => RemovalKind.AutorunEntry,
        _ => RemovalKind.File,
    };

    /// <summary>Packages a plan for use on another machine.</summary>
    public static void Export(
        string path,
        SessionInfo session,
        IReadOnlyList<RemovalItem> items,
        IEnumerable<Observation>? evidence = null)
    {
        var manifest = new PackageManifest
        {
            PackageId = $"ctpkg_{session.SessionId}",
            SubjectName = session.Name,
            SubjectPath = session.TargetPath,
            SubjectSha256 = session.TargetSha256,
            CreatedAt = DateTimeOffset.UtcNow,
            ToolVersion = session.ToolVersion,
            Origins = { session.Machine },
        };

        RemovalPackage.Write(path, manifest, items, evidence);
    }
}
