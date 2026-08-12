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

    public List<RemovalItem> Build(SessionInfo session)
    {
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
            if (_options.ScopedOnly && !IsDelegated(o) && !IsInScope(o, processes)) continue;

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
            if (policy.Evaluate(item).Verdict == SafetyVerdict.Forbidden) continue;

            item.ObservedOn.AddRange(origins);
            plan.Add(AttachTemplate(item));
        }

        return plan.OrderBy(static i => i.Order).ThenBy(static i => i.Target, StringComparer.OrdinalIgnoreCase).ToList();
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

    private bool IsInScope(Observation o, Dictionary<ProcessKey, ProcessNode> processes)
    {
        // Snapshot-derived changes carry no actor by construction. Excluding them
        // would drop exactly the persistence that live capture is worst at seeing.
        if (o.Actor == ProcessKey.None) return o.Source == EvidenceSource.SnapshotDiff;

        return processes.TryGetValue(o.Actor, out ProcessNode? node) && node.InScope;
    }

    private RemovalItem? Translate(Observation o, Dictionary<ProcessKey, ProcessNode> processes)
    {
        string who = Describe(o, processes);

        switch (o.Action)
        {
            case EventAction.FileCreate:
            case EventAction.HardLinkCreate:
                return new RemovalItem
                {
                    Kind = RemovalKind.File,
                    Target = _paths.Tokenize(o.Target),
                    Rationale = $"created by {who}",
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
                return new RemovalItem
                {
                    Kind = RemovalKind.Directory,
                    Target = _paths.Tokenize(o.Target),
                    Rationale = $"created by {who}",
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
