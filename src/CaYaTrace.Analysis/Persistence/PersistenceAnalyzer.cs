using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;

namespace CaYaTrace.Analysis.Persistence;

/// <summary>
/// Finds the ways a session's subject arranged to run again.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of a measured gap. A session holding <b>33,467 registry
/// observations produced zero registry findings</b>, while a comparison tool run on the
/// same machine at the same time reported the two services the subject had installed,
/// with their image paths, display names, start types, accounts and recovery actions —
/// about seventy lines, all of them useful. Every one of those values was in our
/// recording. Nothing looked at them.
/// </para>
/// <para>
/// The unit of output is a mechanism, not a value. A service installation writes eight
/// or ten registry values; reporting them as ten findings is technically complete and
/// practically useless, because the question an analyst asks is "what did it install",
/// not "which DWORDs changed". One record per mechanism, carrying its values.
/// </para>
/// </remarks>
public sealed class PersistenceAnalyzer
{
    private readonly Func<ProcessKey, ProcessNode?>? _lookup;

    public PersistenceAnalyzer(Func<ProcessKey, ProcessNode?>? processLookup = null)
        => _lookup = processLookup;

    /// <summary>
    /// Where persistence lives, and what a match there means.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Matched against the canonical path, so a rule can be written the readable way and
    /// still match what the kernel actually reports. See
    /// <see cref="RegistryPath.CanonicalizeControlSet"/> for why that is not optional.
    /// </para>
    /// <para>
    /// <see cref="Rule.IdentitySegment"/> is what keeps this honest. The busiest match under
    /// <c>\Services\</c> in real evidence is <c>Services\bam\State\UserSettings\S-1-5-21-…</c> —
    /// the Background Activity Moderator, which is Windows recording that a program ran,
    /// not a program installing itself. A rule that merely contains <c>\Services\</c> reports
    /// a service called "bam" on every machine it is ever run on. Identity is the segment
    /// immediately after the prefix and nothing deeper counts.
    /// </para>
    /// </remarks>
    private sealed record Rule(
        string Prefix,
        PersistenceKind Kind,
        bool IdentitySegment,
        string Why,
        int Score,
        string? CommandValue = null);

    private static readonly Rule[] Rules =
    {
        // ---- services and drivers -------------------------------------------------
        new(@"HKLM\SYSTEM\CurrentControlSet\Services", PersistenceKind.Service, true,
            "installs a Windows service, which runs before anyone logs in", 45, "ImagePath"),

        // ---- scheduled tasks ------------------------------------------------------
        new(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
            PersistenceKind.ScheduledTask, true,
            "registers a scheduled task, which survives reboots and uninstalls", 40, "Path"),
        new(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
            PersistenceKind.ScheduledTask, true,
            "registers a scheduled task, which survives reboots and uninstalls", 40),

        // ---- run keys -------------------------------------------------------------
        new(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", PersistenceKind.RunKey, false,
            "runs at every logon", 45),
        new(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", PersistenceKind.RunKey, false,
            "runs at every logon for this user", 45),
        new(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceKind.RunOnce, false,
            "runs once at the next logon", 35),
        new(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceKind.RunOnce, false,
            "runs once at the next logon for this user", 35),
        new(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", PersistenceKind.RunKey, false,
            "runs at startup", 45),
        new(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            PersistenceKind.RunKey, false, "runs at logon through group policy", 50),
        new(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            PersistenceKind.RunKey, false, "runs at logon through group policy", 50),
        new(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
            PersistenceKind.TerminalServerRun, false, "runs at logon in terminal server sessions", 45),

        // ---- logon path -----------------------------------------------------------
        new(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
            PersistenceKind.WinlogonHook, true, "loads a DLL into the logon process", 60),
        new(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            PersistenceKind.WinlogonHook, false, "changes what runs when a user logs on", 60),

        // ---- loaded into other processes ------------------------------------------
        new(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            PersistenceKind.ImageFileExecutionOption, true,
            "attaches itself to another program's launch", 60, "Debugger"),
        new(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            PersistenceKind.AppInitDll, false, "loads a DLL into every process that uses the window manager", 65),
        new(@"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
            PersistenceKind.AppCertDll, false, "loads a DLL into every process that creates a process", 65),
        new(@"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
            PersistenceKind.KnownDll, false, "changes which system DLLs are loaded from the cache", 65),
        new(@"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            PersistenceKind.SessionManagerExecute, false, "runs before Windows finishes starting", 60),

        // ---- security stack -------------------------------------------------------
        new(@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", PersistenceKind.LsaProvider, false,
            "loads into the process that handles authentication", 70),
        new(@"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders",
            PersistenceKind.SecurityProvider, false, "registers a security provider", 65),

        // ---- service-adjacent extension points ------------------------------------
        new(@"HKLM\SOFTWARE\Microsoft\Netsh", PersistenceKind.NetshHelper, false,
            "loads a DLL whenever network configuration is changed", 50),
        new(@"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors", PersistenceKind.PrintMonitor, true,
            "loads a DLL into the print spooler, which runs as the system account", 60),
        new(@"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders",
            PersistenceKind.TimeProvider, true, "loads a DLL into the time service", 55),
        new(@"HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters",
            PersistenceKind.WinsockProvider, false, "inserts itself into the network stack", 60),

        // ---- shell and COM --------------------------------------------------------
        new(@"HKCU\SOFTWARE\Classes\CLSID", PersistenceKind.ComServer, true,
            "registers a COM object for this user, which takes precedence over the machine's", 55),
        new(@"HKLM\SOFTWARE\Classes\CLSID", PersistenceKind.ComServer, true,
            "registers a COM object", 30),
        new(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            PersistenceKind.BrowserHelperObject, true, "loads into the browser", 55),
        new(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
            PersistenceKind.ShellExtension, false, "loads into the shell at logon", 55),
        new(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
            PersistenceKind.ShellExtension, true, "loads into the shell", 45),
        new(@"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",
            PersistenceKind.ActiveSetup, true, "runs once for every user who logs on", 50, "StubPath"),

        // ---- scripts --------------------------------------------------------------
        new(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup",
            PersistenceKind.GroupPolicyScript, true, "runs a script at startup through group policy", 55),
        new(@"HKCU\SOFTWARE\Microsoft\Command Processor", PersistenceKind.CommandProcessorAutoRun, false,
            "runs whenever a command prompt is opened", 55),
        new(@"HKLM\SOFTWARE\Microsoft\Command Processor", PersistenceKind.CommandProcessorAutoRun, false,
            "runs whenever a command prompt is opened", 55),
    };

    /// <summary>
    /// Values under a matched key that are noise rather than configuration.
    /// </summary>
    /// <remarks>
    /// Windows stamps counters and timestamps into the same keys programs configure
    /// themselves in. Carrying them makes every record look like it changed on every run.
    /// </remarks>
    private static readonly HashSet<string> IgnoredValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "DynamicInfo", "LastRunTime", "LastStartTime", "SequenceNumber", "Count",
        "TriggerCount", "ActionCount", "Index", "Version",
    };

    /// <summary>
    /// Registry surfaces that record what ran rather than arrange for something to run.
    /// </summary>
    /// <remarks>
    /// Checked before the rules, because several of them sit underneath a rule's prefix.
    /// The Background Activity Moderator lives under <c>\Services\bam</c> and would otherwise
    /// be reported as a service on every machine.
    /// </remarks>
    private static readonly string[] ActivityRecords =
    {
        @"HKLM\SYSTEM\CurrentControlSet\Services\bam",
        @"HKLM\SYSTEM\CurrentControlSet\Services\dam",
        @"HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost",
        @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters",
    };

    public IReadOnlyList<PersistenceRecord> Analyze(IEnumerable<Observation> observations)
    {
        var groups = new Dictionary<string, Group>(StringComparer.OrdinalIgnoreCase);

        foreach (Observation o in observations)
        {
            switch (o.Category)
            {
                case EventCategory.Registry when o.Action.IsPersistentChange():
                    Absorb(groups, o);
                    break;

                // Services and tasks also arrive as their own categories from the
                // before/after inventory, which is the only source that sees an entry
                // that was already configured before recording started.
                case EventCategory.Service:
                    AbsorbDirect(groups, o, PersistenceKind.Service);
                    break;

                case EventCategory.ScheduledTask:
                    AbsorbDirect(groups, o, PersistenceKind.ScheduledTask);
                    break;

                case EventCategory.Autorun:
                    AbsorbDirect(groups, o, PersistenceKind.RunKey);
                    break;

                case EventCategory.File when IsStartupFolder(o.Target):
                    AbsorbDirect(groups, o, PersistenceKind.StartupFolder);
                    break;
            }
        }

        return Merge(groups.Values)
            .Select(Build)
            .Where(static r => r.Score > 0)
            .OrderByDescending(static r => r.Score)
            .ThenBy(static r => r.FirstSeen)
            .ToList();
    }

    /// <summary>
    /// Folds the several records that describe one thing into one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Necessary because the same installation is seen from three directions and none of
    /// them agrees on what it is called. Measured on a real capture of one service and
    /// one scheduled task: the service appeared twice — once as
    /// <c>HKLM\SYSTEM\CurrentControlSet\Services\CAYATRACEPROBESVC</c> from the kernel, which
    /// reports whatever case the writer used, and once as <c>CaYaTraceProbeSvc</c> from the
    /// inventory — and the task appeared three times, as its registry GUID, as its tree
    /// entry, and as its path on disk.
    /// </para>
    /// <para>
    /// Merging happens here rather than at the key, because the name that identifies a
    /// task is a value inside it and is not known when its group is created. Doing it
    /// afterwards also means the merge can prefer the better-spelled identity rather than
    /// whichever spelling arrived first.
    /// </para>
    /// </remarks>
    private static IEnumerable<Group> Merge(IEnumerable<Group> groups)
    {
        var merged = new Dictionary<string, Group>(StringComparer.OrdinalIgnoreCase);

        foreach (Group group in groups)
        {
            string key = $"{FoldKind(group.Kind)}|{CanonicalIdentity(group)}";

            if (!merged.TryGetValue(key, out Group? existing))
            {
                merged[key] = group;
                continue;
            }

            // Values from either source, with the richer one winning a collision: the
            // inventory carries a whole record, the kernel carries only what moved.
            foreach ((string name, PersistenceValue value) in group.Values)
            {
                if (!existing.Values.TryGetValue(name, out PersistenceValue? had)
                    || (had.Data is null && value.Data is not null))
                {
                    existing.Values[name] = value;
                }
            }

            existing.SawCreate |= group.SawCreate;
            if (group.FirstSeen < existing.FirstSeen) existing.FirstSeen = group.FirstSeen;

            // Kernel attribution names the process that made the change; the inventory
            // cannot, so it never overwrites a real answer.
            if (group.Confidence > existing.Confidence)
            {
                existing.Confidence = group.Confidence;
                if (group.Actor != ProcessKey.None) existing.Actor = group.Actor;
                existing.Source = group.Source;
            }

            // A registry path locates the entry; a bare name does not.
            if (existing.Location.IndexOf('\\', StringComparison.Ordinal) < 0
                && group.Location.IndexOf('\\', StringComparison.Ordinal) >= 0)
            {
                existing.Location = group.Location;
            }

            // Prefer the identity that looks like a name over one that looks like a GUID
            // or a shouted registry key.
            if (PreferIdentity(group.Identity, existing.Identity)) existing.Identity = group.Identity;
        }

        return merged.Values;
    }

    /// <summary>RunOnce is a Run key with a shorter life; a driver is a service.</summary>
    private static PersistenceKind FoldKind(PersistenceKind kind) => kind switch
    {
        PersistenceKind.RunOnce => PersistenceKind.RunKey,
        PersistenceKind.Driver => PersistenceKind.Service,
        _ => kind,
    };

    /// <summary>
    /// The name that identifies an entry regardless of which source described it.
    /// </summary>
    /// <remarks>
    /// A task is identified by its path, which is a value inside it rather than the
    /// registry key it lives under — the key is a GUID and the tree entry is the name in
    /// upper case. A service is identified by its bare name. Everything else is
    /// identified by where it is plus what it is called, since two Run values with the
    /// same name under different hives are genuinely two entries.
    /// </remarks>
    private static string CanonicalIdentity(Group group)
    {
        switch (group.Kind)
        {
            case PersistenceKind.ScheduledTask:
            {
                string? path = Value(group, "Path") ?? Value(group, "URI");
                if (path is { Length: > 0 }) return path.TrimStart('\\');

                string leaf = Leaf(group.Identity);
                return leaf.TrimStart('\\');
            }

            case PersistenceKind.Service:
            case PersistenceKind.Driver:
                return Leaf(Value(group, "Name") ?? group.Identity);

            default:
            {
                // Both spellings reduce to the same thing: the key that holds it, and the
                // value name under it. Two Run entries with the same name under different
                // hives are genuinely two entries, so the key stays part of the identity.
                (string key, string name) = SplitEntry(group.Location, group.Identity);
                return $"{key}::{name}";
            }
        }
    }

    /// <summary>
    /// Separates the key that holds an entry from the value name under it.
    /// </summary>
    /// <remarks>
    /// The inventory writes an autorun as <c>key::value</c> in one string; a registry event
    /// reports the key and the value name separately. Both arrive here and have to reduce
    /// to the same pair, or one startup entry is reported twice.
    /// </remarks>
    private static (string Key, string Name) SplitEntry(string location, string identity)
    {
        int marker = identity.IndexOf("::", StringComparison.Ordinal);
        if (marker >= 0) return (identity[..marker], identity[(marker + 2)..]);

        marker = location.IndexOf("::", StringComparison.Ordinal);
        if (marker >= 0) return (location[..marker], location[(marker + 2)..]);

        return (location, identity);
    }

    private static string? Value(Group group, string name)
        => group.Values.TryGetValue(name, out PersistenceValue? value) ? value.Data : null;

    private static string Leaf(string identity)
    {
        int slash = identity.LastIndexOf('\\');
        return slash >= 0 ? identity[(slash + 1)..] : identity;
    }

    /// <summary>
    /// True when <paramref name="candidate"/> reads better than what is already held.
    /// </summary>
    /// <remarks>
    /// Mixed case over shouted, a name over a GUID. Cosmetic, but the identity is what
    /// an operator will search for and paste into a command, and <c>CAYATRACEPROBESVC</c> is
    /// not what the service is called.
    /// </remarks>
    private static bool PreferIdentity(string candidate, string current)
    {
        if (candidate.Length == 0) return false;

        bool candidateGuid = candidate.StartsWith('{');
        bool currentGuid = current.StartsWith('{');
        if (candidateGuid != currentGuid) return currentGuid;

        bool candidateShouted = candidate == candidate.ToUpperInvariant() && candidate.Any(char.IsLetter);
        bool currentShouted = current == current.ToUpperInvariant() && current.Any(char.IsLetter);
        if (candidateShouted != currentShouted) return currentShouted;

        // A registry path is a location, not a name.
        bool candidatePath = candidate.Contains('\\', StringComparison.Ordinal);
        bool currentPath = current.Contains('\\', StringComparison.Ordinal);
        if (candidatePath != currentPath) return currentPath;

        return false;
    }

    private sealed class Group
    {
        public required PersistenceKind Kind { get; init; }
        public required string Why { get; init; }
        public required int BaseScore { get; init; }
        public string? CommandValue { get; init; }

        // Settable because the merge pass prefers the better-spelled identity and the
        // more specific location once it can see all the descriptions of one entry.
        public string Identity { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;

        public Dictionary<string, PersistenceValue> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
        public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.MaxValue;
        public ProcessKey Actor { get; set; } = ProcessKey.None;
        public EvidenceSource Source { get; set; }
        public AttributionConfidence Confidence { get; set; }
        public bool SawCreate { get; set; }
    }

    private void Absorb(Dictionary<string, Group> groups, Observation o)
    {
        string canonical = RegistryPath.CanonicalizeControlSet(RegistryPath.Normalize(o.Target));
        string dewowed = RegistryPath.StripWow64(canonical);

        foreach (string record in ActivityRecords)
            if (HasPrefix(dewowed, record)) return;

        foreach (Rule rule in Rules)
        {
            if (!HasPrefix(dewowed, rule.Prefix)) continue;

            string identity;
            string location;

            if (rule.IdentitySegment)
            {
                // Exactly one segment past the prefix, and nothing deeper. This is what
                // stops "Services\bam\State\UserSettings\S-1-5-…" from being reported as
                // a service named bam.
                string remainder = dewowed.Length > rule.Prefix.Length
                    ? dewowed[(rule.Prefix.Length + 1)..]
                    : string.Empty;

                if (remainder.Length == 0) return;

                int slash = remainder.IndexOf('\\');
                identity = slash < 0 ? remainder : remainder[..slash];
                location = $"{rule.Prefix}\\{identity}";
            }
            else
            {
                // A value-keyed surface: the run key itself is the location and each
                // value under it is a separate entry.
                identity = o.Target2 is { Length: > 0 } and not "(Default)" ? o.Target2 : "(Default)";
                location = rule.Prefix;
            }

            if (o.Target2 is { Length: > 0 } && IgnoredValues.Contains(o.Target2)) return;

            string key = $"{rule.Kind}|{location}|{(rule.IdentitySegment ? string.Empty : identity)}";

            if (!groups.TryGetValue(key, out Group? group))
            {
                groups[key] = group = new Group
                {
                    Kind = rule.Kind,
                    Identity = identity,
                    Location = location,
                    Why = rule.Why,
                    BaseScore = rule.Score,
                    CommandValue = rule.CommandValue,
                };
            }

            if (o.Target2 is { Length: > 0 } name)
            {
                group.Values[name] = new PersistenceValue(
                    name, o.NewValue, o.OldValue, o.Source, o.Timestamp);
            }

            if (o.Action == EventAction.KeyCreate) group.SawCreate = true;
            Note(group, o);
            return;
        }
    }

    private void AbsorbDirect(Dictionary<string, Group> groups, Observation o, PersistenceKind kind)
    {
        string identity = o.Target;
        string location = o.Target;

        // An autorun row arrives as one string holding the key and the value name. Split
        // now so the entry is named after itself rather than after its whole path, and so
        // it lines up with the registry event that described the same write.
        if (kind is PersistenceKind.RunKey or PersistenceKind.RunOnce)
            (location, identity) = SplitEntry(o.Target, o.Target);

        string key = $"{kind}|{identity}|";

        if (!groups.TryGetValue(key, out Group? group))
        {
            groups[key] = group = new Group
            {
                Kind = kind,
                Identity = identity,
                Location = location,
                Why = kind switch
                {
                    PersistenceKind.Service => "installs a Windows service, which runs before anyone logs in",
                    PersistenceKind.ScheduledTask => "registers a scheduled task, which survives reboots and uninstalls",
                    PersistenceKind.StartupFolder => "places a shortcut in a startup folder",
                    _ => "arranges to run again",
                },
                BaseScore = kind switch
                {
                    PersistenceKind.Service => 45,
                    PersistenceKind.ScheduledTask => 40,
                    PersistenceKind.StartupFolder => 40,
                    _ => 35,
                },
            };
        }

        // Details over NewValue. The inventory summarises a service down to its image
        // path for display and keeps the whole record — display name, start type,
        // account, dependencies, recovery actions — in the details. Reading the summary
        // is why a service finding used to say nothing but a name and a path, while every
        // other value was sitting in the same row.
        string? payload = o.Details is { Length: > 0 } ? o.Details : o.NewValue;
        if (payload is { Length: > 0 })
            AbsorbPayload(group, payload, o);

        if (o.Action is EventAction.ServiceInstall or EventAction.TaskRegister
            or EventAction.AutorunAdd or EventAction.FileCreate)
        {
            group.SawCreate = true;
        }

        Note(group, o);
    }

    /// <summary>
    /// Pulls named fields out of an inventory record.
    /// </summary>
    /// <remarks>
    /// The inventory stores a snapshot row as JSON. Parsing the interesting fields out of
    /// it rather than showing the raw blob is the difference between an entry that says
    /// what a service does and one that makes the reader do the decoding.
    /// </remarks>
    private static void AbsorbPayload(Group group, string payload, Observation o)
    {
        string trimmed = payload.TrimStart();
        if (!trimmed.StartsWith('{'))
        {
            // Not a record, just a path — which is what a service install reports.
            group.Values.TryAdd("ImagePath",
                new PersistenceValue("ImagePath", payload, o.OldValue, o.Source, o.Timestamp));
            return;
        }

        // Attribution appends a note after the record, on its own line, so the details
        // are a JSON object followed by prose. Trimming back to the last brace recovers
        // the record; if that still does not parse, the whole thing is kept as-is rather
        // than discarded.
        int close = trimmed.LastIndexOf('}');
        if (close >= 0) trimmed = trimmed[..(close + 1)];

        try
        {
            using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(trimmed);
            if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object) return;

            foreach (System.Text.Json.JsonProperty property in doc.RootElement.EnumerateObject())
            {
                if (IgnoredValues.Contains(property.Name)) continue;

                string? text = property.Value.ValueKind switch
                {
                    System.Text.Json.JsonValueKind.String => property.Value.GetString(),
                    System.Text.Json.JsonValueKind.Number => property.Value.ToString(),
                    System.Text.Json.JsonValueKind.True => "true",
                    System.Text.Json.JsonValueKind.False => "false",
                    System.Text.Json.JsonValueKind.Null => null,
                    _ => property.Value.GetRawText(),
                };

                if (text is null) continue;

                group.Values[property.Name] =
                    new PersistenceValue(property.Name, text, null, o.Source, o.Timestamp);
            }
        }
        catch (System.Text.Json.JsonException)
        {
            // A record we cannot parse is still a record. Keeping it whole beats
            // dropping it.
            group.Values.TryAdd("Record", new PersistenceValue("Record", payload, null, o.Source, o.Timestamp));
        }
    }

    private static void Note(Group group, Observation o)
    {
        if (o.Timestamp < group.FirstSeen) group.FirstSeen = o.Timestamp;

        // Kernel attribution wins: it names the process that made the change, which the
        // inventory diff cannot do at all.
        if (o.Confidence >= group.Confidence)
        {
            group.Confidence = o.Confidence;
            if (o.Actor != ProcessKey.None) group.Actor = o.Actor;
            group.Source = o.Source;
        }
    }

    private PersistenceRecord Build(Group group)
    {
        var traits = new List<string>();
        var reasons = new List<string> { group.Why };
        int score = group.BaseScore;

        string? command = null;
        string? displayName = null;
        bool restarts = false;

        if (group.CommandValue is { Length: > 0 } commandValue
            && group.Values.TryGetValue(commandValue, out PersistenceValue? cv))
        {
            command = cv.Data;
        }

        // On a value-keyed surface the entry *is* a value, and its data is the command.
        // A startup entry that reported the key it lives under and not the program it
        // starts answered the wrong half of the question.
        if (command is null && group.Values.TryGetValue(group.Identity, out PersistenceValue? own))
            command = own.Data;

        foreach ((string name, PersistenceValue value) in group.Values)
        {
            switch (name.ToLowerInvariant())
            {
                case "imagepath" or "pathname":
                    command ??= value.Data;
                    break;

                case "servicedll":
                    command ??= value.Data;
                    traits.Add($"runs inside a shared service host from {value.Data}");
                    break;

                case "displayname":
                    displayName = value.Data;
                    break;

                case "description":
                    displayName ??= value.Data;
                    break;

                case "start" or "startmode":
                    if (int.TryParse(value.Data, out int start))
                    {
                        traits.Add(ServiceStartType.Describe(start));
                        if (ServiceStartType.RunsBeforeLogon(start)) score += 5;
                    }
                    else if (value.Data is { Length: > 0 })
                    {
                        traits.Add($"start mode {value.Data}");
                    }
                    break;

                case "delayedautostart":
                    if (value.Data is "1" or "true")
                    {
                        traits.Add("starts automatically, a little after boot");

                        // Worth calling out. Delayed start is how something arranges to
                        // come up after the tools that would notice it.
                        score += 5;
                    }
                    break;

                case "objectname" or "startname":
                    traits.Add($"runs as {value.Data}");
                    if (value.Data is "LocalSystem") score += 5;
                    break;

                case "type":
                    if (int.TryParse(value.Data, out int type) && (type & 0x1) != 0)
                    {
                        traits.Add("is a kernel driver");
                        score += 15;
                    }
                    break;

                case "failureactions":
                    ServiceRecovery? recovery = ServiceFailureActions.DecodeHex(value.Data);
                    if (recovery is not null && recovery.Actions.Count > 0)
                    {
                        traits.Add($"on failure it will {ServiceFailureActions.Describe(recovery)}");
                        restarts = recovery.RestartsOnFailure;

                        if (recovery.RestartsOnFailure)
                        {
                            reasons.Add("restarts itself after being stopped");
                            score += 10;
                        }

                        if (recovery.RebootsMachine)
                        {
                            reasons.Add("is configured to reboot the machine when it fails");
                            score += 20;
                        }

                        if (recovery.RunsCommand)
                        {
                            reasons.Add("runs a command of its own when it fails");
                            score += 15;
                        }
                    }
                    else if (value.Data is { Length: > 0 })
                    {
                        traits.Add("has recovery actions configured, which could not be decoded");
                    }
                    break;

                case "debugger":
                    reasons.Add($"launches {value.Data} instead of the program being started");
                    score += 10;
                    break;

                case "definition":
                    // A scheduled task's real command lives in its XML definition. The
                    // registry holds it as a binary blob and the task path is only a name,
                    // so without this a task entry says what it is called and never what
                    // it runs — which is the only question worth asking of one.
                    string? fromXml = TaskDefinition.ReadCommand(value.Data);
                    if (fromXml is { Length: > 0 }) command = fromXml;
                    break;
            }
        }

        if (group.SawCreate)
        {
            reasons.Add("did not exist before this session");
            score += 10;
        }

        // A name that looks generated rather than chosen. Legitimate software names its
        // service after itself; the sample this was built against installed one called
        // "bf6e56533c2749ec" with a display name of "63918fc1c9ecbbd4".
        if (LooksGenerated(group.Identity))
        {
            reasons.Add("is named with what looks like a generated string rather than a product name");
            score += 15;
        }

        if (displayName is { Length: > 0 } && LooksGenerated(displayName))
        {
            reasons.Add("its display name is a generated string, so it shows up nameless in the services list");
            score += 10;
        }

        ProcessNode? actor = _lookup?.Invoke(group.Actor);
        if (actor is not null && actor.Signature == SignatureState.Unsigned)
        {
            reasons.Add($"was installed by {actor.ImageName}, which is not signed");
            score += 10;
        }

        // Nothing was actually configured. A key that was opened or created and left
        // empty is not something arranging to run — measured on a real capture, this was
        // every entry it produced: Explorer touching three CLSID keys and a service host
        // touching the TCP/IP service, all with no values at all.
        if (group.Values.Count == 0 && command is null) score = 0;

        // Windows adjusting its own configuration. The same trust test as everywhere
        // else, and for the same reason: a directory or a key name can be occupied by
        // anything, but a Microsoft signature on the process that wrote it cannot. An
        // unsigned binary touching these still lands at full weight.
        else if (score > 0 && actor is not null && actor.IsMicrosoftSigned()
                 && !group.SawCreate && command is null)
        {
            score = 0;
        }

        return new PersistenceRecord
        {
            Kind = group.Kind,
            Identity = group.Identity,
            Location = group.Location,
            Command = command,
            DisplayName = displayName,
            Values = group.Values.Values.OrderBy(static v => v.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            Traits = traits,
            Reasons = reasons,
            Score = score,
            Risk = ToRisk(score),
            IsNew = group.SawCreate,
            FirstSeen = group.FirstSeen == DateTimeOffset.MaxValue ? default : group.FirstSeen,
            Actor = group.Actor,
            Source = group.Source,
            Confidence = group.Confidence,
            RestartsItself = restarts,
        };
    }

    /// <summary>
    /// True for names that look machine-generated.
    /// </summary>
    /// <remarks>
    /// A weak signal used only to add weight, never to conclude. Plenty of legitimate
    /// software uses a GUID; almost none uses sixteen hex characters as a display name.
    /// </remarks>
    private static bool LooksGenerated(string name)
    {
        if (name.Length < 12) return false;

        string bare = name.Trim('{', '}').Replace("-", string.Empty);
        if (bare.Length < 12) return false;

        int hex = bare.Count(static c => Uri.IsHexDigit(c));
        if (hex != bare.Length) return false;

        // All hex and long enough to not be a version or a date. A GUID qualifies, which
        // is why this only contributes weight.
        return true;
    }

    private static bool HasPrefix(string path, string prefix)
        => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
           && (path.Length == prefix.Length || path[prefix.Length] == '\\');

    private static bool IsStartupFolder(string path)
        => path.Contains(@"\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase);

    private static RiskLevel ToRisk(int score) => score switch
    {
        >= 70 => RiskLevel.Critical,
        >= 45 => RiskLevel.High,
        >= 25 => RiskLevel.Medium,
        >= 10 => RiskLevel.Low,
        > 0 => RiskLevel.Info,
        _ => RiskLevel.None,
    };
}
