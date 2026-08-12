using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;

namespace CaYaTrace.Analysis;

/// <summary>A scored artifact with the reasons that produced the score.</summary>
public sealed record ScoredArtifact(
    Observation Observation,
    RiskLevel Risk,
    int Score,
    IReadOnlyList<string> Reasons)
{
    /// <summary>Compact one-line form used when packing evidence for a model.</summary>
    public string Describe()
        => $"{Observation.Action} {Observation.Target}" +
           (Observation.Target2 is { Length: > 0 } ? $"::{Observation.Target2}" : string.Empty);
}

/// <summary>
/// Ranks observations by how much an analyst should care, using fixed rules.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately deterministic and free of any model. Two reasons. It has to be
/// explainable — a score an analyst cannot interrogate is worse than no score, so every
/// point carries a reason string that appears in the UI. And it is what makes a local
/// model usable at all: the ranking decides <em>which</em> handful of artifacts a model ever
/// sees, so the model is never asked to find the needle, only to describe one it was
/// handed.
/// </para>
/// <para>
/// The weights are ordinal, not probabilistic. They exist to sort, and the thresholds
/// were chosen so that the things which routinely matter on a real installer run —
/// autostart, services, executables dropped into user-writable directories — land above
/// the noise floor.
/// </para>
/// </remarks>
public sealed class ArtifactScorer
{
    private readonly PathNormalizer _paths;
    private readonly Func<ProcessKey, ProcessNode?>? _lookup;

    public ArtifactScorer(PathNormalizer? paths = null, Func<ProcessKey, ProcessNode?>? processLookup = null)
    {
        _paths = paths ?? PathNormalizer.CreateForCurrentMachine();
        _lookup = processLookup;
    }

    private static readonly string[] AutostartKeys =
    {
        @"\CurrentVersion\Run",
        @"\CurrentVersion\RunOnce",
        @"\CurrentVersion\Policies\Explorer\Run",
        @"\CurrentVersion\Winlogon",
        @"\Image File Execution Options",
        @"\CurrentVersion\Explorer\Browser Helper Objects",
        @"\CurrentVersion\ShellServiceObjectDelayLoad",
        @"\Control\Session Manager",
        @"\Control\Lsa",
    };

    private static readonly string[] ExecutableExtensions =
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv",
    };

    private static readonly string[] ScriptExtensions =
    {
        ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".vbe", ".wsf", ".hta", ".lnk",
    };

    /// <summary>
    /// Directories Windows rewrites as a matter of course.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Measured against a real session: of 2,000 findings, <b>1,864 were Windows Update
    /// writing into <c>%WINDIR%\SoftwareDistribution</c></b>. Nothing about them was wrong —
    /// they were real file writes, correctly attributed, correctly scored low — and they
    /// still made the findings list useless, because the twelve rows that described the
    /// subject were somewhere below row 1,900. A comparison tool run on the same machine
    /// at the same time produced about seventy lines, all of them signal.
    /// </para>
    /// <para>
    /// This is a floor, not a filter: the observations are all still recorded, still in
    /// the tree, still exported. It only decides what is worth putting at the top of a
    /// report. And it applies only to code Windows itself signed — see
    /// <see cref="IsBackgroundChurn"/> — so an unknown binary writing into the update
    /// cache is still one of the loudest things this scorer can say.
    /// </para>
    /// </remarks>
    private static readonly string[] OsManagedChurn =
    {
        @"%WINDIR%\SoftwareDistribution\",
        @"%WINDIR%\Prefetch\",
        @"%WINDIR%\Logs\",
        @"%WINDIR%\AppCompat\",
        @"%WINDIR%\ServiceProfiles\",
        @"%WINDIR%\WinSxS\Temp\",
        @"%WINDIR%\Temp\",
        @"%SYSTEM32%\LogFiles\",
        @"%SYSTEM32%\wbem\Repository\",
        @"%SYSTEM32%\sessions\",
        @"%SYSTEM32%\config\",
        @"%SYSTEM32%\Tasks\Microsoft\",
        @"%PROGRAMDATA%\Microsoft\Windows Defender\",
        @"%PROGRAMDATA%\Microsoft\Windows\WER\",
        @"%PROGRAMDATA%\USOShared\",
        @"%LOCALAPPDATA%\Microsoft\Windows\INetCache\",
        @"%LOCALAPPDATA%\Microsoft\Windows\Explorer\",
        @"%LOCALAPPDATA%\Microsoft\Windows\WebCache\",
        @"%LOCALAPPDATA%\Temp\__PSScriptPolicyTest",
    };

    public ScoredArtifact Score(Observation o)
    {
        var reasons = new List<string>();
        int score = 0;

        string token = o.Category == EventCategory.File ? _paths.Tokenize(o.Target) : o.Target;
        string extension = Path.GetExtension(token);

        bool executable = ExecutableExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
        bool script = ScriptExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);

        switch (o.Category)
        {
            case EventCategory.Autorun:
                score += 45;
                reasons.Add("registers the program to start automatically");
                break;

            case EventCategory.Service:
                score += 45;
                reasons.Add("installs or modifies a Windows service, which runs before any user logs in");
                break;

            case EventCategory.ScheduledTask:
                score += 40;
                reasons.Add("registers a scheduled task, which survives reboots and uninstalls");
                break;

            case EventCategory.Driver:
                score += 55;
                reasons.Add("loads code into the kernel");
                break;

            case EventCategory.Registry when IsAutostartKey(o.Target):
                score += 45;
                reasons.Add("writes to an auto-start location");
                break;
        }

        if (o.Category == EventCategory.File && o.Action.IsPersistentChange())
        {
            if (executable)
            {
                score += 25;
                reasons.Add("drops an executable");
            }
            else if (script)
            {
                score += 20;
                reasons.Add("drops a script, which runs with the user's privileges");
            }

            // An executable in a directory the user can write to needs no elevation to
            // replace later, which is why so much unwanted software installs there.
            if ((executable || script) && IsUserWritable(token))
            {
                score += 15;
                reasons.Add("placed in a user-writable location");
            }

            if ((executable || script) && token.StartsWith("%TEMP%", StringComparison.OrdinalIgnoreCase))
            {
                score += 10;
                reasons.Add("executable staged in a temporary directory");
            }

            if (_paths.IsSystemPath(token))
            {
                score += 20;
                reasons.Add("writes into a Windows-owned directory");
            }
        }

        if (o.Action == EventAction.RemoteThread)
        {
            // Rated above driver loading. Plenty of legitimate software ships a driver;
            // very little legitimate software starts a thread inside a process it does
            // not own, outside debuggers and security products. It is the strongest
            // single signal this scorer recognises — which is exactly why it has to be
            // right. See RemoteThreadWeight for what one measured session did with it.
            int weight = RemoteThreadWeight(o, reasons);
            score += weight;
        }

        if (o.Action is EventAction.KeySetSecurity or EventAction.FileSetSecurity)
        {
            score += 15;
            reasons.Add("changes permissions on an existing object");
        }

        if (o.Category == EventCategory.Security)
        {
            score += 40;
            reasons.Add("alters the machine's certificate trust");
        }

        // Talking to a raw address that no DNS lookup produced is characteristic of
        // hardcoded infrastructure. Common in updaters too, so it is a lead, not a verdict.
        if (o.Category == EventCategory.Network && o.Action == EventAction.Connect
            && System.Net.IPAddress.TryParse(StripPort(o.Target), out _))
        {
            score += 10;
            reasons.Add("connects to a literal IP address");
        }

        if (o.Status == EventStatus.AccessDenied)
        {
            score += 10;
            reasons.Add("attempted something it was not permitted to do");
        }

        // Evidence quality adjusts the score rather than being ignored: an unattributed
        // change is still a change, but it is a weaker basis for a conclusion.
        if (o.Confidence == AttributionConfidence.None && o.Source != EvidenceSource.SnapshotDiff)
        {
            score -= 10;
            reasons.Add("could not be attributed to a process");
        }

        if (IsBackgroundChurn(o, token))
        {
            reasons.Clear();
            reasons.Add("a directory Windows maintains, written by Windows");
            return new ScoredArtifact(o, RiskLevel.None, 0, reasons);
        }

        return new ScoredArtifact(o, ToRisk(score), score, reasons);
    }

    /// <summary>
    /// True when this is the operating system keeping house.
    /// </summary>
    /// <remarks>
    /// Both halves are required. The path being an OS-managed cache is not enough on its
    /// own — something unknown writing into the Windows Update download directory is
    /// among the most interesting things a session can contain — so the actor also has to
    /// be code Microsoft signed. When the process table is unavailable nothing is
    /// suppressed, because "cannot tell who did it" must never read as "nothing happened".
    /// </remarks>
    private bool IsBackgroundChurn(Observation o, string token)
    {
        if (o.Category != EventCategory.File) return false;

        // The tool's own tracing session. Observing yourself observing is not evidence,
        // and a report whose top file findings are the recorder's own buffers reads as
        // though the subject did nothing — measured on a real capture.
        if (token.Contains("EtwRTCaYaTrace", StringComparison.OrdinalIgnoreCase)) return true;

        if (!OsManagedChurn.Any(prefix => token.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
            return false;

        ProcessNode? actor = _lookup?.Invoke(o.Actor);
        return actor is not null && IsMicrosoftSigned(actor);
    }

    /// <summary>
    /// Scores a stream and returns the highest-ranked artifacts.
    /// </summary>
    /// <remarks>
    /// Capped per category as well as overall. Without that, one category with a long
    /// tail fills the list on its own and the report reads as though nothing else
    /// happened: a measured session put 1,933 file rows and two service rows in front of
    /// an analyst, when the two service rows were the entire story.
    /// </remarks>
    public IReadOnlyList<ScoredArtifact> TopFindings(IEnumerable<Observation> observations, int limit = 40)
    {
        var byArtifact = new Dictionary<string, ScoredArtifact>(StringComparer.OrdinalIgnoreCase);

        foreach (Observation o in observations)
        {
            if (!o.Action.IsPersistentChange()
                && o.Action is not (EventAction.RemoteThread or EventAction.Connect)) continue;

            ScoredArtifact scored = Score(o);
            if (scored.Score <= 0) continue;

            // The same artifact touched repeatedly is one finding, not many.
            string key = scored.Describe();
            if (byArtifact.TryGetValue(key, out ScoredArtifact? existing) && existing.Score >= scored.Score)
                continue;

            byArtifact[key] = scored;
        }

        // Half the list is reserved for the categories that are not the loudest one, so
        // a service installation is never pushed off the page by file writes.
        int perCategory = Math.Max(10, limit / 2);
        var taken = new Dictionary<EventCategory, int>();
        var result = new List<ScoredArtifact>(Math.Min(limit, byArtifact.Count));
        var overflow = new List<ScoredArtifact>();

        foreach (ScoredArtifact scored in byArtifact.Values
                     .OrderByDescending(static s => s.Score)
                     .ThenBy(static s => s.Observation.Timestamp))
        {
            EventCategory category = scored.Observation.Category;
            int used = taken.GetValueOrDefault(category);

            if (used >= perCategory) { overflow.Add(scored); continue; }
            if (result.Count >= limit) break;

            taken[category] = used + 1;
            result.Add(scored);
        }

        // Anything held back by the per-category cap still fills the remaining room, so
        // the cap shortens a dominant category rather than shrinking the whole list.
        foreach (ScoredArtifact scored in overflow)
        {
            if (result.Count >= limit) break;
            result.Add(scored);
        }

        return result
            .OrderByDescending(static s => s.Score)
            .ThenBy(static s => s.Observation.Timestamp)
            .ToList();
    }

    /// <summary>
    /// How much a cross-process thread creation is worth, given who did it to whom.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Measured, not assumed. One 485,000-event session produced <b>61 critical "code
    /// injection" findings</b> at the top of its report, and every single one was a
    /// Windows component acting on another Windows component: service hosts, the audio
    /// graph, the print spooler, the consent dialog, memory compression, the update
    /// workers, the shell's runtime broker. Windows creates threads across process
    /// boundaries constantly and it is not injection. A report whose first 61 entries are
    /// wrong is a report nobody reads to entry 62.
    /// </para>
    /// <para>
    /// The trust test is the <b>code signature</b>, deliberately not the path. Software
    /// that wants to look like Windows stages itself inside the Windows directory — the
    /// sample this was tuned against installs to <c>%WINDIR%\SysWOW64\7669\</c> and names
    /// its binaries in hex — so a path rule would have suppressed the one finding that
    /// mattered while keeping all 61 that did not. A signature can be checked; a
    /// directory can only be occupied.
    /// </para>
    /// <para>
    /// Unsigned or unverifiable is treated as untrusted, so an unknown binary is judged,
    /// not excused. When the process table is unavailable the finding is kept at full
    /// weight: a session that cannot tell who did it should say so loudly rather than go
    /// quiet.
    /// </para>
    /// </remarks>
    private int RemoteThreadWeight(Observation o, List<string> reasons)
    {
        const int Injection = 70;

        ProcessNode? injector = _lookup?.Invoke(o.Actor);
        ProcessNode? owner = _lookup is null ? null : LookupOwner(o);

        if (injector is null || owner is null)
        {
            reasons.Add("creates a thread inside another process, which is code injection");
            return Injection;
        }

        // The same program, in two processes. Browsers, anything built on Chromium or
        // Electron, and plenty of services split themselves across processes and create
        // threads in their own siblings as a matter of design. Measured: three critical
        // findings in one capture, all of them one instance of an editor starting a
        // thread in another instance of the same editor.
        if (injector.ImagePath is { Length: > 0 } injectorImage
            && owner.ImagePath is { Length: > 0 } ownerImage
            && injectorImage.Equals(ownerImage, StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("one instance of a program started a thread in another instance of itself");
            return 0;
        }

        bool injectorTrusted = IsMicrosoftSigned(injector);
        bool ownerTrusted = IsMicrosoftSigned(owner);

        if (injectorTrusted && ownerTrusted)
        {
            // Both ends are Microsoft-signed. This is Windows working, and reporting it
            // buries everything that is not.
            reasons.Add("one Windows component started a thread in another, which is routine");
            return 0;
        }

        if (injectorTrusted)
        {
            // A signed Microsoft binary reaching into something else. Debuggers, the
            // shell and security products do this legitimately, so it is a lead rather
            // than a verdict.
            reasons.Add($"{injector.ImageName} started a thread inside {owner.ImageName}");
            return 25;
        }

        // A signature nobody checked is not the same as one that failed. Signature
        // verification runs in the background and does not always finish before a
        // session ends, so treating "unknown" as "untrusted" claims a certainty this
        // does not have — and critical severity is exactly where that matters.
        if (injector.Signature == SignatureState.Unchecked)
        {
            reasons.Add(
                $"{injector.ImageName} creates a thread inside {owner.ImageName}; its signature was not verified");
            return 55;
        }

        reasons.Add($"{injector.ImageName} creates a thread inside {owner.ImageName}, which is code injection");
        return Injection;
    }

    /// <summary>
    /// The process a remote thread was created in.
    /// </summary>
    /// <remarks>
    /// Read from the observation's details rather than parsed out of the display string,
    /// because "svchost.exe (1234)" is written for a person and a pid alone cannot
    /// distinguish a process from the one that reused its id.
    /// </remarks>
    private ProcessNode? LookupOwner(Observation o)
    {
        if (o.Details is not { Length: > 0 } details) return null;

        const string Marker = "\"owner\":\"";
        int start = details.IndexOf(Marker, StringComparison.Ordinal);
        if (start < 0) return null;

        start += Marker.Length;
        int end = details.IndexOf('"', start);
        if (end < 0) return null;

        return ProcessKey.TryParse(details[start..end], out ProcessKey key) ? _lookup?.Invoke(key) : null;
    }

    /// <summary>
    /// The shared trust test; see <see cref="ProcessNode.IsMicrosoftSigned"/> for why it
    /// is a signature check rather than a path check.
    /// </summary>
    private static bool IsMicrosoftSigned(ProcessNode node) => node.IsMicrosoftSigned();

    private static RiskLevel ToRisk(int score) => score switch
    {
        >= 70 => RiskLevel.Critical,
        >= 45 => RiskLevel.High,
        >= 25 => RiskLevel.Medium,
        >= 10 => RiskLevel.Low,
        > 0 => RiskLevel.Info,
        _ => RiskLevel.None,
    };

    private static bool IsAutostartKey(string target)
        => AutostartKeys.Any(k => target.Contains(k, StringComparison.OrdinalIgnoreCase));

    private static bool IsUserWritable(string token)
        => token.StartsWith("%APPDATA%", StringComparison.OrdinalIgnoreCase)
           || token.StartsWith("%LOCALAPPDATA%", StringComparison.OrdinalIgnoreCase)
           || token.StartsWith("%TEMP%", StringComparison.OrdinalIgnoreCase)
           || token.StartsWith("%USERPROFILE%", StringComparison.OrdinalIgnoreCase)
           || token.StartsWith("%PUBLIC%", StringComparison.OrdinalIgnoreCase)
           || token.StartsWith("%PROGRAMDATA%", StringComparison.OrdinalIgnoreCase);

    private static string StripPort(string endpoint)
    {
        if (endpoint.StartsWith('['))
        {
            int close = endpoint.IndexOf(']');
            return close > 0 ? endpoint[1..close] : endpoint;
        }
        int colon = endpoint.LastIndexOf(':');
        return colon > 0 ? endpoint[..colon] : endpoint;
    }
}
