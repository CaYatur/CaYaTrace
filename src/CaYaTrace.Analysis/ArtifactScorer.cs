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

    public ArtifactScorer(PathNormalizer? paths = null)
        => _paths = paths ?? PathNormalizer.CreateForCurrentMachine();

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
            // single signal this scorer recognises.
            score += 70;
            reasons.Add("creates a thread inside another process, which is code injection");
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

        return new ScoredArtifact(o, ToRisk(score), score, reasons);
    }

    /// <summary>Scores a stream and returns the highest-ranked artifacts.</summary>
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

        return byArtifact.Values
            .OrderByDescending(static s => s.Score)
            .ThenBy(static s => s.Observation.Timestamp)
            .Take(limit)
            .ToList();
    }

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
