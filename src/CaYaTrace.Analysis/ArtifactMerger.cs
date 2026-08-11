using CaYaTrace.Core.Model;

namespace CaYaTrace.Analysis;

/// <summary>How consistently an artifact appeared across the machines observed.</summary>
public enum Consistency
{
    /// <summary>Seen on every machine. Fixed behaviour; safe to build a plan around.</summary>
    Universal = 0,

    /// <summary>Seen on most but not all. Conditional behaviour, or a missed capture.</summary>
    Common = 1,

    /// <summary>
    /// Seen on one machine only. Either machine-specific randomness, or something the
    /// program did exactly once — the two are worth telling apart.
    /// </summary>
    Unique = 2,
}

/// <summary>One artifact as it appeared across every machine that observed it.</summary>
public sealed class MergedArtifact
{
    public required EventCategory Category { get; init; }

    public required EventAction Action { get; init; }

    /// <summary>The artifact with its run-specific parts marked.</summary>
    public required PathTemplate Template { get; init; }

    /// <summary>Concrete value seen on each machine, keyed by origin id.</summary>
    public Dictionary<string, string> ByOrigin { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Total machines in the comparison, including those that did not see this.</summary>
    public int TotalOrigins { get; init; }

    public int SeenOn => ByOrigin.Count;

    public Consistency Consistency => SeenOn switch
    {
        _ when TotalOrigins <= 1 => Consistency.Unique,
        _ when SeenOn == TotalOrigins => Consistency.Universal,
        1 => Consistency.Unique,
        _ => Consistency.Common,
    };

    /// <summary>Representative observations, one per origin, for drilling into evidence.</summary>
    public List<long> Evidence { get; } = new();

    public string? OldValue { get; set; }

    public string? NewValue { get; set; }

    public override string ToString() => $"{Action} {Template.Pattern} [{SeenOn}/{TotalOrigins}]";
}

public sealed class MergeReport
{
    public required IReadOnlyList<string> Origins { get; init; }

    public required IReadOnlyList<MergedArtifact> Artifacts { get; init; }

    public IEnumerable<MergedArtifact> Universal => Artifacts.Where(static a => a.Consistency == Consistency.Universal);

    public IEnumerable<MergedArtifact> Varying => Artifacts.Where(static a => a.Template.HasVariables);

    public IEnumerable<MergedArtifact> OneOff => Artifacts.Where(static a => a.Consistency == Consistency.Unique);

    /// <summary>Short summary for the comparison header.</summary>
    public string Summarize()
        => $"{Artifacts.Count:N0} artifacts across {Origins.Count} machines · " +
           $"{Universal.Count():N0} on all · {Varying.Count():N0} with run-specific names · " +
           $"{OneOff.Count():N0} seen once";
}

/// <summary>
/// Combines observations of the same program from several machines into one picture.
/// </summary>
/// <remarks>
/// <para>
/// The point is not to diff two files. Running the same installer on two VMs produces
/// two artifact sets that differ in ways that are meaningless — a random working
/// directory, a per-install GUID, a timestamped log — and a plain diff reports all of
/// it as a difference. What an analyst wants is the opposite: the parts that are the
/// same every time, which are the program's actual behaviour, separated from the parts
/// that are not, which are noise.
/// </para>
/// <para>
/// Getting there needs alignment before comparison. Artifacts are grouped by a coarse
/// shape — same category, same verb, same depth, same fixed anchors — and only then are
/// the differing segments read off as variables. That is what turns
/// <c>%APPDATA%\a8f3c1\svc.exe</c> and <c>%APPDATA%\d92b47\svc.exe</c> into one finding
/// rather than two.
/// </para>
/// </remarks>
public sealed class ArtifactMerger
{
    /// <summary>
    /// Merges persistent-change observations from several machines.
    /// </summary>
    /// <param name="byOrigin">Observations keyed by the machine that produced them.</param>
    public MergeReport Merge(IReadOnlyDictionary<string, IReadOnlyList<Observation>> byOrigin)
    {
        var origins = byOrigin.Keys.ToList();

        // Coarse grouping first. Two artifacts can only be the same thing if they share
        // a verb, a depth, and their non-variable anchor points; comparing across those
        // boundaries produces alignments that are arbitrary.
        var buckets = new Dictionary<string, List<(string Origin, Observation Observation)>>(StringComparer.OrdinalIgnoreCase);

        foreach ((string origin, IReadOnlyList<Observation> observations) in byOrigin)
        {
            foreach (Observation o in observations)
            {
                if (!o.Action.IsPersistentChange()) continue;

                string bucket = BucketKey(o);
                if (!buckets.TryGetValue(bucket, out List<(string, Observation)>? list))
                {
                    list = new List<(string, Observation)>();
                    buckets[bucket] = list;
                }
                list.Add((origin, o));
            }
        }

        var artifacts = new List<MergedArtifact>(buckets.Count);

        foreach ((string _, List<(string Origin, Observation Observation)> members) in buckets)
        {
            // One representative per machine: an installer that writes the same file
            // twice should not count as two machines' agreement.
            var perOrigin = new Dictionary<string, Observation>(StringComparer.OrdinalIgnoreCase);
            foreach ((string origin, Observation observation) in members)
                perOrigin.TryAdd(origin, observation);

            List<string> targets = perOrigin.Values.Select(static o => o.Target).ToList();

            PathTemplate? template = perOrigin.Count > 1
                ? PathTemplater.FromObservations(targets)
                : PathTemplater.Infer(targets[0]);

            // Differing depths within a bucket mean the coarse key was too permissive;
            // fall back to per-path templates rather than forcing a bad alignment.
            template ??= PathTemplater.Infer(targets[0]);

            Observation first = perOrigin.Values.First();
            var artifact = new MergedArtifact
            {
                Category = first.Category,
                Action = first.Action,
                Template = template,
                TotalOrigins = origins.Count,
                OldValue = first.OldValue,
                NewValue = first.NewValue,
            };

            foreach ((string origin, Observation observation) in perOrigin)
            {
                artifact.ByOrigin[origin] = observation.Target;
                artifact.Evidence.Add(observation.Seq);
            }

            artifacts.Add(artifact);
        }

        artifacts.Sort(static (a, b) =>
        {
            int byConsistency = a.Consistency.CompareTo(b.Consistency);
            return byConsistency != 0
                ? byConsistency
                : string.Compare(a.Template.Pattern, b.Template.Pattern, StringComparison.OrdinalIgnoreCase);
        });

        return new MergeReport { Origins = origins, Artifacts = artifacts };
    }

    /// <summary>
    /// The coarse alignment key.
    /// </summary>
    /// <remarks>
    /// Uses the verb, the depth, the root token, and the leaf. Those are the parts that
    /// stay put when only a working-directory name is randomized — which is the case
    /// this exists to handle. Intermediate segments are left out precisely because they
    /// are where the variation lives.
    /// </remarks>
    private static string BucketKey(Observation o)
    {
        string[] parts = PathTemplate.Split(o.Target);
        string root = parts.Length > 0 ? parts[0] : string.Empty;
        string leaf = parts.Length > 0 ? parts[^1] : string.Empty;

        // A leaf that is itself randomized would split a bucket that should hold
        // together — the creation of the random directory, as opposed to the files
        // inside it — so it is generalized when it looks generated.
        //
        // The permissive test is correct here even though the strict one governs
        // removal. Bucketing only decides what gets *compared*; being too eager costs
        // a bad alignment, which the segment-agreement check then rejects. Being too
        // timid costs a missed merge, which shows up as the same artifact reported
        // twice as machine-specific. The asymmetry favours merging.
        if (PathTemplater.LooksVariable(leaf))
            leaf = $"*{Path.GetExtension(leaf)}";

        return $"{o.Category}|{o.Action}|{parts.Length}|{root}|{leaf}|{o.Target2}".ToUpperInvariant();
    }
}
