using System.Text;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Analysis.Ai;

/// <summary>One artifact, deterministically scored and optionally labelled by a model.</summary>
public sealed record AnnotatedFinding(
    ScoredArtifact Artifact,
    string? Label,
    string? LabelConfidence,
    bool ModelAgreesWithRules,
    string? Disagreement)
{
    public RiskLevel Risk => Artifact.Risk;

    /// <summary>File reputation, when a lookup was requested and the file was hashable.</summary>
    public Reputation.ReputationResult? Reputation { get; init; }
}

public sealed record AiReport(
    string? Model,
    ModelSuitability Suitability,
    IReadOnlyList<AnnotatedFinding> Findings,
    IReadOnlyList<string> Caveats)
{
    public bool ModelWasUsed => Model is not null && Suitability != ModelSuitability.Unusable;
}

/// <summary>
/// Produces an explained set of findings, using a local model only for the part it can
/// actually do.
/// </summary>
/// <remarks>
/// <para>
/// The governing decision is that <b>the model is never the analyst</b>. Ranking, scoring,
/// and every claim about what happened come from deterministic rules over the recorded
/// evidence. The model is handed one already-selected artifact at a time and asked a
/// single multiple-choice question about it. That is a task a 1B model can do; "analyse
/// this session" is not, and asking produces confident fabrication.
/// </para>
/// <para>Concretely, five constraints make weak models usable:</para>
/// <list type="number">
///   <item><description>
///     <b>Code picks what matters.</b> The model never sees the event firehose, only the
///     top-ranked artifacts, so it cannot miss the needle — it was handed one.
///   </description></item>
///   <item><description>
///     <b>One item per call, fixed label set.</b> Batching makes small models merge items
///     and mis-assign answers.
///   </description></item>
///   <item><description>
///     <b>Schema-constrained output.</b> Without it, small models do not answer the
///     question asked at all.
///   </description></item>
///   <item><description>
///     <b>Grounding is verified.</b> An answer citing an id it was not shown is discarded,
///     not displayed.
///   </description></item>
///   <item><description>
///     <b>Disagreement is surfaced, not resolved.</b> Where the model's label contradicts
///     the rules, both are shown. Silently preferring either one would be a guess
///     presented as a finding.
///   </description></item>
/// </list>
/// <para>
/// The consequence is that removing the model entirely degrades the report rather than
/// breaking it: the findings, scores, and reasons are all still there.
/// </para>
/// </remarks>
public sealed class LocalAnalysisPipeline
{
    private readonly OllamaClient _client;
    private readonly ArtifactScorer _scorer;

    public LocalAnalysisPipeline(OllamaClient client, ArtifactScorer? scorer = null)
    {
        _client = client;
        _scorer = scorer ?? new ArtifactScorer();
    }

    /// <summary>Progress callback, so a long run over forty artifacts is not silent.</summary>
    public Action<int, int, string>? OnProgress { get; init; }

    public async Task<AiReport> AnalyzeAsync(
        IEnumerable<Observation> observations,
        string? model,
        int maxFindings = 30,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<ScoredArtifact> ranked = _scorer.TopFindings(observations, maxFindings);
        var caveats = new List<string>();

        if (model is null)
        {
            return new AiReport(null, ModelSuitability.Unusable,
                ranked.Select(static a => new AnnotatedFinding(a, null, null, true, null)).ToList(),
                new[] { "No model was selected; findings come from CaYaTrace's built-in rules only." });
        }

        // The model is measured before it is trusted. A run against an unvetted model
        // is how an analyst ends up reading fabrication as fact.
        ModelAssessment assessment;
        try
        {
            assessment = await new ModelCapability(_client).AssessAsync(model, cancellationToken).ConfigureAwait(false);
        }
        catch (OllamaException ex)
        {
            return new AiReport(model, ModelSuitability.Unusable,
                ranked.Select(static a => new AnnotatedFinding(a, null, null, true, null)).ToList(),
                new[] { $"Could not reach the model ({ex.Message}); showing rule-based findings only." });
        }

        caveats.Add(assessment.Summarize());
        caveats.AddRange(assessment.Notes);

        if (assessment.Suitability == ModelSuitability.Unusable)
        {
            caveats.Add("The model was not used. Findings below are entirely rule-based and unaffected.");
            return new AiReport(model, ModelSuitability.Unusable,
                ranked.Select(static a => new AnnotatedFinding(a, null, null, true, null)).ToList(), caveats);
        }

        // A model that fabricated during assessment gets its answers cross-checked
        // harder, and repeated sampling to catch instability.
        int samples = assessment.Suitability == ModelSuitability.Limited ? 3 : 1;

        var findings = new List<AnnotatedFinding>(ranked.Count);
        int index = 0;

        foreach (ScoredArtifact artifact in ranked)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OnProgress?.Invoke(++index, ranked.Count, artifact.Describe());

            (string? label, string? confidence) = await ClassifyAsync(
                model, index, artifact, samples, cancellationToken).ConfigureAwait(false);

            string? disagreement = CheckAgainstRules(artifact, label);
            findings.Add(new AnnotatedFinding(artifact, label, confidence, disagreement is null, disagreement));
        }

        int disagreements = findings.Count(static f => !f.ModelAgreesWithRules);
        if (disagreements > 0)
        {
            caveats.Add($"{disagreements} of {findings.Count} labels contradict the built-in rules. " +
                        "Both readings are shown; the rules are the ones derived from the recorded evidence.");
        }

        return new AiReport(model, assessment.Suitability, findings, caveats);
    }

    /// <summary>
    /// Classifies one artifact, optionally sampling several times and taking the
    /// majority.
    /// </summary>
    /// <remarks>
    /// Voting exists for the unstable models. A model that returns three different
    /// labels for one artifact has no opinion, and reporting the first of them as
    /// though it did would be inventing certainty.
    /// </remarks>
    private async Task<(string? Label, string? Confidence)> ClassifyAsync(
        string model, int evidenceId, ScoredArtifact artifact, int samples, CancellationToken cancellationToken)
    {
        var votes = new List<ModelCapability.Classification>(samples);

        for (int i = 0; i < samples; i++)
        {
            ModelCapability.Classification? answer;
            try
            {
                answer = await _client.GenerateAsync<ModelCapability.Classification>(
                    model,
                    ModelCapability.BuildPrompt(evidenceId, Describe(artifact)),
                    ModelCapability.ClassificationSchema,
                    maxTokens: 160,
                    // Varying the seed is what makes repeated sampling informative;
                    // identical seeds would just repeat one answer.
                    seed: 42 + i,
                    temperature: samples > 1 ? 0.3 : 0,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch (OllamaException)
            {
                continue;
            }

            // Grounding check: an answer about an artifact it was not shown is discarded.
            if (answer is null || answer.EvidenceId != evidenceId) continue;
            if (!ValidLabels.Contains(answer.Label, StringComparer.OrdinalIgnoreCase)) continue;

            votes.Add(answer);
        }

        if (votes.Count == 0) return (null, null);

        IGrouping<string, ModelCapability.Classification> winner = votes
            .GroupBy(static v => v.Label.ToLowerInvariant())
            .OrderByDescending(static g => g.Count())
            .First();

        // No majority means no opinion.
        if (samples > 1 && winner.Count() * 2 <= samples) return (null, null);

        return (winner.Key, winner.First().Confidence);
    }

    private static readonly string[] ValidLabels = { "persistence", "config", "cache", "log", "unknown" };

    /// <summary>
    /// Compares the model's label against what the rules already established.
    /// </summary>
    /// <remarks>
    /// The rules know, from the recorded evidence, whether an artifact sits on an
    /// autostart surface. If the model calls that "cache", the model is wrong, and
    /// saying so is more useful than hiding it — it also tells the analyst how much
    /// weight the rest of that model's labels deserve.
    /// </remarks>
    private static string? CheckAgainstRules(ScoredArtifact artifact, string? label)
    {
        if (label is null) return null;

        // Keyed on what the scorer actually found, not on the category alone. A plain
        // registry write to a Run key is categorised as Registry but is functionally
        // autostart, and the scorer already said so in its reasons — checking the
        // category would let exactly that case slip through unflagged.
        bool rulesSayPersistence =
            artifact.Observation.Category
                is EventCategory.Autorun or EventCategory.Service or EventCategory.ScheduledTask or EventCategory.Driver
            || artifact.Reasons.Any(static r =>
                r.Contains("auto-start", StringComparison.OrdinalIgnoreCase)
                || r.Contains("start automatically", StringComparison.OrdinalIgnoreCase)
                || r.Contains("before any user logs in", StringComparison.OrdinalIgnoreCase));

        if (rulesSayPersistence && !label.Equals("persistence", StringComparison.OrdinalIgnoreCase))
        {
            return $"the model called this '{label}', but the recorded evidence puts it on " +
                   "an auto-start surface";
        }

        if (!rulesSayPersistence && label.Equals("persistence", StringComparison.OrdinalIgnoreCase)
            && artifact.Risk < RiskLevel.Medium)
        {
            return "the model called this 'persistence', but it is not on any auto-start surface " +
                   "CaYaTrace recognises";
        }

        return null;
    }

    /// <summary>
    /// Renders an artifact for the prompt.
    /// </summary>
    /// <remarks>
    /// Plain prose, no JSON, no field names. Small models read English far better than
    /// they read a serialized structure, and every token spent on syntax is one not
    /// spent on the fact.
    /// </remarks>
    private static string Describe(ScoredArtifact artifact)
    {
        Observation o = artifact.Observation;

        var sb = new StringBuilder();
        sb.Append(o.Category switch
        {
            EventCategory.File => "a file was ",
            EventCategory.Registry => "a registry entry was ",
            EventCategory.Service => "a Windows service was ",
            EventCategory.ScheduledTask => "a scheduled task was ",
            EventCategory.Autorun => "an auto-start entry was ",
            EventCategory.Network => "a network connection was ",
            _ => "something was ",
        });

        sb.Append(o.Action switch
        {
            EventAction.FileCreate or EventAction.DirectoryCreate or EventAction.KeyCreate => "created",
            EventAction.FileWrite or EventAction.ValueSet => "written",
            EventAction.FileDelete or EventAction.KeyDelete or EventAction.ValueDelete => "deleted",
            EventAction.FileRename => "renamed",
            EventAction.ServiceInstall or EventAction.TaskRegister or EventAction.AutorunAdd => "installed",
            EventAction.Connect => "opened",
            _ => o.Action.ToString().ToLowerInvariant(),
        });

        sb.Append(" at ").Append(o.Target);
        if (o.Target2 is { Length: > 0 }) sb.Append(" named ").Append(o.Target2);
        if (o.NewValue is { Length: > 0 }) sb.Append(" with the value ").Append(Trim(o.NewValue));

        return sb.ToString();
    }

    private static string Trim(string value) => value.Length <= 120 ? value : value[..120] + "…";
}
