using System.Diagnostics;
using System.Text.Json.Serialization;

namespace CaYaTrace.Analysis.Ai;

public enum ModelSuitability
{
    /// <summary>Cannot produce valid structured output. Do not use.</summary>
    Unusable = 0,

    /// <summary>Valid output, but it fabricates or guesses. Labels only, no prose.</summary>
    Limited = 1,

    /// <summary>Reliable on the classification tasks this pipeline issues.</summary>
    Suitable = 2,
}

public sealed record ModelAssessment(
    string Model,
    ModelSuitability Suitability,
    int Correct,
    int Total,
    int SchemaFailures,
    int GroundingFailures,
    TimeSpan AverageLatency,
    IReadOnlyList<string> Notes)
{
    public double Accuracy => Total == 0 ? 0 : (double)Correct / Total;

    public string Summarize()
        => $"{Model}: {Suitability.ToString().ToLowerInvariant()} — " +
           $"{Correct}/{Total} correct, {SchemaFailures} malformed, {GroundingFailures} fabricated, " +
           $"{AverageLatency.TotalSeconds:F1}s per item";
}

/// <summary>
/// Measures whether a local model is good enough to be trusted, before it is used.
/// </summary>
/// <remarks>
/// <para>
/// Local models vary enormously, and the bad ones fail quietly rather than loudly: they
/// return a well-formed answer that happens to be wrong. Measured on one developer
/// machine, given an identical autostart artifact and an identical schema, a 1B model
/// answered <c>persistence</c> correctly while a 0.5B coder model answered <c>unknown</c> and a
/// 0.8B model answered <c>unknown</c> while citing an evidence id that did not exist.
/// </para>
/// <para>
/// So the pipeline does not assume. It runs a handful of probes with known answers,
/// scores the model on three axes that matter — does it obey the schema, is it right,
/// does it invent references — and downgrades what the model is allowed to do
/// accordingly. A model that fails grounding is still useful for labelling but is never
/// permitted to write prose an analyst might read as fact.
/// </para>
/// <para>
/// The probes are deliberately drawn from unambiguous Windows behaviour, so a wrong
/// answer reflects the model rather than a debatable judgement call.
/// </para>
/// </remarks>
public sealed class ModelCapability
{
    private readonly OllamaClient _client;

    public ModelCapability(OllamaClient client) => _client = client;

    private sealed record Probe(int EvidenceId, string Artifact, string Expected);

    /// <summary>
    /// Known-answer probes. Each has one defensible label; a model that misses several
    /// is guessing rather than reasoning about Windows.
    /// </summary>
    private static readonly Probe[] Probes =
    {
        new(7,  @"a registry value was created at HKCU\Software\Microsoft\Windows\CurrentVersion\Run "
              + @"named Updater pointing to %APPDATA%\Vendor\upd.exe",
            "persistence"),

        new(12, @"a file was written at %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\f_00021b",
            "cache"),

        new(19, @"a Windows service named VendorSync was installed with image path "
              + @"%PROGRAMFILES%\Vendor\sync.exe",
            "persistence"),

        new(23, @"a file was written at %PROGRAMDATA%\Vendor\logs\install-2026-08-11.log",
            "log"),

        new(31, @"a file was created at %APPDATA%\Vendor\settings.json",
            "config"),
    };

    internal const string LabelInstruction =
        "Labels: persistence = makes the program run again automatically after reboot or logon; " +
        "config = stores settings; cache = temporary reusable data; log = a record of what happened; " +
        "unknown = none of these fit.";

    internal static readonly object ClassificationSchema = new Dictionary<string, object>
    {
        ["type"] = "object",
        ["properties"] = new Dictionary<string, object>
        {
            ["evidence_id"] = new Dictionary<string, object> { ["type"] = "integer" },
            ["label"] = new Dictionary<string, object>
            {
                ["type"] = "string",
                ["enum"] = new[] { "persistence", "config", "cache", "log", "unknown" },
            },
            ["confidence"] = new Dictionary<string, object>
            {
                ["type"] = "string",
                ["enum"] = new[] { "low", "medium", "high" },
            },
        },
        ["required"] = new[] { "evidence_id", "label", "confidence" },
    };

    internal sealed class Classification
    {
        [JsonPropertyName("evidence_id")] public int EvidenceId { get; set; }
        [JsonPropertyName("label")] public string Label { get; set; } = "unknown";
        [JsonPropertyName("confidence")] public string Confidence { get; set; } = "low";
    }

    public async Task<ModelAssessment> AssessAsync(string model, CancellationToken cancellationToken = default)
    {
        int correct = 0, schemaFailures = 0, groundingFailures = 0;
        var latencies = new List<TimeSpan>();
        var notes = new List<string>();

        foreach (Probe probe in Probes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string prompt = BuildPrompt(probe.EvidenceId, probe.Artifact);
            var stopwatch = Stopwatch.StartNew();

            Classification? answer;
            try
            {
                answer = await _client.GenerateAsync<Classification>(
                    model, prompt, ClassificationSchema, maxTokens: 160,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch (OllamaException ex)
            {
                notes.Add($"probe {probe.EvidenceId} failed: {ex.Message}");
                schemaFailures++;
                continue;
            }
            finally
            {
                stopwatch.Stop();
                latencies.Add(stopwatch.Elapsed);
            }

            if (answer is null)
            {
                schemaFailures++;
                continue;
            }

            // Citing an id it was not given is the clearest signal a model is
            // generating rather than reading.
            if (answer.EvidenceId != probe.EvidenceId)
            {
                groundingFailures++;
                notes.Add($"cited evidence {answer.EvidenceId} when asked about {probe.EvidenceId}");
            }

            if (string.Equals(answer.Label, probe.Expected, StringComparison.OrdinalIgnoreCase))
                correct++;
        }

        TimeSpan average = latencies.Count == 0
            ? TimeSpan.Zero
            : TimeSpan.FromTicks((long)latencies.Average(static l => l.Ticks));

        ModelSuitability suitability = Judge(correct, Probes.Length, schemaFailures, groundingFailures, notes);

        return new ModelAssessment(model, suitability, correct, Probes.Length,
            schemaFailures, groundingFailures, average, notes);
    }

    private static ModelSuitability Judge(int correct, int total, int schemaFailures, int groundingFailures,
        List<string> notes)
    {
        // Any inability to produce the requested shape disqualifies the model: every
        // downstream step parses structured output.
        if (schemaFailures > 0)
        {
            notes.Add("produced malformed output; this model cannot be used for analysis");
            return ModelSuitability.Unusable;
        }

        if (groundingFailures > 0)
        {
            notes.Add("referenced evidence it was not shown; restricted to labelling, " +
                      "and its labels are cross-checked against the deterministic score");
            return ModelSuitability.Limited;
        }

        // Three of five is the floor for being better than the built-in rules on the
        // cases the rules do not already cover.
        if (correct < 3)
        {
            notes.Add($"answered {correct} of {total} known cases correctly; " +
                      "too unreliable to add anything the deterministic scoring does not already provide");
            return ModelSuitability.Limited;
        }

        if (correct < total)
            notes.Add($"answered {correct} of {total} known cases correctly; treat its labels as suggestions");

        return ModelSuitability.Suitable;
    }

    /// <summary>
    /// Builds a single-item classification prompt.
    /// </summary>
    /// <remarks>
    /// One artifact per call, always. Batching several into one prompt is tempting for
    /// speed and is exactly what small models fail at: they lose track of which answer
    /// belongs to which item and start merging them. A call per item is slower in wall
    /// clock and far more accurate, and since schema-constrained replies finish in
    /// around a second the difference is tolerable.
    /// </remarks>
    internal static string BuildPrompt(int evidenceId, string artifact)
        => $"""
            You are labelling one artifact observed during Windows software analysis.

            {LabelInstruction}

            Artifact {evidenceId}: {artifact}.

            Reply with the JSON object for artifact {evidenceId} only.
            Set evidence_id to {evidenceId}.
            """;

    /// <summary>
    /// Assesses every installed model and ranks them.
    /// </summary>
    /// <remarks>
    /// Small models are probed first so an operator gets an answer quickly, and because
    /// the large ones are the ones worth waiting for if the small ones fail.
    /// </remarks>
    public async Task<IReadOnlyList<ModelAssessment>> AssessAllAsync(
        IEnumerable<OllamaModel> models,
        CancellationToken cancellationToken = default)
    {
        var results = new List<ModelAssessment>();

        foreach (OllamaModel model in models.OrderBy(static m => m.Billions))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                results.Add(await AssessAsync(model.Name, cancellationToken).ConfigureAwait(false));
            }
            catch (OllamaException ex)
            {
                results.Add(new ModelAssessment(model.Name, ModelSuitability.Unusable, 0, Probes.Length,
                    Probes.Length, 0, TimeSpan.Zero, new[] { ex.Message }));
            }
        }

        return results
            .OrderByDescending(static r => r.Suitability)
            .ThenByDescending(static r => r.Accuracy)
            .ThenBy(static r => r.AverageLatency)
            .ToList();
    }
}
