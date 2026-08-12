using CaYaTrace.Analysis;
using CaYaTrace.Analysis.Ai;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;
using CaYaTrace.Storage;

namespace CaYaTrace.App.Cli;

/// <summary>
/// Explains a session's most significant findings, optionally with a local model.
/// </summary>
/// <remarks>
/// Works without any model at all — the ranking, scoring, and reasons are rule-based.
/// A model adds labels on top and is measured before it is believed.
/// </remarks>
public static class ExplainCommand
{
    public static int Run(CommandLine cmd)
    {
        var endpoint = new Uri(cmd.Get("ollama") ?? "http://localhost:11434");
        using var client = new OllamaClient(endpoint);

        return cmd.Flag("check-models")
            ? CheckModels(cmd, client).GetAwaiter().GetResult()
            : Explain(cmd, client).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Scores every installed model against known-answer probes.
    /// </summary>
    /// <remarks>
    /// Exists because "local models give bad results" is usually a model-selection
    /// problem that the user has no way to see. Measuring turns it into a visible,
    /// comparable number.
    /// </remarks>
    private static async Task<int> CheckModels(CommandLine cmd, OllamaClient client)
    {
        if (!await client.IsAvailableAsync().ConfigureAwait(false))
        {
            Console.Error.WriteLine($"cayatrace: no Ollama instance at {client.Endpoint}");
            Console.Error.WriteLine("           Start it with `ollama serve`, or pass --ollama <url>.");
            return 3;
        }

        IReadOnlyList<OllamaModel> models = await client.ListModelsAsync().ConfigureAwait(false);
        if (models.Count == 0)
        {
            Console.Error.WriteLine("cayatrace: no models are installed. Try `ollama pull llama3.1`.");
            return 3;
        }

        // Probing a very large model costs minutes per item and, for this task, buys
        // nothing an 8B instruct model does not already deliver. They stay available
        // via --all for anyone who wants the measurement anyway.
        double sizeCap = cmd.Flag("all") ? double.MaxValue : cmd.Int("max-params", 24);

        List<OllamaModel> candidates = models
            .Where(m => !m.Name.EndsWith(":cloud", StringComparison.OrdinalIgnoreCase))
            .Where(m => m.Billions <= sizeCap || m.Billions == 0)
            .OrderBy(static m => m.Billions)
            .ToList();

        int skipped = models.Count - candidates.Count;

        Console.WriteLine($"Testing {candidates.Count} model(s) against known-answer probes.");
        Console.WriteLine("Each is asked to classify Windows artifacts whose correct label is not in dispute.");
        if (skipped > 0)
            Console.WriteLine($"Skipping {skipped} model(s): hosted remotely, or larger than {sizeCap:F0}B (use --all).");
        Console.WriteLine();

        var capability = new ModelCapability(client);
        var results = new List<ModelAssessment>();

        foreach (OllamaModel model in candidates)
        {
            // Written and flushed before the probe runs, so an operator watching a slow
            // model can see which one is taking the time. Without the flush this is
            // block-buffered when redirected and the whole run looks hung.
            Console.Write($"  {model.Name,-34} ");
            Console.Out.Flush();

            try
            {
                ModelAssessment assessment = await capability.AssessAsync(model.Name).ConfigureAwait(false);
                results.Add(assessment);
                Console.WriteLine(
                    $"{assessment.Suitability.ToString().ToLowerInvariant(),-9} " +
                    $"{assessment.Correct}/{assessment.Total} correct  " +
                    $"{assessment.AverageLatency.TotalSeconds,5:F1}s/item");
            }
            catch (OllamaException ex)
            {
                Console.WriteLine($"failed — {ex.Message}");
            }
        }

        ModelAssessment? best = results
            .Where(static r => r.Suitability == ModelSuitability.Suitable)
            .OrderByDescending(static r => r.Accuracy)
            .ThenBy(static r => r.AverageLatency)
            .FirstOrDefault();

        Console.WriteLine();
        if (best is not null)
        {
            Console.WriteLine($"Recommended: {best.Model}");
            Console.WriteLine($"  CaYaTrace explain --session <dir> --model {best.Model}");
        }
        else
        {
            Console.WriteLine("None of the installed models scored well enough to add anything.");
            Console.WriteLine("Findings are still produced from CaYaTrace's built-in rules — run `explain`");
            Console.WriteLine("without --model. For labelling, an 8B instruct model is usually the smallest");
            Console.WriteLine("that helps; coder-tuned and sub-1B models score poorly on this task.");
        }

        foreach (ModelAssessment result in results.Where(static r => r.Notes.Count > 0))
        {
            Console.WriteLine();
            Console.WriteLine($"{result.Model}:");
            foreach (string note in result.Notes.Distinct()) Console.WriteLine($"  · {note}");
        }

        return 0;
    }

    private static async Task<int> Explain(CommandLine cmd, OllamaClient client)
    {
        string path = ResolveSession(cmd.Require("session"));
        using SessionStore store = SessionStore.Open(path);

        SessionInfo? session = store.LoadSessionInfo();
        if (session is null)
        {
            Console.Error.WriteLine($"cayatrace: {path} does not contain a CaYaTrace session");
            return 1;
        }

        string? model = cmd.Get("model");
        if (model is not null && !await client.IsAvailableAsync().ConfigureAwait(false))
        {
            Console.Error.WriteLine($"cayatrace: no Ollama instance at {client.Endpoint}; continuing without a model.");
            model = null;
        }

        var inScope = new HashSet<ProcessKey>(
            store.LoadProcesses().Where(static p => p.InScope).Select(static p => p.Key));

        List<Observation> observations = store
            .Query(new ObservationQuery())
            .Where(o => cmd.Flag("include-out-of-scope")
                        || o.Actor == ProcessKey.None
                        || inScope.Contains(o.Actor))
            .ToList();

        var pipeline = new LocalAnalysisPipeline(client)
        {
            OnProgress = (index, total, what) =>
            {
                if (model is not null) Console.Error.Write($"\r  labelling {index}/{total}  {Shorten(what),-70}");
            },
        };

        AiReport report = await pipeline
            .AnalyzeAsync(observations, model, cmd.Int("max-findings", 30))
            .ConfigureAwait(false);

        if (model is not null) Console.Error.WriteLine();
        Render(session, report);
        return 0;
    }

    private static void Render(SessionInfo session, AiReport report)
    {
        Console.WriteLine();
        Console.WriteLine($"Findings for {session.Name}  ({session.StartedAt:u})");
        Console.WriteLine();

        if (report.Findings.Count == 0)
        {
            Console.WriteLine("No persistent changes were attributed to the subject.");
            return;
        }

        foreach (IGrouping<RiskLevel, AnnotatedFinding> group in report.Findings
                     .GroupBy(static f => f.Risk)
                     .OrderByDescending(static g => g.Key))
        {
            Console.WriteLine($"{group.Key.ToString().ToUpperInvariant()}  [{group.Count()}]");

            foreach (AnnotatedFinding finding in group)
            {
                Console.WriteLine($"  {finding.Artifact.Describe()}");

                foreach (string reason in finding.Artifact.Reasons)
                    Console.WriteLine($"      · {reason}");

                if (finding.Label is not null)
                    Console.WriteLine($"      model: {finding.Label} ({finding.LabelConfidence})");

                // Shown, never resolved: silently preferring one reading would present
                // a guess as a finding.
                if (finding.Disagreement is not null)
                    Console.WriteLine($"      ⚠ {finding.Disagreement}");
            }

            Console.WriteLine();
        }

        if (report.Caveats.Count > 0)
        {
            Console.WriteLine("ABOUT THIS ANALYSIS");
            foreach (string caveat in report.Caveats) Console.WriteLine($"  · {caveat}");
            Console.WriteLine();
        }

        Console.WriteLine(report.ModelWasUsed
            ? "Scores and reasons above are CaYaTrace's own; the model contributed only the labels."
            : "All findings above are rule-based. No model was involved.");
    }

    private static string Shorten(string value)
        => value.Length <= 70 ? value : "…" + value[^69..];

    private static string ResolveSession(string input)
    {
        string full = Path.GetFullPath(input);
        if (File.Exists(full)) return full;

        if (Directory.Exists(full))
        {
            string direct = Path.Combine(full, "session.ctdb");
            if (File.Exists(direct)) return direct;

            string? newest = Directory.EnumerateDirectories(full, "session_*")
                .Select(static d => Path.Combine(d, "session.ctdb"))
                .Where(File.Exists)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();

            if (newest is not null) return newest;
        }

        throw new CommandLineException($"session not found: {full}");
    }
}
