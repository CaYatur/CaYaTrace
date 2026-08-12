using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using CaYaTrace.Analysis;
using CaYaTrace.Analysis.Ai;
using CaYaTrace.Analysis.Reputation;
using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;
using CaYaTrace.Export;
using CaYaTrace.Remediation;
using CaYaTrace.Storage;

namespace CaYaTrace.App.Modes;

/// <summary>
/// Everything the workbench does to a session that has already been recorded: export,
/// removal planning, multi-machine comparison, and the local-model assistant.
/// </summary>
public sealed partial class WorkbenchWindow
{
    private List<RemovalItem> _planItems = new();
    private string? _quarantineRoot;

    /// <summary>
    /// A VirusTotal key typed into the workbench, held for this process only.
    /// </summary>
    /// <remarks>
    /// Never written to <see cref="UserSettings"/> and never included in an export. The
    /// convenience of remembering it is not worth turning a one-off into a credential
    /// sitting in a plaintext file in the user profile.
    /// </remarks>
    private string? _virusTotalKey;

    // ------------------------------------------------------------------- export

    private void ExportSession(JsonElement payload)
    {
        if (_store is null || _session is null) return;

        string formatName = Str(payload, "format") ?? "html";
        string scopeName = Str(payload, "scope") ?? "standard";

        ExportFormat format = formatName switch
        {
            "json" => ExportFormat.Json,
            "csv" => ExportFormat.Csv,
            "tree" => ExportFormat.Tree,
            "package" => ExportFormat.Package,
            _ => ExportFormat.Html,
        };

        var request = new ExportRequest
        {
            Format = format,
            Scope = scopeName switch
            {
                "minimal" => ExportScope.Minimal,
                "full" => ExportScope.Full,
                _ => ExportScope.Standard,
            },
            Categories = ParseCategories(StringList(payload, "categories")),
            Language = Strings.Language,
        };

        string suggested = Sanitize(_session.Name) + request.DefaultExtension;

        using var dialog = new SaveFileDialog
        {
            Title = Strings.T("export.title"),
            FileName = suggested,
            Filter = FilterFor(format),
            OverwritePrompt = true,
            AddExtension = true,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            WriteExport(dialog.FileName, request);
            Toast(Strings.Format("export.written", dialog.FileName), "ok");
            Reveal(dialog.FileName);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Toast(ex.Message, "error");
        }
    }

    private void WriteExport(string path, ExportRequest request)
    {
        if (_store is null || _session is null) return;

        switch (request.Format)
        {
            case ExportFormat.Html:
                File.WriteAllText(path,
                    Assets.RenderStatic(SessionProjection.Build(_store, _session, request)),
                    new UTF8Encoding(false));
                break;

            case ExportFormat.Json:
                File.WriteAllText(path,
                    JsonSerializer.Serialize(
                        SessionProjection.BuildModel(_store, _session, request),
                        new JsonSerializerOptions(SessionProjection.Json) { WriteIndented = true }),
                    new UTF8Encoding(false));
                break;

            case ExportFormat.Csv:
                using (var writer = new StreamWriter(path, append: false, CsvExporter.FileEncoding))
                    CsvExporter.Write(writer, _store, request);
                break;

            case ExportFormat.Tree:
                File.WriteAllText(path, RenderTreeText(request), new UTF8Encoding(false));
                break;

            case ExportFormat.Package:
                ExportPackageTo(path, _planItems.Count > 0 ? _planItems : BuildPlanItems(new PlanOptions()));
                break;
        }
    }

    private string RenderTreeText(ExportRequest request)
    {
        var processes = new ProcessTable();
        foreach (ProcessNode node in _store!.LoadProcesses()) processes.AddOrUpdate(node);

        var flows = new FlowTable();
        foreach (NetworkFlow flow in _store.LoadFlows())
            flows.NoteConnect(flow.Key, flow.Owner, flow.FirstSeen, flow.OwnerEvidence ?? "stored");

        IReadOnlyList<CausalNode> roots = new CausalGraphBuilder(processes, flows).Build(
            _store.Query(new ObservationQuery { Categories = request.Categories?.ToList() }),
            new CausalGraphOptions
            {
                IncludeReads = request.IncludeReads,
                IncludeOutOfScope = request.IncludeOutOfScope,
                MaxArtifactsPerGroup = request.MaxArtifactsPerGroup,
                RootProcess = _session!.RootProcess == ProcessKey.None ? null : _session.RootProcess,
            });

        return TreeTextExporter.Render(_session, roots, _store);
    }

    private static string FilterFor(ExportFormat format) => format switch
    {
        ExportFormat.Html => "HTML report (*.html)|*.html",
        ExportFormat.Json => "JSON (*.json)|*.json",
        ExportFormat.Csv => "CSV (*.csv)|*.csv",
        ExportFormat.Tree => "Text (*.txt)|*.txt",
        _ => "CaYaTrace package (*.ctpkg)|*.ctpkg",
    };

    private static List<EventCategory>? ParseCategories(List<string> names)
    {
        if (names.Count == 0) return null;

        var result = new List<EventCategory>();
        foreach (string name in names)
            if (Enum.TryParse(name, ignoreCase: true, out EventCategory category)) result.Add(category);

        return result.Count == 0 ? null : result;
    }

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name) sb.Append(Path.GetInvalidFileNameChars().Contains(c) ? '_' : c);
        return sb.Length == 0 ? "session" : sb.ToString();
    }

    // --------------------------------------------------------------- remediation

    private readonly record struct PlanOptions(bool IncludeModified, bool IncludeTemp, bool IncludeOutOfScope);

    private void BuildPlan(JsonElement payload)
    {
        if (_store is null || _session is null) return;

        var options = new PlanOptions(
            Bool(payload, "includeModified"),
            Bool(payload, "includeTemp"),
            Bool(payload, "includeOutOfScope"));

        _planItems = BuildPlanItems(options);
        _quarantineRoot = Path.Combine(
            Path.GetDirectoryName(_sessionPath) ?? Environment.CurrentDirectory, "quarantine");

        PostPlan();
    }

    private List<RemovalItem> BuildPlanItems(PlanOptions options)
    {
        var planner = new RemovalPlanner(_store!, options: new RemovalPlannerOptions
        {
            ScopedOnly = !options.IncludeOutOfScope,
            IncludeModifiedFiles = options.IncludeModified,
            ExcludeTemporary = !options.IncludeTemp,
        });

        return planner.Build(_session!);
    }

    private void PostPlan()
    {
        var paths = Core.Naming.PathNormalizer.CreateForCurrentMachine();
        var policy = new SafetyPolicy(paths);

        // The safety verdict is computed here, before the operator sees the list, so a
        // protected item is shown as unselectable rather than being silently dropped by
        // the runner after they approved it. A plan that quietly does less than it
        // showed is a plan nobody can audit.
        var items = _planItems.Select((item, index) =>
        {
            SafetyDecision decision = policy.Evaluate(item);
            return new
            {
                id = index.ToString(System.Globalization.CultureInfo.InvariantCulture),
                kind = item.Kind.ToString(),
                target = item.ValueName is { Length: > 0 }
                    ? $"{item.Target}::{item.ValueName}"
                    : item.Target,
                reason = item.Rationale,
                pattern = item.TargetPattern,
                @protected = decision.Verdict == SafetyVerdict.Forbidden,
                protectionReason = decision.Reason,
            };
        }).ToList();

        Post("plan", new { items, quarantine = _quarantineRoot });
    }

    private void ExportPackage(JsonElement payload)
    {
        if (_session is null) return;

        List<RemovalItem> chosen = Select(StringList(payload, "ids"));
        if (chosen.Count == 0) { Toast(Strings.T("remediate.empty")); return; }

        using var dialog = new SaveFileDialog
        {
            Title = Strings.T("remediate.export"),
            FileName = Sanitize(_session.Name) + RemovalPackage.Extension,
            Filter = "CaYaTrace package (*.ctpkg)|*.ctpkg",
            OverwritePrompt = true,
            AddExtension = true,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            ExportPackageTo(dialog.FileName, chosen);
            Toast(Strings.Format("export.written", dialog.FileName), "ok");
            Reveal(dialog.FileName);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Toast(ex.Message, "error");
        }
    }

    private void ExportPackageTo(string path, List<RemovalItem> items)
    {
        RemovalPlanner.Export(path, _session!, items,
            _store!.Query(new ObservationQuery { PersistentChangesOnly = true }));
    }

    private List<RemovalItem> Select(List<string> ids)
    {
        var wanted = new HashSet<int>();
        foreach (string id in ids)
            if (int.TryParse(id, out int index) && index >= 0 && index < _planItems.Count) wanted.Add(index);

        return _planItems.Where((_, index) => wanted.Contains(index)).ToList();
    }

    /// <summary>
    /// Applies the selected part of a removal plan to this machine.
    /// </summary>
    /// <remarks>
    /// The page has already shown a confirmation naming the count and the quarantine
    /// folder. What is enforced here is what the page cannot be trusted with: the item
    /// list is re-resolved from indices into the plan this process built, so the page
    /// can choose <em>which</em> of those items to remove but can never name a path of its own.
    /// </remarks>
    private void ApplyPlan(JsonElement payload)
    {
        List<RemovalItem> chosen = Select(StringList(payload, "ids"));
        if (chosen.Count == 0) return;

        if (!Privilege.IsElevated())
        {
            Toast(Strings.T("error.needs_admin"), "error");
            return;
        }

        string quarantine = _quarantineRoot ?? Path.Combine(
            Path.GetDirectoryName(_sessionPath) ?? Environment.CurrentDirectory, "quarantine");

        _ = Task.Run(() =>
        {
            try
            {
                var runner = new RemediationRunner(quarantine, apply: true)
                {
                    // The operator approved this exact list in the confirmation. Asking
                    // again per item, with no console to ask on, would mean skipping
                    // everything that needed a decision.
                    ConfirmationHandler = static (_, _, _) => true,
                };

                List<ItemResult> results = runner.Execute(chosen);

                int removed = results.Count(static r => r.Outcome == ItemOutcome.Removed);
                int skipped = results.Count(static r => r.Outcome
                    is ItemOutcome.SkippedByPolicy
                    or ItemOutcome.SkippedFingerprintMismatch
                    or ItemOutcome.SkippedByOperator
                    or ItemOutcome.NotPresent);
                int failed = results.Count(static r => r.Outcome == ItemOutcome.Failed);

                Toast(Strings.Format("remediate.applied", removed, skipped, failed, quarantine),
                    failed > 0 ? "error" : "ok");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                Toast(ex.Message, "error");
            }
        });
    }

    // ------------------------------------------------------------------ compare

    private void CompareRun(JsonElement payload)
    {
        List<string> inputs = StringList(payload, "sessions");
        if (inputs.Count < 2) { Toast(Strings.T("compare.need_two"), "error"); return; }

        _ = Task.Run(() =>
        {
            try
            {
                (MergeReport report, SessionInfo? reference) = Compare(inputs);

                object Row(MergedArtifact a) => new
                {
                    target = a.Template.Pattern,
                    origins = a.SeenOn,
                    template = a.Template.HasVariables ? a.Template.Pattern : null,
                    action = a.Action.ToString(),
                    category = a.Category.ToString(),
                };

                Post("compare", new
                {
                    originCount = report.Origins.Count,
                    stable = report.Artifacts.Where(static a => a.Consistency == Consistency.Universal).Select(Row).ToList(),
                    partial = report.Artifacts.Where(static a => a.Consistency == Consistency.Common).Select(Row).ToList(),
                    unique = report.Artifacts.Where(static a => a.Consistency == Consistency.Unique).Select(Row).ToList(),
                    subject = reference?.Name,
                });
            }
            catch (Exception ex) when (ex is IOException or FileNotFoundException or Microsoft.Data.Sqlite.SqliteException)
            {
                Toast(ex.Message, "error");
            }
        });
    }

    /// <summary>Merges several recordings of the same program, one origin per session.</summary>
    private static (MergeReport Report, SessionInfo? Reference) Compare(List<string> inputs)
    {
        var stores = new List<SessionStore>();
        try
        {
            var byOrigin = new Dictionary<string, IReadOnlyList<Observation>>(StringComparer.OrdinalIgnoreCase);
            SessionInfo? reference = null;

            foreach (string input in inputs)
            {
                SessionStore store = SessionStore.Open(SessionPaths.Resolve(input));
                stores.Add(store);

                SessionInfo? info = store.LoadSessionInfo();
                if (info is null) continue;
                reference ??= info;

                // Sessions recorded on cloned VMs can share a machine id, so the key is
                // made unique per session — otherwise two machines collapse into one and
                // their agreement is invented.
                byOrigin[$"{info.Machine.MachineName}#{info.SessionId}"] = LoadScopedChanges(store);
            }

            return (new ArtifactMerger().Merge(byOrigin), reference);
        }
        finally
        {
            foreach (SessionStore store in stores) store.Dispose();
        }
    }

    /// <summary>
    /// The persistent changes a session attributed to the subject's process tree.
    /// </summary>
    /// <remarks>
    /// Scope filtering matters more here than anywhere else. Two recordings taken on the
    /// same busy desktop agree on a great deal that has nothing to do with the subject —
    /// antivirus logs, browser caches, indexer journals — and every one of those looks
    /// like corroborated behaviour to a merger that cannot see who caused it.
    /// </remarks>
    private static IReadOnlyList<Observation> LoadScopedChanges(SessionStore store)
    {
        var inScope = new HashSet<ProcessKey>(
            store.LoadProcesses().Where(static p => p.InScope).Select(static p => p.Key));

        return store.Query(new ObservationQuery { PersistentChangesOnly = true })
            .Where(o => o.Actor == ProcessKey.None
                ? o.Source == EvidenceSource.SnapshotDiff
                : inScope.Contains(o.Actor))
            .ToList();
    }

    /// <summary>
    /// Writes a removal package built from what every compared machine agreed on.
    /// </summary>
    /// <remarks>
    /// The package worth carrying to a third machine. With one recording the variable
    /// parts of a path can only be guessed; with two they are measured, so the pattern
    /// still matches on a machine that names its per-install directories differently
    /// again. Only artifacts seen on <em>every</em> compared machine are included — a change
    /// that happened once is a change this package has no business proposing to remove
    /// somewhere else.
    /// </remarks>
    private void CompareExportPackage(JsonElement payload)
    {
        List<string> inputs = StringList(payload, "sessions");
        if (inputs.Count < 2) { Toast(Strings.T("compare.need_two"), "error"); return; }

        using var dialog = new SaveFileDialog
        {
            Title = Strings.T("compare.export_package"),
            FileName = "comparison" + RemovalPackage.Extension,
            Filter = "CaYaTrace package (*.ctpkg)|*.ctpkg",
            OverwritePrompt = true,
            AddExtension = true,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        string path = dialog.FileName;

        _ = Task.Run(() =>
        {
            try
            {
                (MergeReport report, SessionInfo? reference) = Compare(inputs);
                if (reference is null) { Toast(Strings.T("compare.need_two"), "error"); return; }

                List<RemovalItem> items = RemovalPlanner.FromComparison(report, report.Origins.Count);
                if (items.Count == 0) { Toast(Strings.T("remediate.empty")); return; }

                RemovalPlanner.Export(path, reference, items);
                Toast(Strings.Format("export.written", path), "ok");
                Reveal(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                          or FileNotFoundException or Microsoft.Data.Sqlite.SqliteException)
            {
                Toast(ex.Message, "error");
            }
        });
    }

    // ---------------------------------------------------------------- assistant

    private Uri ResolveEndpoint(string? endpoint)
    {
        if (Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? parsed))
        {
            _settings.OllamaEndpoint = parsed.ToString();
            _settings.Save();
            return parsed;
        }
        return new Uri("http://localhost:11434");
    }

    private async Task AiStatusAsync(string? endpoint)
    {
        Uri uri = ResolveEndpoint(endpoint);
        using var client = new OllamaClient(uri);

        try
        {
            bool reachable = await client.IsAvailableAsync().ConfigureAwait(false);
            IReadOnlyList<OllamaModel> models = reachable
                ? await client.ListModelsAsync().ConfigureAwait(false)
                : Array.Empty<OllamaModel>();

            Post("ai", new
            {
                busy = false,
                status = new
                {
                    reachable,
                    endpoint = uri.ToString(),
                    models = models.Select(static m => m.Name).ToList(),
                },
            });
        }
        catch (OllamaException ex)
        {
            Post("ai", new { busy = false, status = new { reachable = false, endpoint = uri.ToString(), models = Array.Empty<string>() } });
            Toast(ex.Message, "error");
        }
    }

    /// <summary>
    /// Scores installed models against known-answer probes.
    /// </summary>
    /// <remarks>
    /// Exists because "local models give bad results" is usually a model-selection
    /// problem the operator has no way to see. Measuring turns it into a number they can
    /// compare, and the recommendation that follows is derived from that measurement
    /// rather than from a list of model names someone wrote down once.
    /// </remarks>
    private async Task AiProbeAsync(string? endpoint)
    {
        Uri uri = ResolveEndpoint(endpoint);
        using var client = new OllamaClient(uri);

        try
        {
            if (!await client.IsAvailableAsync().ConfigureAwait(false))
            {
                Post("ai", new { busy = false, progress = (string?)null });
                Toast(Strings.Format("assistant.status_down", uri.ToString()), "error");
                return;
            }

            IReadOnlyList<OllamaModel> models = await client.ListModelsAsync().ConfigureAwait(false);

            // A very large model costs minutes per item and, for this task, buys nothing
            // an 8B instruct model does not already deliver.
            List<OllamaModel> candidates = models
                .Where(static m => !m.Name.EndsWith(":cloud", StringComparison.OrdinalIgnoreCase))
                .Where(static m => m.Billions <= 24 || m.Billions == 0)
                .OrderBy(static m => m.Billions)
                .ToList();

            var capability = new ModelCapability(client);
            var results = new List<object>();

            foreach (OllamaModel model in candidates)
            {
                Post("ai", new { busy = true, progress = Strings.Format("assistant.probing", model.Name) });

                try
                {
                    ModelAssessment assessment = await capability.AssessAsync(model.Name).ConfigureAwait(false);
                    results.Add(new
                    {
                        model = assessment.Model,
                        suitability = assessment.Suitability.ToString(),
                        correct = assessment.Correct,
                        total = assessment.Total,
                        latencySeconds = assessment.AverageLatency.TotalSeconds,
                        notes = assessment.Notes,
                    });
                }
                catch (OllamaException ex)
                {
                    results.Add(new
                    {
                        model = model.Name,
                        suitability = ModelSuitability.Unusable.ToString(),
                        correct = 0,
                        total = 0,
                        latencySeconds = 0.0,
                        notes = new[] { ex.Message },
                    });
                }

                Post("ai", new { busy = true, assessments = results, progress = (string?)null });
            }

            Post("ai", new { busy = false, assessments = results, progress = (string?)null });
        }
        catch (OllamaException ex)
        {
            Post("ai", new { busy = false, progress = (string?)null });
            Toast(ex.Message, "error");
        }
    }

    private async Task AiExplainAsync(string? endpoint, string? model)
    {
        if (_store is null || _session is null) return;

        Uri uri = ResolveEndpoint(endpoint);
        using var client = new OllamaClient(uri);

        string? chosen = string.IsNullOrWhiteSpace(model) ? null : model;
        if (chosen is not null && !await client.IsAvailableAsync().ConfigureAwait(false))
        {
            Toast(Strings.Format("assistant.status_down", uri.ToString()), "error");
            chosen = null;
        }

        var inScope = new HashSet<ProcessKey>(
            _store.LoadProcesses().Where(static p => p.InScope).Select(static p => p.Key));

        List<Observation> observations = _store.Query(new ObservationQuery())
            .Where(o => o.Actor == ProcessKey.None || inScope.Contains(o.Actor))
            .ToList();

        var pipeline = new LocalAnalysisPipeline(client)
        {
            OnProgress = (index, total, _) =>
                Post("ai", new { busy = true, progress = Strings.Format("assistant.analysing", index, total) }),
        };

        try
        {
            AiReport report = await pipeline.AnalyzeAsync(observations, chosen, 40).ConfigureAwait(false);
            PostAiReport(report);
        }
        catch (OllamaException ex)
        {
            Post("ai", new { busy = false, progress = (string?)null });
            Toast(ex.Message, "error");
        }
    }

    private AiReport? _lastReport;

    private void PostAiReport(AiReport report)
    {
        _lastReport = report;

        Post("ai", new
        {
            busy = false,
            progress = (string?)null,
            report = new
            {
                model = report.Model,
                modelWasUsed = report.ModelWasUsed,
                caveats = report.Caveats,
                findings = report.Findings.Select(static f => new
                {
                    risk = f.Risk.ToString(),
                    artifact = f.Artifact.Describe(),
                    reasons = f.Artifact.Reasons,
                    label = f.Label,
                    labelConfidence = f.LabelConfidence,
                    disagreement = f.Disagreement,
                    reputation = f.Reputation?.Summarize(),
                }).ToList(),

                // Keyed by target so the findings view can attach a label to the card it
                // belongs to without the page having to match anything up itself.
                byTarget = report.Findings
                    .GroupBy(static f => f.Artifact.Observation.Target)
                    .ToDictionary(static g => g.Key, static g => new
                    {
                        label = g.First().Label,
                        labelConfidence = g.First().LabelConfidence,
                        disagreement = g.First().Disagreement,
                        reputation = g.First().Reputation?.Summarize(),
                    }),
            },
        });
    }

    /// <summary>
    /// Adds file reputation to findings that are dropped executables.
    /// </summary>
    /// <remarks>
    /// Hash lookup only, and never implicit. CaYaTrace cannot upload a file by
    /// construction — submitting a sample publishes it permanently, and that is not a
    /// side effect an analysis tool gets to have. The lookup alone still discloses that
    /// someone is interested in this exact file, which is why it takes a button.
    /// </remarks>
    private async Task VirusTotalAsync(string? typedKey)
    {
        if (_lastReport is null)
        {
            Toast(Strings.T("assistant.analyse"), "error");
            return;
        }

        if (!string.IsNullOrWhiteSpace(typedKey)) _virusTotalKey = typedKey.Trim();

        string? key = _virusTotalKey ?? VirusTotalClient.ReadKeyFromEnvironment();
        if (key is null)
        {
            Toast(Strings.T("assistant.vt_missing_key"), "error");
            return;
        }

        Post("ai", new { busy = true, progress = Strings.T("common.loading") });

        try
        {
            using var client = new VirusTotalClient(key);
            var enricher = new ReputationEnricher(new VirusTotalReputationSource(client))
            {
                OnProgress = (index, total, _) =>
                    Post("ai", new { busy = true, progress = $"{index}/{total}" }),
            };

            IReadOnlyDictionary<string, ReputationResult> reputations = await enricher
                .EnrichAsync(_lastReport.Findings.Select(static f => f.Artifact))
                .ConfigureAwait(false);

            var enriched = _lastReport.Findings
                .Select(f => reputations.TryGetValue(f.Artifact.Observation.Target, out ReputationResult? r)
                    ? f with { Reputation = r }
                    : f)
                .ToList();

            PostAiReport(_lastReport with
            {
                Findings = enriched,
                Caveats = _lastReport.Caveats.Append(Strings.T("assistant.vt_hint")).ToList(),
            });
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            Post("ai", new { busy = false, progress = (string?)null });
            Toast(ex.Message, "error");
        }
    }
}
