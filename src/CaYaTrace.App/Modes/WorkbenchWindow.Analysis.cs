using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using CaYaTrace.Analysis;
using CaYaTrace.Analysis.Ai;
using CaYaTrace.Analysis.Persistence;
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

                    Progress = PostRemediationProgress,
                };

                // The protected path, not the plain one. Anything configured to restart
                // itself is disarmed first — recovery actions cleared, autostart set to
                // manual, watchdog groups stopped together — because a removal that runs
                // while its subject is putting itself back looks like it worked.
                (DisarmResult disarmed, List<ItemResult> results) = runner.ExecuteProtected(chosen);

                int removed = results.Count(static r => r.Outcome == ItemOutcome.Removed);
                int skipped = results.Count(static r => r.Outcome
                    is ItemOutcome.SkippedByPolicy
                    or ItemOutcome.SkippedFingerprintMismatch
                    or ItemOutcome.SkippedByOperator
                    or ItemOutcome.NotPresent);
                int failed = results.Count(static r => r.Outcome == ItemOutcome.Failed);

                PostRemediationResult(quarantine, disarmed, results, removed, skipped, failed);

                Toast(Strings.Format("remediate.applied", removed, skipped, failed, quarantine),
                    failed > 0 ? "error" : "ok");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                Post("remediation", new { running = false });
                Toast(ex.Message, "error");
            }
        });
    }

    private void PostRemediationProgress(RemediationProgress progress) => Post("remediation", new
    {
        running = true,
        index = progress.Index,
        total = progress.Total,
        percent = progress.Percent,
        kind = progress.Kind?.ToString(),
        target = progress.Target,
        preparation = progress.IsPreparation,
        outcome = progress.Outcome?.ToString(),
        detail = progress.Detail,
        finished = progress.Outcome is not null,
    });

    /// <summary>
    /// The result of a removal, and what is now sitting in quarantine.
    /// </summary>
    /// <remarks>
    /// The quarantine listing is part of the result rather than a separate screen because
    /// the decision it invites — keep, put back, or delete for good — is one an operator
    /// makes while they still remember what they were doing and why.
    /// </remarks>
    private void PostRemediationResult(
        string quarantineRoot,
        DisarmResult disarmed,
        List<ItemResult> results,
        int removed,
        int skipped,
        int failed)
    {
        var quarantine = new Quarantine(quarantineRoot);

        Post("remediation", new
        {
            running = false,
            complete = true,
            root = quarantineRoot,
            removed,
            skipped,
            failed,
            defences = disarmed.Found.Select(static d => new
            {
                kind = d.Kind.ToString(),
                subject = d.Subject,
                description = d.Description,
                response = d.Response,
                disarmed = d.CanDisarm,
            }).ToList(),
            actions = disarmed.Actions,
            blocked = disarmed.Failures,
            items = results.Select(static r => new
            {
                kind = r.Item.Kind.ToString(),
                target = r.Item.Target,
                value = r.Item.ValueName,
                outcome = r.Outcome.ToString(),
                detail = r.Detail,
            }).ToList(),
            held = quarantine.Contents().Select(static q => new
            {
                path = q.QuarantinePath,
                original = q.OriginalPath,
                size = q.SizeBytes,
                directory = q.IsDirectory,
                canRestore = q.CanRestore,
            }).ToList(),
        });
    }

    /// <summary>Carries out what the operator decided about the quarantined files.</summary>
    /// <remarks>
    /// Deleting is the only step in this tool that cannot be undone, so it is its own
    /// intent, taken after the operator has seen the list, and it refuses anything outside
    /// the quarantine directory regardless of what the journal claims.
    /// </remarks>
    private void QuarantineApply(JsonElement payload)
    {
        string? root = Str(payload, "root") ?? _quarantineRoot;
        if (root is null) return;

        QuarantineDisposition disposition = Str(payload, "disposition") switch
        {
            "restore" => QuarantineDisposition.Restore,
            "delete" => QuarantineDisposition.Delete,
            _ => QuarantineDisposition.Keep,
        };

        if (disposition == QuarantineDisposition.Keep)
        {
            Toast(Strings.T("quarantine.kept"), "ok");
            return;
        }

        if (!Privilege.IsElevated())
        {
            Toast(Strings.T("error.needs_admin"), "error");
            return;
        }

        List<string> only = StringList(payload, "paths");

        _ = Task.Run(() =>
        {
            var quarantine = new Quarantine(root);
            IReadOnlyList<(QuarantinedItem Item, bool Succeeded, string Message)> results =
                quarantine.Apply(disposition, only.Count > 0 ? only : null, PostRemediationProgress);

            int ok = results.Count(static r => r.Succeeded);
            int bad = results.Count - ok;

            Post("quarantine", new
            {
                disposition = disposition.ToString(),
                succeeded = ok,
                failed = bad,
                held = quarantine.Contents().Select(static q => new
                {
                    path = q.QuarantinePath,
                    original = q.OriginalPath,
                    size = q.SizeBytes,
                    directory = q.IsDirectory,
                    canRestore = q.CanRestore,
                }).ToList(),
                results = results.Select(static r => new
                {
                    original = r.Item.OriginalPath,
                    succeeded = r.Succeeded,
                    message = r.Message,
                }).ToList(),
            });

            Toast(Strings.Format("quarantine.done", ok, bad), bad > 0 ? "error" : "ok");
        });
    }

    /// <summary>Lists what is currently held, so the view can offer the decision again later.</summary>
    private void QuarantineList(JsonElement payload)
    {
        string? root = Str(payload, "root") ?? _quarantineRoot;
        if (root is null) return;

        var quarantine = new Quarantine(root);
        Post("quarantine", new
        {
            root,
            held = quarantine.Contents().Select(static q => new
            {
                path = q.QuarantinePath,
                original = q.OriginalPath,
                size = q.SizeBytes,
                directory = q.IsDirectory,
                canRestore = q.CanRestore,
            }).ToList(),
        });
    }

    /// <summary>
    /// Loads a removal package and shows what it would do on this machine.
    /// </summary>
    /// <remarks>
    /// A package built on one machine is a set of measured patterns, not a list of literal
    /// paths, so what it resolves to here is a real question with a real answer — and the
    /// operator sees that answer, through the same safety policy and the same review, before
    /// anything is applied. It was previously buildable from the window and appliable only
    /// from a command line.
    /// </remarks>
    private void LoadPackage(JsonElement payload)
    {
        string? path = Str(payload, "path");

        if (path is null)
        {
            using var dialog = new OpenFileDialog
            {
                Title = Strings.T("remediate.open_package"),
                Filter = "CaYaTrace package (*.ctpkg)|*.ctpkg|All files (*.*)|*.*",
                CheckFileExists = true,
            };

            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            path = dialog.FileName;
        }

        try
        {
            (PackageManifest manifest, List<RemovalItem> items, bool integrityOk) = RemovalPackage.Read(path);

            // Said, not silently tolerated. The hash detects damage, not forgery, and an
            // operator about to change their machine should know which of those they are
            // relying on.
            if (!integrityOk)
            {
                Toast(Strings.Format("remediate.package_damaged", Path.GetFileName(path)), "error");
                return;
            }

            _planItems = items;
            _quarantineRoot = Path.Combine(
                Path.GetDirectoryName(path) ?? Environment.CurrentDirectory, "quarantine");

            PostPlan();

            Toast(Strings.Format("remediate.package_loaded", items.Count, manifest.SubjectName), "ok");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            Toast(ex.Message, "error");
        }
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

    /// <summary>
    /// Answers a question about the loaded session.
    /// </summary>
    /// <remarks>
    /// The answer comes from the session; a model, if one is configured, only rewords it.
    /// See <see cref="SessionAssistant"/> for why that inversion is the whole design —
    /// briefly, the models people run locally are small enough to confabulate confidently,
    /// and an answer about someone's own machine is not a good place for that.
    /// </remarks>
    private async Task AskAsync(JsonElement payload)
    {
        if (_store is null || _session is null)
        {
            Toast(Strings.T("assistant.no_session"), "error");
            return;
        }

        string question = Str(payload, "question")?.Trim() ?? string.Empty;
        if (question.Length == 0) return;

        AnswerDetail detail = Str(payload, "detail") == "detailed" ? AnswerDetail.Detailed : AnswerDetail.Brief;
        string? model = Str(payload, "model");

        Post("chat", new { busy = true });

        try
        {
            List<ProcessNode> processes = _store.LoadProcesses();
            var byKey = new Dictionary<ProcessKey, ProcessNode>();
            foreach (ProcessNode node in processes) byKey.TryAdd(node.Key, node);

            IReadOnlyList<PersistenceRecord> persistence =
                new PersistenceAnalyzer(byKey.GetValueOrDefault).Analyze(_store.Query());

            var questions = new SessionQuestions(_store, _session, persistence, processes);

            using var client = new OllamaClient(ResolveEndpoint(Str(payload, "endpoint")));
            var assistant = new SessionAssistant(questions, client);

            AssistantReply reply = await assistant
                .AskAsync(question, detail, Strings.Language, model)
                .ConfigureAwait(true);

            PostReply(reply);
        }
        catch (Exception ex) when (ex is OllamaException or IOException or Microsoft.Data.Sqlite.SqliteException)
        {
            Post("chat", new { busy = false });
            Toast(ex.Message, "error");
        }
    }

    private void PostReply(AssistantReply reply) => Post("chat", new
    {
        busy = false,
        question = reply.Question,
        understood = reply.Understood,
        kind = reply.Answer.Kind.ToString(),

        // Both are sent. The measured answer is the evidence; the phrased one is a
        // convenience, and a reader has to be able to see which is which.
        answer = reply.Answer.Text,
        phrased = reply.Phrased,
        model = reply.Model,
        note = reply.ModelNote,
        evidence = reply.Answer.Evidence,
        matches = reply.Answer.MatchCount,
        empty = reply.Answer.IsEmpty,
    });

    /// <summary>
    /// Fetches the bytes of one side of one conversation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// On demand rather than in the projection, because a session can hold thousands of
    /// conversations and any one of them can be megabytes. The projection carries the
    /// hash; this turns a hash into something readable when somebody opens it.
    /// </para>
    /// <para>
    /// Rendered as text when the bytes are text and as hex when they are not, and bounded
    /// either way. The content came off the wire and is not to be trusted — it reaches the
    /// page as an escaped string in a pre-formatted block, never as markup.
    /// </para>
    /// </remarks>
    private void ReadBody(JsonElement payload)
    {
        if (_store is null) return;

        string? hash = Str(payload, "hash");
        if (hash is not { Length: 64 } || !hash.All(Uri.IsHexDigit))
        {
            // The page only ever echoes back a hash the projection gave it. Anything
            // else is not something to go looking for on disk.
            Toast(Strings.T("network.body_unknown"), "error");
            return;
        }

        byte[]? body;
        try
        {
            body = _store.ReadBlob(hash);
        }
        catch (Exception ex) when (ex is IOException or Microsoft.Data.Sqlite.SqliteException)
        {
            Toast(ex.Message, "error");
            return;
        }

        if (body is null)
        {
            Toast(Strings.T("network.body_unknown"), "error");
            return;
        }

        const int Preview = 64 * 1024;
        byte[] slice = body.Length <= Preview ? body : body[..Preview];

        bool text = IsMostlyText(slice);

        Post("body", new
        {
            hash,
            bytes = body.Length,
            truncated = body.Length > slice.Length,
            kind = text ? "text" : "hex",
            content = text
                ? new UTF8Encoding(false, false).GetString(slice)
                : Hex(slice),
        });
    }

    /// <summary>Renders bytes as an offset/hex/ASCII dump, the way they are read.</summary>
    private static string Hex(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 4);

        for (int offset = 0; offset < data.Length; offset += 16)
        {
            int run = Math.Min(16, data.Length - offset);
            sb.Append(offset.ToString("x8")).Append("  ");

            for (int i = 0; i < 16; i++)
            {
                sb.Append(i < run ? data[offset + i].ToString("x2") : "  ").Append(' ');
                if (i == 7) sb.Append(' ');
            }

            sb.Append(' ');
            for (int i = 0; i < run; i++)
            {
                byte b = data[offset + i];
                sb.Append(b >= 32 && b < 127 ? (char)b : '.');
            }

            sb.Append('\n');
        }

        return sb.ToString();
    }

    private static bool IsMostlyText(byte[] data)
    {
        if (data.Length == 0) return true;

        int length = Math.Min(data.Length, 512);
        int printable = 0;

        for (int i = 0; i < length; i++)
        {
            byte b = data[i];
            if (b is 9 or 10 or 13 || (b >= 32 && b < 127)) printable++;
        }

        return printable * 10 >= length * 9;
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
