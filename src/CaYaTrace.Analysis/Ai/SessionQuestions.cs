using System.Text;
using CaYaTrace.Analysis.Persistence;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;
using CaYaTrace.Storage;

namespace CaYaTrace.Analysis.Ai;

/// <summary>What the assistant was asked, once the question has been understood.</summary>
public enum SessionQuestionKind
{
    /// <summary>Nothing recognised — the model answers from packed evidence, if there is one.</summary>
    OpenEnded,

    Persistence,
    Services,
    ScheduledTasks,
    NetworkDestinations,
    Listeners,
    FilesDropped,
    RegistryChanges,
    ProcessesStarted,
    Injection,
    Summary,
    Removal,
}

/// <summary>How much of an answer the operator wants.</summary>
public enum AnswerDetail
{
    /// <summary>The answer and the evidence for it, nothing else.</summary>
    Brief,

    /// <summary>Every matching record, with its values.</summary>
    Detailed,
}

/// <summary>An answer built from the session, with the evidence it came from.</summary>
public sealed record SessionAnswer
{
    public required SessionQuestionKind Kind { get; init; }

    /// <summary>The answer in plain words, computed from the data.</summary>
    public required string Text { get; init; }

    /// <summary>Rows behind the answer, so the reader can check it.</summary>
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();

    /// <summary>How many records matched, which may exceed what is listed.</summary>
    public int MatchCount { get; init; }

    /// <summary>True when nothing in the session answers this.</summary>
    public bool IsEmpty { get; init; }

    /// <summary>
    /// Compact facts handed to a model when one is asked to phrase this.
    /// </summary>
    /// <remarks>
    /// The model receives this and is told to rephrase it. It is never asked to find
    /// anything, and never sees the raw session — which is what makes a small local model
    /// usable here rather than a liability.
    /// </remarks>
    public string Facts { get; init; } = string.Empty;
}

/// <summary>
/// Answers questions about a recorded session from the session itself.
/// </summary>
/// <remarks>
/// <para>
/// The design constraint is that the models available locally are small and unreliable,
/// and the answers matter. So the division of labour is strict: <b>this class finds the
/// answer, and a model is only ever asked to say it in better words.</b> Ask "is anything
/// adding itself to startup and where" and the answer comes from the persistence records,
/// not from a model reading a wall of text and guessing.
/// </para>
/// <para>
/// That inversion is what makes the feature work at all with a 3B model on a laptop. It
/// also means every answer degrades to something correct when no model is configured, and
/// that a model failing its capability probe costs phrasing rather than accuracy.
/// </para>
/// <para>
/// Questions are recognised in both interface languages, because an operator asking about
/// their own machine asks in the language they think in.
/// </para>
/// </remarks>
public sealed class SessionQuestions
{
    private readonly SessionStore _store;
    private readonly SessionInfo _session;
    private readonly IReadOnlyList<PersistenceRecord> _persistence;
    private readonly IReadOnlyList<ProcessNode> _processes;

    public SessionQuestions(
        SessionStore store,
        SessionInfo session,
        IReadOnlyList<PersistenceRecord> persistence,
        IReadOnlyList<ProcessNode> processes)
    {
        _store = store;
        _session = session;
        _persistence = persistence;
        _processes = processes;
    }

    /// <summary>
    /// Keywords that identify a question, in both interface languages.
    /// </summary>
    /// <remarks>
    /// Deliberately keyword matching rather than asking a model to classify. Classifying
    /// is the one job a small model is reasonably good at, but it is also the job whose
    /// failure is invisible: a misrouted question produces a confident answer to a
    /// question nobody asked. Keywords fail by not matching, which falls through to the
    /// open-ended path and says so.
    /// </remarks>
    private static readonly (SessionQuestionKind Kind, string[] Words)[] Intents =
    {
        (SessionQuestionKind.Persistence, new[]
        {
            "persist", "startup", "start up", "autostart", "auto-start", "boot", "logon", "survive", "reboot",
            "başlangıç", "başlat", "kalıcı", "kalıcılık", "açılış", "yeniden başlat", "otomatik",
        }),
        (SessionQuestionKind.Services, new[] { "service", "servis", "hizmet" }),
        (SessionQuestionKind.ScheduledTasks, new[]
        {
            "task", "scheduled", "schedule", "görev", "zamanlanmış", "zamanlama",
        }),
        (SessionQuestionKind.NetworkDestinations, new[]
        {
            "network", "connect", "internet", "url", "domain", "host", "server", "traffic", "dns",
            "ağ", "bağlan", "sunucu", "trafik", "istek", "adres",
        }),
        (SessionQuestionKind.Listeners, new[]
        {
            "listen", "port", "server socket", "incoming", "expose",
            "dinle", "port aç", "gelen", "aç",
        }),
        (SessionQuestionKind.FilesDropped, new[]
        {
            "file", "drop", "wrote", "write", "install", "disk",
            "dosya", "yaz", "bırak", "kur", "yükle",
        }),
        (SessionQuestionKind.RegistryChanges, new[]
        {
            "registry", "regedit", "key", "kayıt defteri", "anahtar",
        }),
        (SessionQuestionKind.ProcessesStarted, new[]
        {
            "process", "launch", "spawn", "child", "ran", "executable",
            "süreç", "işlem", "çalıştır", "başlattı", "alt işlem",
        }),
        (SessionQuestionKind.Injection, new[]
        {
            "inject", "remote thread", "hook", "enjekte", "enjeksiyon", "iş parçacığı",
        }),
        (SessionQuestionKind.Removal, new[]
        {
            "remove", "uninstall", "clean", "delete", "kaldır", "sil", "temizle",
        }),
        (SessionQuestionKind.Summary, new[]
        {
            "summary", "summarise", "summarize", "overview", "what happened", "what did",
            "özet", "genel", "ne yaptı", "ne oldu",
        }),
    };

    public static SessionQuestionKind Classify(string question)
    {
        string lower = question.ToLowerInvariant();

        // Longest match wins, so "scheduled task" is not answered as a process question
        // because it happens to contain a shorter word.
        SessionQuestionKind best = SessionQuestionKind.OpenEnded;
        int bestLength = 0;

        foreach ((SessionQuestionKind kind, string[] words) in Intents)
        {
            foreach (string word in words)
            {
                if (word.Length <= bestLength) continue;
                if (!lower.Contains(word, StringComparison.Ordinal)) continue;

                best = kind;
                bestLength = word.Length;
            }
        }

        return best;
    }

    public SessionAnswer Answer(string question, AnswerDetail detail)
        => Answer(Classify(question), detail);

    public SessionAnswer Answer(SessionQuestionKind kind, AnswerDetail detail) => kind switch
    {
        SessionQuestionKind.Persistence => Persistence(detail, null),
        SessionQuestionKind.Services => Persistence(detail, PersistenceKind.Service),
        SessionQuestionKind.ScheduledTasks => Persistence(detail, PersistenceKind.ScheduledTask),
        SessionQuestionKind.NetworkDestinations => NetworkDestinations(detail),
        SessionQuestionKind.Listeners => Listeners(detail),
        SessionQuestionKind.FilesDropped => Files(detail),
        SessionQuestionKind.RegistryChanges => RegistryChanges(detail),
        SessionQuestionKind.ProcessesStarted => Processes(detail),
        SessionQuestionKind.Injection => Injection(detail),
        SessionQuestionKind.Removal => Removal(detail),
        SessionQuestionKind.Summary => Summary(detail),
        _ => new SessionAnswer
        {
            Kind = SessionQuestionKind.OpenEnded,
            Text = string.Empty,
            IsEmpty = true,
        },
    };

    /// <summary>
    /// The answer to "is anything adding itself to startup, and where".
    /// </summary>
    /// <remarks>
    /// Written to answer in the first line and justify afterwards, because that is how
    /// the question was asked. The location and what actually runs are on the same line
    /// as the name — an answer that says "a service was installed" and makes the reader
    /// go looking for its image path has not answered anything.
    /// </remarks>
    private SessionAnswer Persistence(AnswerDetail detail, PersistenceKind? only)
    {
        List<PersistenceRecord> matches = _persistence
            .Where(r => only is null || r.Kind == only)
            .OrderByDescending(static r => r.Score)
            .ToList();

        if (matches.Count == 0)
        {
            return new SessionAnswer
            {
                Kind = only switch
                {
                    PersistenceKind.Service => SessionQuestionKind.Services,
                    PersistenceKind.ScheduledTask => SessionQuestionKind.ScheduledTasks,
                    _ => SessionQuestionKind.Persistence,
                },
                Text = "No. Nothing in this session arranged to run again.",
                IsEmpty = true,
                Facts = "no persistence entries",
            };
        }

        var evidence = new List<string>();
        var facts = new StringBuilder();

        int limit = detail == AnswerDetail.Detailed ? matches.Count : Math.Min(6, matches.Count);

        foreach (PersistenceRecord record in matches.Take(limit))
        {
            var line = new StringBuilder();
            line.Append(record.Kind).Append(" · ").Append(record.Identity);
            if (record.DisplayName is { Length: > 0 } && record.DisplayName != record.Identity)
                line.Append(" (").Append(record.DisplayName).Append(')');
            line.Append('\n').Append("    ").Append(record.Location);
            if (record.Command is { Length: > 0 }) line.Append('\n').Append("    → ").Append(record.Command);

            foreach (string trait in record.Traits) line.Append('\n').Append("    · ").Append(trait);

            if (detail == AnswerDetail.Detailed)
            {
                foreach (PersistenceValue value in record.Values)
                    line.Append('\n').Append("      ").Append(value.Name).Append(" = ").Append(value.Data);
            }

            evidence.Add(line.ToString());
            facts.Append(record.Kind).Append(' ').Append(record.Identity)
                 .Append(" at ").Append(record.Location)
                 .Append(record.Command is { Length: > 0 } ? $" runs {record.Command}" : string.Empty)
                 .Append(record.Traits.Count > 0 ? $" ({string.Join("; ", record.Traits)})" : string.Empty)
                 .Append('\n');
        }

        string headline = only switch
        {
            PersistenceKind.Service => $"Yes — {matches.Count} service(s).",
            PersistenceKind.ScheduledTask => $"Yes — {matches.Count} scheduled task(s).",
            _ => $"Yes — {matches.Count} way(s) to run again.",
        };

        // The mechanisms present, so the first line answers "what kind" as well as "how
        // many". Read before deciding whether to read the rest.
        string kinds = string.Join(", ", matches
            .GroupBy(static r => r.Kind)
            .OrderByDescending(static g => g.Count())
            .Select(static g => $"{g.Count()} {g.Key}"));

        return new SessionAnswer
        {
            Kind = only switch
            {
                PersistenceKind.Service => SessionQuestionKind.Services,
                PersistenceKind.ScheduledTask => SessionQuestionKind.ScheduledTasks,
                _ => SessionQuestionKind.Persistence,
            },
            Text = $"{headline} {kinds}.",
            Evidence = evidence,
            MatchCount = matches.Count,
            Facts = facts.ToString(),
        };
    }

    private SessionAnswer NetworkDestinations(AnswerDetail detail)
    {
        var hosts = new Dictionary<string, (int Count, string Process)>(StringComparer.OrdinalIgnoreCase);

        foreach (NetworkFlow flow in _store.LoadFlows())
        {
            string name = flow.ResolvedHost ?? flow.ServerName ?? flow.Key.RemoteAddress.ToString();
            if (flow.Key.RemoteAddress.Equals(System.Net.IPAddress.Loopback)) continue;

            string process = _processes.FirstOrDefault(p => p.Key == flow.Owner)?.ImageName ?? "unattributed";
            hosts[name] = hosts.TryGetValue(name, out (int Count, string Process) prior)
                ? (prior.Count + 1, prior.Process)
                : (1, process);
        }

        foreach (Observation o in _store.Query(new ObservationQuery { Categories = new List<EventCategory> { EventCategory.Dns } }))
        {
            if (o.Action != EventAction.DnsQuery) continue;
            if (o.Target.Length == 0) continue;
            hosts.TryAdd(o.Target, (0, _processes.FirstOrDefault(p => p.Key == o.Actor)?.ImageName ?? "unattributed"));
        }

        if (hosts.Count == 0)
        {
            return new SessionAnswer
            {
                Kind = SessionQuestionKind.NetworkDestinations,
                Text = "Nothing. No connections or lookups were recorded for this session.",
                IsEmpty = true,
                Facts = "no network activity",
            };
        }

        int limit = detail == AnswerDetail.Detailed ? hosts.Count : Math.Min(12, hosts.Count);
        List<string> evidence = hosts
            .OrderByDescending(static h => h.Value.Count)
            .Take(limit)
            .Select(static h => $"{h.Key}  ({h.Value.Process}{(h.Value.Count > 0 ? $", {h.Value.Count} connection(s)" : ", lookup only")})")
            .ToList();

        return new SessionAnswer
        {
            Kind = SessionQuestionKind.NetworkDestinations,
            Text = $"{hosts.Count} host(s).",
            Evidence = evidence,
            MatchCount = hosts.Count,
            Facts = string.Join('\n', evidence),
        };
    }

    /// <summary>
    /// Ports the subject opened for other machines to connect to.
    /// </summary>
    /// <remarks>
    /// A separate question from "who did it call", and the more interesting one when
    /// asking whether a program has components that talk to each other: something that
    /// opens a socket and waits is expecting to be found.
    /// </remarks>
    private SessionAnswer Listeners(AnswerDetail detail)
    {
        var listeners = new List<string>();

        foreach (Observation o in _store.Query(new ObservationQuery
                 {
                     Categories = new List<EventCategory> { EventCategory.Network },
                 }))
        {
            if (o.Action is not (EventAction.Listen or EventAction.Accept)) continue;

            string process = _processes.FirstOrDefault(p => p.Key == o.Actor)?.ImageName ?? "unattributed";
            string line = $"{o.Target}  ({process}, {o.Action})";
            if (!listeners.Contains(line)) listeners.Add(line);
        }

        if (listeners.Count == 0)
        {
            return new SessionAnswer
            {
                Kind = SessionQuestionKind.Listeners,
                Text = "None. Nothing in this session opened a port and waited for a connection.",
                IsEmpty = true,
                Facts = "no listeners",
            };
        }

        int limit = detail == AnswerDetail.Detailed ? listeners.Count : Math.Min(10, listeners.Count);

        return new SessionAnswer
        {
            Kind = SessionQuestionKind.Listeners,
            Text = $"{listeners.Count} listening endpoint(s).",
            Evidence = listeners.Take(limit).ToList(),
            MatchCount = listeners.Count,
            Facts = string.Join('\n', listeners.Take(limit)),
        };
    }

    private SessionAnswer Files(AnswerDetail detail)
        => FromScored(SessionQuestionKind.FilesDropped, EventCategory.File, detail, "file(s) created or written");

    private SessionAnswer RegistryChanges(AnswerDetail detail)
        => FromScored(SessionQuestionKind.RegistryChanges, EventCategory.Registry, detail, "registry change(s)");

    private SessionAnswer FromScored(
        SessionQuestionKind kind, EventCategory category, AnswerDetail detail, string noun)
    {
        var scorer = new ArtifactScorer();
        List<ScoredArtifact> matches = scorer
            .TopFindings(
                _store.Query(new ObservationQuery { Categories = new List<EventCategory> { category } }),
                detail == AnswerDetail.Detailed ? 200 : 40)
            .ToList();

        if (matches.Count == 0)
        {
            return new SessionAnswer
            {
                Kind = kind,
                Text = $"None. No {noun} worth reporting were recorded.",
                IsEmpty = true,
                Facts = $"no {noun}",
            };
        }

        int limit = detail == AnswerDetail.Detailed ? matches.Count : Math.Min(10, matches.Count);
        List<string> evidence = matches
            .Take(limit)
            .Select(static m => $"{m.Risk}  {m.Observation.Action}  {m.Observation.Target}"
                                + (m.Observation.Target2 is { Length: > 0 } ? $"::{m.Observation.Target2}" : string.Empty))
            .ToList();

        return new SessionAnswer
        {
            Kind = kind,
            Text = $"{matches.Count} {noun} ranked worth attention.",
            Evidence = evidence,
            MatchCount = matches.Count,
            Facts = string.Join('\n', evidence),
        };
    }

    private SessionAnswer Processes(AnswerDetail detail)
    {
        List<ProcessNode> started = _processes.Where(static p => !p.PreExisting).ToList();

        if (started.Count == 0)
        {
            return new SessionAnswer
            {
                Kind = SessionQuestionKind.ProcessesStarted,
                Text = "None. No process started while this session was recording.",
                IsEmpty = true,
                Facts = "no processes started",
            };
        }

        int limit = detail == AnswerDetail.Detailed ? started.Count : Math.Min(15, started.Count);
        List<string> evidence = started
            .OrderBy(static p => p.StartTime)
            .Take(limit)
            .Select(static p =>
            {
                string life = p.ExitTime is { } exit
                    ? $"{(exit - p.StartTime).TotalSeconds:0.#}s"
                    : "still running";
                return $"{p.StartTime:HH:mm:ss}  {p.ImageName} ({p.Pid})  {life}"
                       + (p.CommandLine is { Length: > 0 } ? $"\n    {p.CommandLine}" : string.Empty);
            })
            .ToList();

        return new SessionAnswer
        {
            Kind = SessionQuestionKind.ProcessesStarted,
            Text = $"{started.Count} process(es) started.",
            Evidence = evidence,
            MatchCount = started.Count,
            Facts = string.Join('\n', evidence),
        };
    }

    private SessionAnswer Injection(AnswerDetail detail)
    {
        var scorer = new ArtifactScorer(processLookup: key => _processes.FirstOrDefault(p => p.Key == key));

        List<ScoredArtifact> matches = _store
            .Query(new ObservationQuery { Categories = new List<EventCategory> { EventCategory.Process } })
            .Where(static o => o.Action == EventAction.RemoteThread)
            .Select(scorer.Score)
            .Where(static s => s.Score > 0)
            .OrderByDescending(static s => s.Score)
            .ToList();

        if (matches.Count == 0)
        {
            return new SessionAnswer
            {
                Kind = SessionQuestionKind.Injection,
                Text = "None. No process put a thread inside another process it does not own.",
                IsEmpty = true,
                Facts = "no injection",
            };
        }

        int limit = detail == AnswerDetail.Detailed ? matches.Count : Math.Min(10, matches.Count);
        List<string> evidence = matches
            .Take(limit)
            .Select(static m => $"{m.Observation.NewValue} → {m.Observation.Target}  at {m.Observation.Target2}")
            .ToList();

        return new SessionAnswer
        {
            Kind = SessionQuestionKind.Injection,
            Text = $"{matches.Count} cross-process thread creation(s) worth attention.",
            Evidence = evidence,
            MatchCount = matches.Count,
            Facts = string.Join('\n', evidence),
        };
    }

    private SessionAnswer Removal(AnswerDetail detail)
    {
        SessionAnswer persistence = Persistence(detail, null);

        return new SessionAnswer
        {
            Kind = SessionQuestionKind.Removal,
            Text = persistence.IsEmpty
                ? "Nothing needs undoing to stop this running again."
                : $"{persistence.MatchCount} entry point(s) would have to be undone. Build a plan on the Remediate view to see exactly what.",
            Evidence = persistence.Evidence,
            MatchCount = persistence.MatchCount,
            IsEmpty = persistence.IsEmpty,
            Facts = persistence.Facts,
        };
    }

    /// <summary>The whole session in a paragraph, computed rather than generated.</summary>
    public SessionAnswer Summary(AnswerDetail detail)
    {
        Dictionary<EventCategory, long> counts = _store.CountByCategory();
        var parts = new List<string>();
        var evidence = new List<string>();

        string subject = _session.TargetPath is { Length: > 0 }
            ? System.IO.Path.GetFileName(_session.TargetPath)
            : _session.Name;

        parts.Add($"{subject} was recorded for {_session.Duration.TotalMinutes:0.#} minutes on {_session.Machine.MachineName}.");

        int started = _processes.Count(static p => !p.PreExisting);
        if (started > 0) parts.Add($"{started} process(es) started.");

        long files = counts.GetValueOrDefault(EventCategory.File);
        long registry = counts.GetValueOrDefault(EventCategory.Registry);
        if (files > 0 || registry > 0)
            parts.Add($"{files:N0} file and {registry:N0} registry operations were observed.");

        if (_persistence.Count > 0)
        {
            string kinds = string.Join(", ", _persistence
                .GroupBy(static r => r.Kind)
                .Select(static g => $"{g.Count()} {g.Key}"));
            parts.Add($"It arranged to run again in {_persistence.Count} way(s): {kinds}.");

            foreach (PersistenceRecord record in _persistence.Take(detail == AnswerDetail.Detailed ? 50 : 5))
                evidence.Add($"{record.Kind} · {record.Identity} → {record.Command ?? record.Location}");
        }
        else
        {
            parts.Add("Nothing it did survives a reboot.");
        }

        long dns = counts.GetValueOrDefault(EventCategory.Dns);
        long network = counts.GetValueOrDefault(EventCategory.Network);
        if (dns > 0 || network > 0)
            parts.Add($"It made {network:N0} connection(s) and {dns:N0} name lookup(s).");
        else
            parts.Add("It made no network connections.");

        // Said plainly, because a quiet session and an incomplete one look identical in a
        // summary and mean opposite things.
        if (!_session.WasElevated)
            parts.Add("This was recorded without administrator rights, so kernel tracing was unavailable and only before/after inventories were compared.");

        if (_session.Quality.EventsLost > 0)
            parts.Add($"{_session.Quality.EventsLost:N0} events were lost, so this is incomplete.");

        return new SessionAnswer
        {
            Kind = SessionQuestionKind.Summary,
            Text = string.Join(' ', parts),
            Evidence = evidence,
            MatchCount = _persistence.Count,
            Facts = string.Join('\n', parts),
        };
    }
}
