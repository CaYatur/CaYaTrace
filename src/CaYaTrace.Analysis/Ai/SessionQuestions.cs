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

    /// <summary>What led to what — the launch chain, rendered.</summary>
    Tree,

    /// <summary>
    /// Conversations between programs on this machine, which never touch the network.
    /// </summary>
    /// <remarks>
    /// Split from <see cref="NetworkDestinations"/> because the two have opposite answers
    /// from the same session and were sharing one. Asked whether programs had talked to
    /// each other locally, the assistant answered "no" and then listed five internet hosts
    /// — the loopback conversations were recorded and never consulted.
    /// </remarks>
    LocalConversations,

    /// <summary>What something is and what it appears to be for.</summary>
    Explain,

    /// <summary>The command that would carry out what was just discussed.</summary>
    Command,
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
            "dinle", "port aç", "gelen", "soket",
        }),

        // Deliberately ahead of the internet-facing network words in specificity: every
        // phrase here also contains one of them, and longest-match is what keeps "did
        // programs talk to each other on this machine" away from the list of web hosts.
        (SessionQuestionKind.LocalConversations, new[]
        {
            "local network", "same machine", "each other", "between processes", "loopback",
            "127.0.0.1", "inter-process", "talk to each other", "localhost",
            "yerel ağ", "aynı makine", "birbiri", "kendi aralarında", "haberleş",
            "süreçler arası", "yerel bağlantı",
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
            "process", "launch", "spawn", "child", "ran", "executable", "program", "application",

            // "which programs opened during the recording" is a question about processes,
            // and the operator asked it in both of these words. It used to be answered
            // with a list of listening sockets, because nothing here matched it and a
            // two-letter listener keyword did.
            "süreç", "işlem", "çalıştır", "başlattı", "alt işlem", "uygulama", "açıldı",
            "açılan", "çalışan", "başlayan",
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
        (SessionQuestionKind.Tree, new[]
        {
            "tree", "chain", "who started", "what started", "lineage", "hierarchy",
            "ağaç", "ağac", "zincir", "kim başlattı", "hangi süreç başlattı", "hiyerarşi",
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
                if (!Mentions(lower, word)) continue;

                best = kind;
                bestLength = word.Length;
            }
        }

        return best;
    }

    /// <summary>
    /// True when the question uses this word, rather than merely containing its letters.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A plain substring test reads "hangi programlar açıldı kayıt esnasında" — which
    /// programs opened during the recording — as a question about listening ports, because
    /// "açıldı" contains "aç". The operator got a list of sockets for a question about
    /// programs, and nothing in the answer hinted at why.
    /// </para>
    /// <para>
    /// A word here must start at a word boundary. It may still run into a suffix, because
    /// Turkish attaches them freely — "servis" has to match "servisleri", "bağlan" has to
    /// match "bağlantı" — so only the start is anchored. That is the asymmetry the
    /// language actually has, and anchoring both ends would break far more than it fixed.
    /// </para>
    /// </remarks>
    private static bool Mentions(string question, string word)
    {
        int from = 0;
        while (true)
        {
            int at = question.IndexOf(word, from, StringComparison.Ordinal);
            if (at < 0) return false;

            if (at == 0 || !char.IsLetterOrDigit(question[at - 1])) return true;
            from = at + 1;
        }
    }

    public SessionAnswer Answer(string question, AnswerDetail detail)
        => Answer(Classify(question), detail);

    /// <summary>
    /// Whether activity by this process belongs in the answers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A recording with no subject is a recording of the whole machine, so everything
    /// counts. A recording of one program answers about that program and everything it
    /// started.
    /// </para>
    /// <para>
    /// Unattributed activity is kept either way. It is the only category where excluding
    /// costs evidence that cannot be recovered — an event nobody could tie to a process is
    /// still an event that happened, and dropping it silently would make a session look
    /// quieter than it was.
    /// </para>
    /// </remarks>
    private bool InScope(ProcessKey owner)
    {
        if (_session.RootProcess == ProcessKey.None) return true;
        if (owner == ProcessKey.None) return true;

        ProcessNode? node = _processes.FirstOrDefault(p => p.Key == owner);
        return node is null || node.InScope;
    }

    private SessionVocabulary? _vocabulary;

    /// <summary>
    /// The names this session contains, so a question can be matched against them.
    /// </summary>
    /// <remarks>
    /// Built once and cached. A service named <c>61df826a3fa71fa6</c> is recognisable only
    /// because the session holds it — no pattern would ever match that, and an operator
    /// pasting it into the chat box is asking about exactly one thing.
    /// </remarks>
    public SessionVocabulary Vocabulary()
    {
        if (_vocabulary is not null) return _vocabulary;

        var vocabulary = new SessionVocabulary();

        foreach (PersistenceRecord record in _persistence)
        {
            switch (record.Kind)
            {
                case PersistenceKind.ScheduledTask:
                    vocabulary.AddTask(record.Identity);
                    vocabulary.AddTask(record.DisplayName);
                    break;

                default:
                    // Everything else that arranges to run again is asked about the same
                    // way — by the name it was registered under.
                    vocabulary.AddService(record.Identity);
                    vocabulary.AddService(record.DisplayName);
                    break;
            }

            vocabulary.AddFile(record.Command);
        }

        foreach (ProcessNode process in _processes)
        {
            vocabulary.AddProcess(process.ImageName);
            vocabulary.AddFile(process.ImagePath);
        }

        foreach (NetworkFlow flow in _store.LoadFlows())
        {
            vocabulary.AddHost(flow.ResolvedHost);
            vocabulary.AddHost(flow.ServerName);
        }

        foreach (Observation o in _store.Query(new ObservationQuery
        {
            Categories = new List<EventCategory> { EventCategory.Dns },
        }))
        {
            if (o.Action == EventAction.DnsQuery) vocabulary.AddHost(o.Target);
        }

        foreach (Observation o in _store.Query(new ObservationQuery
        {
            Categories = new List<EventCategory> { EventCategory.File },
        }))
        {
            if (o.Action is EventAction.FileCreate or EventAction.FileWrite) vocabulary.AddFile(o.Target);
        }

        return _vocabulary = vocabulary;
    }

    /// <summary>
    /// Cuts an answer down to the things the question actually named.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The measured answer is built per topic, so "is anything connecting to example.com"
    /// produces every host in the session. Narrowing turns that back into an answer to the
    /// question that was asked.
    /// </para>
    /// <para>
    /// When nothing matches, the answer says so and keeps the rest as context rather than
    /// either returning empty or pretending the question was about the topic. "Did anything
    /// reach example.com" answered with twenty-nine other hosts is not an answer; neither is
    /// "0 host(s)", which reads as though the session recorded no network activity at all.
    /// The honest reply is that this name does not appear, and here is what does.
    /// </para>
    /// </remarks>
    public static SessionAnswer Narrow(SessionAnswer answer, QuestionEntities entities)
    {
        if (!entities.Any || answer.Evidence.Count == 0) return answer;

        List<string> names = entities.AllNames().Where(static n => n.Length >= 3).ToList();
        if (names.Count == 0) return answer;

        List<string> kept = answer.Evidence
            .Where(row => names.Any(n => row.Contains(n, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (kept.Count == answer.Evidence.Count) return answer;

        string subject = string.Join(", ", names.Take(3));

        if (kept.Count == 0)
        {
            return answer with
            {
                Text = $"Nothing here matches {subject}. "
                     + $"The session does hold {answer.MatchCount} other entr(ies) for this question, "
                     + "listed below.",

                // The facts handed to a model are the negative answer, not the rows — a
                // small model given the rows will happily answer about them instead, which
                // is precisely the confusion this branch exists to prevent.
                Facts = $"nothing matching {subject} was recorded",
            };
        }

        return answer with
        {
            Text = $"{kept.Count} of {answer.Evidence.Count} match {subject}.",
            Evidence = kept,
            MatchCount = kept.Count,
            Facts = string.Join('\n', kept),
        };
    }

    public SessionAnswer Answer(SessionQuestionKind kind, AnswerDetail detail) => kind switch
    {
        SessionQuestionKind.Persistence => Persistence(detail, null),
        SessionQuestionKind.Services => Persistence(detail, PersistenceKind.Service),
        SessionQuestionKind.ScheduledTasks => Persistence(detail, PersistenceKind.ScheduledTask),
        SessionQuestionKind.NetworkDestinations => NetworkDestinations(detail),
        SessionQuestionKind.LocalConversations => LocalConversations(detail),
        SessionQuestionKind.Listeners => Listeners(detail),
        SessionQuestionKind.FilesDropped => Files(detail),
        SessionQuestionKind.RegistryChanges => RegistryChanges(detail),
        SessionQuestionKind.ProcessesStarted => Processes(detail),
        SessionQuestionKind.Injection => Injection(detail),
        SessionQuestionKind.Removal => Removal(detail),
        SessionQuestionKind.Tree => Tree(detail),
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

            // A session recorded to watch one program answers about that program. Without
            // this, asking a scoped recording which hosts were contacted returned the
            // operator's own browser, their remote-support agent and their editor's API
            // traffic — measured, from a session whose subject was a PowerShell script.
            if (!InScope(flow.Owner)) continue;

            string process = _processes.FirstOrDefault(p => p.Key == flow.Owner)?.ImageName ?? "unattributed";
            hosts[name] = hosts.TryGetValue(name, out (int Count, string Process) prior)
                ? (prior.Count + 1, prior.Process)
                : (1, process);
        }

        foreach (Observation o in _store.Query(new ObservationQuery { Categories = new List<EventCategory> { EventCategory.Dns } }))
        {
            if (o.Action != EventAction.DnsQuery) continue;
            if (o.Target.Length == 0) continue;
            if (!InScope(o.Actor)) continue;
            hosts.TryAdd(o.Target, (0, _processes.FirstOrDefault(p => p.Key == o.Actor)?.ImageName ?? "unattributed"));
        }

        // With interception on, the subject's own sockets all go to the proxy on loopback
        // and its real destinations are only in the exchange records. Without this, turning
        // interception on made "which hosts did it connect to" answer "nothing" — the one
        // setting whose entire purpose is to see that traffic better.
        foreach (Observation o in _store.Query(new ObservationQuery
        {
            Categories = new List<EventCategory> { EventCategory.Http },
        }))
        {
            if (o.Action != EventAction.HttpRequest) continue;
            if (!InScope(o.Actor)) continue;
            if (!Uri.TryCreate(o.Target, UriKind.Absolute, out Uri? url)) continue;

            string process = _processes.FirstOrDefault(p => p.Key == o.Actor)?.ImageName ?? "unattributed";

            hosts[url.Host] = hosts.TryGetValue(url.Host, out (int Count, string Process) prior)
                ? (prior.Count + 1, prior.Process)
                : (1, process);
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
    /// Conversations between two programs on this machine.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A separate answer from the list of internet hosts, and it has to be: asked "did
    /// programs on the local network talk to each other", the assistant used to answer
    /// "no" and then print five hosts on the internet. The conversations were in the
    /// session the whole time — recorded through Winsock, which is the only source that
    /// sees traffic that never reaches a network adapter.
    /// </para>
    /// <para>
    /// Both ends of a conversation are recorded separately, once by each participant. They
    /// are paired here so the answer is a conversation rather than two halves of one, and
    /// the tool's own proxy is named plainly when it is the other end — an operator
    /// comparing byte counts deserves to know which of them are the tool's.
    /// </para>
    /// </remarks>
    private SessionAnswer LocalConversations(AnswerDetail detail)
    {
        var rows = new List<(string Row, long Bytes)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Observation o in _store.Query(new ObservationQuery
        {
            Categories = new List<EventCategory> { EventCategory.Network },
        }))
        {
            if (o.Details is not { Length: > 0 } details) continue;
            if (!details.Contains("\"via\":\"winsock\"", StringComparison.Ordinal)) continue;
            if (!details.Contains("\"scope\":\"Loopback\"", StringComparison.Ordinal)) continue;

            LoopbackDetail? parsed = LoopbackDetail.Parse(details);
            if (parsed is null) continue;

            string owner = _processes.FirstOrDefault(p => p.Key == o.Actor)?.ImageName ?? "unattributed";
            string peer = o.Target2 is { Length: > 0 } ? o.Target2 : "not identified";

            // One conversation, not two half-conversations: the pair of endpoints is the
            // same either way round, so the first of the two to arrive represents it.
            string pair = string.Join('|', new[] { $"{owner}:{parsed.SentBytes}", $"{peer}:{parsed.ReceivedBytes}" }.OrderBy(static s => s, StringComparer.Ordinal));
            if (!seen.Add(pair)) continue;

            string direction = parsed.Inbound ? "←" : "→";
            rows.Add((
                $"{owner} {direction} {peer}   {parsed.SentBytes:N0} B sent, {parsed.ReceivedBytes:N0} B received"
                + $" ({parsed.Sends} send(s), {parsed.Receives} receive(s)) on {o.Target}",
                parsed.SentBytes + parsed.ReceivedBytes));
        }

        if (rows.Count == 0)
        {
            return new SessionAnswer
            {
                Kind = SessionQuestionKind.LocalConversations,
                Text = "No. Nothing on this machine talked to anything else on this machine "
                     + "during the recording.",
                IsEmpty = true,
                Facts = "no local conversations",
            };
        }

        int limit = detail == AnswerDetail.Detailed ? rows.Count : Math.Min(15, rows.Count);
        List<string> evidence = rows
            .OrderByDescending(static r => r.Bytes)
            .Take(limit)
            .Select(static r => r.Row)
            .ToList();

        return new SessionAnswer
        {
            Kind = SessionQuestionKind.LocalConversations,
            Text = $"Yes — {rows.Count} conversation(s) between programs on this machine. "
                 + "Winsock reports who spoke to whom and how much, but not what was said: "
                 + "the bytes never leave the sending program's memory.",
            Evidence = evidence,
            MatchCount = rows.Count,
            Facts = string.Join('\n', evidence),
        };
    }

    /// <summary>The parts of a loopback conversation record this answer reads.</summary>
    private sealed record LoopbackDetail(
        long SentBytes, long ReceivedBytes, int Sends, int Receives, bool Inbound)
    {
        public static LoopbackDetail? Parse(string json)
        {
            try
            {
                using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(json);
                System.Text.Json.JsonElement root = document.RootElement;

                return new LoopbackDetail(
                    Number(root, "sentBytes"),
                    Number(root, "receivedBytes"),
                    (int)Number(root, "sends"),
                    (int)Number(root, "receives"),
                    root.TryGetProperty("inbound", out System.Text.Json.JsonElement inbound)
                        && inbound.ValueKind == System.Text.Json.JsonValueKind.True);
            }
            catch (System.Text.Json.JsonException)
            {
                return null;
            }

            static long Number(System.Text.Json.JsonElement root, string name) =>
                root.TryGetProperty(name, out System.Text.Json.JsonElement value)
                && value.ValueKind == System.Text.Json.JsonValueKind.Number
                    ? value.GetInt64()
                    : 0;
        }
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

    /// <summary>
    /// What started what, drawn.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Drawn as text rather than described, because a launch chain is a shape and a
    /// sentence about a shape is worse than the shape. This is the one answer where the
    /// evidence <em>is</em> the layout, so a model is not asked to reword it — see
    /// <see cref="SessionAnswer.Facts"/> being left empty below.
    /// </para>
    /// <para>
    /// Rooted on the subject when there is one, and on whatever started during the
    /// session when there is not: a system-wide recording has no single root, and drawing
    /// every process on the machine from Idle downwards answers nothing.
    /// </para>
    /// </remarks>
    private SessionAnswer Tree(AnswerDetail detail)
    {
        var byParent = new Dictionary<ProcessKey, List<ProcessNode>>();
        var byKey = new Dictionary<ProcessKey, ProcessNode>();

        foreach (ProcessNode node in _processes) byKey.TryAdd(node.Key, node);
        foreach (ProcessNode node in _processes)
        {
            if (!byParent.TryGetValue(node.ParentKey, out List<ProcessNode>? kids))
                byParent[node.ParentKey] = kids = new List<ProcessNode>();
            kids.Add(node);
        }

        List<ProcessNode> roots;
        if (_session.RootProcess != ProcessKey.None && byKey.ContainsKey(_session.RootProcess))
        {
            roots = new List<ProcessNode> { byKey[_session.RootProcess] };
        }
        else
        {
            // Everything that started during the session and whose parent did not.
            roots = _processes
                .Where(p => !p.PreExisting && (p.ParentKey == ProcessKey.None
                                               || !byKey.TryGetValue(p.ParentKey, out ProcessNode? parent)
                                               || parent.PreExisting))
                .OrderBy(static p => p.StartTime)
                .ToList();
        }

        if (roots.Count == 0)
        {
            return new SessionAnswer
            {
                Kind = SessionQuestionKind.Tree,
                Text = "Nothing started during this session, so there is no chain to draw.",
                IsEmpty = true,
            };
        }

        var lines = new List<string>();
        int limit = detail == AnswerDetail.Detailed ? 400 : 60;
        int drawn = 0;

        void Draw(ProcessNode node, string prefix, bool last, int depth)
        {
            if (drawn >= limit || depth > 12) return;
            drawn++;

            string life = node.ExitTime is { } exit
                ? $"{(exit - node.StartTime).TotalSeconds:0.#}s"
                : "still running";

            lines.Add($"{prefix}{(depth == 0 ? string.Empty : last ? "└─ " : "├─ ")}"
                      + $"{node.ImageName} ({node.Pid})  {life}");

            List<ProcessNode> kids = byParent.GetValueOrDefault(node.Key) ?? new List<ProcessNode>();
            kids = kids.Where(k => k.Key != node.Key).OrderBy(static k => k.StartTime).ToList();

            string childPrefix = depth == 0 ? string.Empty : prefix + (last ? "   " : "│  ");
            for (int i = 0; i < kids.Count; i++) Draw(kids[i], childPrefix, i == kids.Count - 1, depth + 1);
        }

        foreach (ProcessNode root in roots.Take(detail == AnswerDetail.Detailed ? 40 : 8))
            Draw(root, string.Empty, true, 0);

        int started = _processes.Count(static p => !p.PreExisting);

        return new SessionAnswer
        {
            Kind = SessionQuestionKind.Tree,
            Text = $"{started} process(es) started, in {roots.Count} chain(s).",
            Evidence = lines,
            MatchCount = started,

            // Deliberately empty. The shape is the answer; asking a model to put a
            // drawing into prose would lose the only thing it communicates.
            Facts = string.Empty,
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
