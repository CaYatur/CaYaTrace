using System.Text;
using CaYaTrace.Analysis.Persistence;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Analysis.Ai;

/// <summary>One turn of the conversation, with where each part of it came from.</summary>
public sealed record AssistantReply
{
    public required string Question { get; init; }

    /// <summary>The answer computed from the session. Always present, always correct.</summary>
    public required SessionAnswer Answer { get; init; }

    /// <summary>
    /// The same answer in the model's words, or null when no model phrased it.
    /// </summary>
    /// <remarks>
    /// Kept separate from <see cref="SessionAnswer.Text"/> rather than replacing it, so a
    /// reader can always see what the tool actually measured next to what a model said
    /// about it. If the two ever disagree, the measured one is the evidence.
    /// </remarks>
    public string? Phrased { get; init; }

    public string? Model { get; init; }

    /// <summary>Why a model did not contribute, when one did not.</summary>
    public string? ModelNote { get; init; }

    /// <summary>A command built from the session, when one was asked for.</summary>
    public GeneratedCommand? Command { get; init; }

    /// <summary>What a web search returned, when the operator had that switched on.</summary>
    public IReadOnlyList<WebFinding> Web { get; init; } = Array.Empty<WebFinding>();

    /// <summary>How this question was read, so a wrong reading is visible rather than mysterious.</summary>
    public FollowUpIntent FollowUp { get; init; }

    public bool Understood => Answer.Kind != SessionQuestionKind.OpenEnded;
}

/// <summary>
/// The conversational front end to a recorded session.
/// </summary>
/// <remarks>
/// <para>
/// The models people run locally are small, and small models confabulate confidently. The
/// division of labour is built around that: <b>the session supplies every fact, and the
/// model reasons only over facts it was given.</b> A model is never handed the raw evidence
/// and asked to find something, and cannot introduce a fact about the machine.
/// </para>
/// <para>
/// What changed is where the line sits. The model used to be allowed to reword a measured
/// answer and nothing else, which made it safe and nearly useless: asked which of five
/// hosts was suspicious it said all five, including Windows' own connectivity checks;
/// asked which was more critical it said it did not understand the question; asked for a
/// command to remove one service it wrote instructions to delete four, one of them part of
/// the network stack. Every one of those is a question about the facts rather than a
/// request to restate them.
/// </para>
/// <para>
/// So the model may now compare, rank, and say what something looks like — and is required
/// to mark that as inference — while three things stay out of its hands entirely: which
/// records the answer is about, which of them the tool considers suspicious, and any
/// command the operator might run. Those come from the session and the scoring rules,
/// because those are the ones where being wrong costs something.
/// </para>
/// </remarks>
public sealed class SessionAssistant
{
    private readonly SessionQuestions _questions;
    private readonly OllamaClient? _client;
    private readonly IReadOnlyList<PersistenceRecord> _persistence;
    private readonly IReadOnlyList<ProcessNode> _processes;

    public SessionAssistant(
        SessionQuestions questions,
        OllamaClient? client = null,
        IReadOnlyList<PersistenceRecord>? persistence = null,
        IReadOnlyList<ProcessNode>? processes = null)
    {
        _questions = questions;
        _client = client;
        _persistence = persistence ?? Array.Empty<PersistenceRecord>();
        _processes = processes ?? Array.Empty<ProcessNode>();
    }

    /// <summary>The running conversation, so follow-ups mean something.</summary>
    public AssistantConversation Conversation { get; } = new();

    /// <summary>Web lookups, when the operator has switched them on.</summary>
    public WebResearch? Research { get; set; }

    /// <summary>
    /// How long a local model is given before the deterministic answer is shown alone.
    /// </summary>
    /// <remarks>
    /// A chat that stalls is worse than a chat that answers plainly. The computed answer is
    /// already correct and already on screen; the model is an improvement to it, and an
    /// improvement is not worth waiting a minute for.
    /// </remarks>
    private static readonly TimeSpan PhrasingBudget = TimeSpan.FromSeconds(45);

    public async Task<AssistantReply> AskAsync(
        string question,
        AnswerDetail detail,
        string language,
        string? model,
        CancellationToken cancellationToken = default)
    {
        FollowUpIntent followUp = AssistantConversation.ReadFollowUp(question);
        QuestionEntities entities = _questions.Vocabulary().Extract(question);

        (SessionQuestionKind kind, AnswerDetail effectiveDetail) = Route(question, entities, followUp, detail);

        if (kind == SessionQuestionKind.OpenEnded)
        {
            Conversation.Remember(new ConversationTurn
            {
                Question = question,
                Kind = SessionQuestionKind.OpenEnded,
                Entities = entities,
            });

            return new AssistantReply
            {
                Question = question,
                FollowUp = followUp,
                Answer = new SessionAnswer
                {
                    Kind = SessionQuestionKind.OpenEnded,
                    Text = "I did not recognise that as a question about this session.",
                    Evidence = Suggestions(),
                    IsEmpty = true,
                },
                ModelNote = "not sent to a model: there was no measured answer for it to phrase",
            };
        }

        SessionAnswer answer = SessionQuestions.Narrow(_questions.Answer(kind, effectiveDetail), entities);

        // Built here rather than asked of the model, and this is the whole point of the
        // command path: the model is not in it.
        GeneratedCommand? command = followUp == FollowUpIntent.Command
            ? BuildCommand(entities)
            : null;

        IReadOnlyList<WebFinding> web = await ResearchAsync(followUp, entities, cancellationToken)
            .ConfigureAwait(false);

        Conversation.Remember(new ConversationTurn
        {
            Question = question,
            Kind = kind,
            Entities = entities,
            Headline = answer.Text,
            Evidence = answer.Evidence,
        });

        if (_client is null || model is not { Length: > 0 })
        {
            return new AssistantReply
            {
                Question = question,
                FollowUp = followUp,
                Answer = answer,
                Command = command,
                Web = web,
                ModelNote = "no model configured — this is the measured answer",
            };
        }

        // Some answers are a shape rather than a sentence — the launch chain most of all.
        // Handing a drawing to a language model to reword loses the only thing it
        // communicates, so those answers say so by carrying no facts to reword.
        if (answer.Facts.Length == 0 && command is null && web.Count == 0)
        {
            return new AssistantReply
            {
                Question = question,
                FollowUp = followUp,
                Answer = answer,
                ModelNote = "not sent to a model: this answer is a drawing, not a sentence",
            };
        }

        try
        {
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            budget.CancelAfter(PhrasingBudget);

            string prompt = BuildPrompt(question, answer, effectiveDetail, language, followUp, command, web);
            string phrased = (await _client.GenerateAsync(model, prompt, budget.Token).ConfigureAwait(false)).Trim();

            return new AssistantReply
            {
                Question = question,
                FollowUp = followUp,
                Answer = answer,
                Command = command,
                Web = web,
                Phrased = phrased.Length == 0 ? null : phrased,
                Model = model,
                ModelNote = phrased.Length == 0 ? "the model returned nothing" : null,
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new AssistantReply
            {
                Question = question,
                FollowUp = followUp,
                Answer = answer,
                Command = command,
                Web = web,
                ModelNote = $"the model did not answer within {PhrasingBudget.TotalSeconds:0}s — this is the measured answer",
            };
        }
        catch (OllamaException ex)
        {
            return new AssistantReply
            {
                Question = question,
                FollowUp = followUp,
                Answer = answer,
                Command = command,
                Web = web,
                ModelNote = $"the model could not be reached ({ex.Message}) — this is the measured answer",
            };
        }
    }

    /// <summary>
    /// Decides what this question is about, using the conversation when it has to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three sources, in order of how much they know. The words of the question come first,
    /// because a question that states its own topic means it. What the question <em>names</em>
    /// comes next: typing a bare host name is a question about that host whatever was being
    /// discussed a moment ago. The previous turn comes last, and only for questions that
    /// cannot stand alone — "which is more critical" has no topic of its own and never will.
    /// </para>
    /// <para>
    /// Every one of the failures this replaces was the third case: a plainly meaningful
    /// follow-up answered with "I did not recognise that as a question about this session",
    /// because each question was routed as though it were the first.
    /// </para>
    /// </remarks>
    private (SessionQuestionKind Kind, AnswerDetail Detail) Route(
        string question, QuestionEntities entities, FollowUpIntent followUp, AnswerDetail detail)
    {
        SessionQuestionKind stated = SessionQuestions.Classify(question);

        // "Tell me more" is the same question again, in full.
        if (followUp == FollowUpIntent.Expand && stated == SessionQuestionKind.OpenEnded)
        {
            ConversationTurn? previous = Conversation.LastAnswered();
            if (previous is not null) return (previous.Kind, AnswerDetail.Detailed);
        }

        // A question that states its topic means it, and whatever it named narrows the
        // answer within that topic rather than replacing it: "does the service reach
        // example.com" is a network question that mentions a service, not both.
        if (stated != SessionQuestionKind.OpenEnded) return (stated, detail);

        // No topic stated. A bare name is a question about that name — typing "example.com"
        // on its own, or pasting a service name, is the shortest form of asking.
        if (entities.ImpliedKind() is { } fromName) return (fromName, detail);

        if (followUp != FollowUpIntent.None)
        {
            ConversationTurn? previous = Conversation.LastAnswered();

            // A follow-up asking for more detail wants the whole set; the others are about
            // the set that was already shown.
            if (previous is not null)
                return (previous.Kind, followUp == FollowUpIntent.Expand ? AnswerDetail.Detailed : detail);
        }

        return (SessionQuestionKind.OpenEnded, detail);
    }

    /// <summary>
    /// Builds a command for the one thing the question named.
    /// </summary>
    /// <remarks>
    /// Refuses when the question names nothing, and that refusal is the useful part. Asked
    /// "how do I remove these" about a list of four, a model wrote removal steps for all
    /// four including a Windows service. A command is for one named thing, or it is not
    /// offered.
    /// </remarks>
    private GeneratedCommand? BuildCommand(QuestionEntities entities)
    {
        foreach (string name in entities.Services.Concat(entities.Tasks))
        {
            PersistenceRecord? record = _persistence.FirstOrDefault(r =>
                string.Equals(r.Identity, name, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r.DisplayName, name, StringComparison.OrdinalIgnoreCase));

            if (record is not null) return RemediationCommands.ForPersistence(record);
        }

        foreach (uint pid in entities.Pids)
        {
            ProcessNode? process = _processes.FirstOrDefault(p => p.Key.Pid == pid);
            if (process is not null) return RemediationCommands.ForProcess(process);
        }

        foreach (string name in entities.Processes)
        {
            ProcessNode? process = _processes.FirstOrDefault(p =>
                string.Equals(p.ImageName, name, StringComparison.OrdinalIgnoreCase));

            if (process is not null) return RemediationCommands.ForProcess(process);
        }

        foreach (string file in entities.Files)
        {
            bool suspicious = _persistence.Any(r =>
                r.Risk >= RiskLevel.Medium
                && r.Command is { Length: > 0 } c
                && c.Contains(file, StringComparison.OrdinalIgnoreCase));

            return RemediationCommands.ForFile(file, suspicious);
        }

        return new GeneratedCommand
        {
            Subject = "nothing in particular",
            Refused = true,
            Rationale =
                "Name the one thing you want the command for — a service, a task, a file or a "
                + "process id. A command written against a list is how something the machine needs "
                + "ends up in it.",
        };
    }

    private async Task<IReadOnlyList<WebFinding>> ResearchAsync(
        FollowUpIntent followUp, QuestionEntities entities, CancellationToken cancellationToken)
    {
        if (Research is not { Enabled: true }) return Array.Empty<WebFinding>();
        if (followUp != FollowUpIntent.Explain) return Array.Empty<WebFinding>();

        // The most specific name available, because "what is this" about a session is not
        // a searchable question and "what is svcworker.exe" is.
        string? term = entities.Files.FirstOrDefault()
            ?? entities.Services.FirstOrDefault()
            ?? entities.Tasks.FirstOrDefault()
            ?? entities.Processes.FirstOrDefault()
            ?? entities.Hosts.FirstOrDefault();

        if (term is null) return Array.Empty<WebFinding>();

        try
        {
            IReadOnlyList<WebFinding> found =
                await Research.SearchAsync(term, cancellationToken).ConfigureAwait(false);

            if (found.Count == 0) return found;

            // Search snippets are two lines of marketing and rarely say what a file is.
            // The top result's own page usually does, so it is fetched and put in place of
            // the snippet — one page, because the operator is waiting and the second result
            // has never yet been the one that answered it.
            string page = await Research.FetchAsync(found[0].Url, cancellationToken).ConfigureAwait(false);
            if (page.Length <= found[0].Snippet.Length) return found;

            var enriched = found.ToList();
            enriched[0] = found[0] with { Snippet = page[..Math.Min(1200, page.Length)] };
            return enriched;
        }
        catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException)
        {
            return Array.Empty<WebFinding>();
        }
    }

    /// <summary>Builds a session summary, optionally phrased by a model.</summary>
    public Task<AssistantReply> SummariseAsync(
        AnswerDetail detail, string language, string? model, CancellationToken cancellationToken = default)
        => AskAsync("summary", detail, language, model, cancellationToken);

    /// <summary>
    /// The instruction given to the model.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Written for a small model: one job stated first, the facts second, and an explicit
    /// prohibition on the failure mode. What is new is that the job is no longer always
    /// "reword this". A question that asks which of these matters most is a real question
    /// about the facts, and answering it with the facts restated is what made the assistant
    /// feel like it was not listening.
    /// </para>
    /// <para>
    /// The boundary is stated in the terms a small model can actually follow: it may weigh
    /// and compare what it was given, it may say what something resembles as long as it
    /// says that is what it is doing, and it may not state anything about this machine that
    /// is not in the facts. "Do not add facts" survives paraphrase in a way that "do not
    /// speculate" does not — and forbidding inference outright is what produced an
    /// assistant that could list five hosts and not say which one mattered.
    /// </para>
    /// </remarks>
    private string BuildPrompt(
        string question, SessionAnswer answer, AnswerDetail detail, string language,
        FollowUpIntent followUp, GeneratedCommand? command, IReadOnlyList<WebFinding> web)
    {
        string languageName = language.StartsWith("tr", StringComparison.OrdinalIgnoreCase)
            ? "Turkish"
            : "English";

        var prompt = new StringBuilder();

        prompt.AppendLine(followUp switch
        {
            FollowUpIntent.Rank =>
                $"Answer in {languageName}: of the entries below, which matter most and why. "
                + "Put them in order, most serious first. Order them by the severity the facts "
                + "state. If the facts carry no severity, say plainly that the tool did not rank "
                + "these and that nothing in them stands out on its own — do NOT call an entry "
                + "suspicious to have something to say.",
            FollowUpIntent.Explain =>
                $"Answer in {languageName}: say what the thing below appears to be and what it is "
                + "for, based on its name, its location and what it does.",
            FollowUpIntent.Narrow =>
                $"Answer in {languageName} with only the entries that the question is about. "
                + "Leave everything else out.",
            FollowUpIntent.Command =>
                $"Answer in {languageName}. The command is given below and is already correct — "
                + "introduce it in one sentence and say what it does. Do not write a different one.",
            _ =>
                $"Answer the question below in {languageName}, using the finding.",
        });

        prompt.AppendLine();
        prompt.AppendLine("Rules:");
        prompt.AppendLine("- Answer the question in the first sentence. No preamble.");
        prompt.AppendLine(detail == AnswerDetail.Detailed
            ? "- Then explain what each entry is and why it matters. Stay under 220 words."
            : "- Then at most two short sentences. Stay under 70 words.");
        prompt.AppendLine($"- Write in {languageName}, even though the facts below are in English.");
        prompt.AppendLine("- Every fact about this machine must come from the facts below. Do not invent paths, names, numbers or events.");

        // The one judgement a small model reaches for unprompted, and the one it is worst
        // at. Asked which of a list was suspicious, it answered "all of them" — including
        // Windows' own connectivity checks — because being asked implied there was an
        // answer. Calling something suspicious is a verdict, and the verdicts are the
        // tool's.
        prompt.AppendLine("- Never call something suspicious, malicious or dangerous unless the facts below say so. \"Nothing here stands out\" is a complete answer.");
        prompt.AppendLine("- You MAY compare, rank and say what something resembles. Mark that clearly as your reading, with words like \"looks like\" or \"probably\".");
        prompt.AppendLine("- If the facts do not answer the question, say exactly that and stop.");
        prompt.AppendLine("- Keep file paths, registry keys, service names and commands exactly as written.");

        if (command is not null)
            prompt.AppendLine("- Do not modify, extend or re-order the command. Do not add commands for anything else.");

        if (web.Count > 0)
            prompt.AppendLine("- Web results are somebody's claim, not evidence from this machine. Say so when you use them.");

        if (!Conversation.IsEmpty)
        {
            prompt.AppendLine();
            prompt.AppendLine("Earlier in this conversation:");
            prompt.AppendLine(Truncate(Conversation.Describe(), 1200));
        }

        prompt.AppendLine();
        prompt.AppendLine($"Question: {question}");
        prompt.AppendLine();
        prompt.AppendLine($"Measured answer: {answer.Text}");

        if (answer.Facts.Length > 0)
        {
            prompt.AppendLine();
            prompt.AppendLine("Facts:");

            // Stated as a fact rather than as a rule, because that is what a small model
            // actually follows. Told "do not call anything suspicious unless the facts say
            // so", qwen2.5-coder:7b answered that example.com was among the suspicious
            // connections anyway — asked to rank, it produced a ranking. Given a line
            // saying the tool assigned no severity, it has something true to say instead,
            // and restating a fact is the one thing it is reliably good at.
            if (followUp == FollowUpIntent.Rank && !CarriesSeverity(answer.Facts))
                prompt.AppendLine("CaYaTrace assigned no severity to any of these. None of them is marked suspicious.");

            prompt.AppendLine(Truncate(answer.Facts, 4000));
        }

        if (command is not null)
        {
            prompt.AppendLine();
            prompt.AppendLine(command.Refused
                ? $"No command was produced. Reason: {command.Rationale}"
                : $"Command (exact, do not change):\n{string.Join('\n', command.Lines)}\n\nWhy: {command.Rationale}");
        }

        if (web.Count > 0)
        {
            prompt.AppendLine();
            prompt.AppendLine(WebResearch.Describe(web));
        }

        return prompt.ToString();
    }

    /// <summary>
    /// Questions this can answer, shown when one was not recognised.
    /// </summary>
    /// <remarks>
    /// Phrased as questions rather than as command names, because the operator typed a
    /// question and the useful reply is a question they could have typed instead.
    /// </remarks>
    private static IReadOnlyList<string> Suggestions() => new[]
    {
        "Is anything adding itself to startup, and where?",
        "Show me what started what.",
        "What services did it install?",
        "What scheduled tasks did it register?",
        "Which hosts did it connect to?",
        "Did programs on this machine talk to each other?",
        "Did it open any ports?",
        "What files did it write?",
        "What did it change in the registry?",
        "What processes did it start?",
        "Did anything inject into another process?",
        "Which of those is most critical?",
        "What is svcworker.exe and what does it do?",
        "Give me the PowerShell to remove DelayedSvc.",
        "Summarise this session.",
    };

    /// <summary>
    /// True when the rows carry the tool's own severity, so a ranking has something to
    /// rank by.
    /// </summary>
    /// <remarks>
    /// The scored answers — files, persistence, findings — render a risk level at the start
    /// of each row. A list of hosts or processes carries none, and that absence is what a
    /// ranking question has to be told about rather than left to infer.
    /// </remarks>
    private static bool CarriesSeverity(string facts) =>
        facts.Contains("Critical", StringComparison.Ordinal)
        || facts.Contains("High", StringComparison.Ordinal)
        || facts.Contains("Medium", StringComparison.Ordinal)
        || facts.Contains("Low", StringComparison.Ordinal);

    private static string Truncate(string text, int max)
        => text.Length <= max ? text : text[..max] + "\n… (truncated)";
}
