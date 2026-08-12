using System.Text;

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

    public bool Understood => Answer.Kind != SessionQuestionKind.OpenEnded;
}

/// <summary>
/// The conversational front end to a recorded session.
/// </summary>
/// <remarks>
/// <para>
/// The models people run locally are small, and small models confabulate confidently.
/// This is built around that rather than in spite of it: <b>the session answers the
/// question and the model only rewords the answer.</b> A model is never handed the raw
/// evidence and asked what it thinks, never asked to find anything, and cannot introduce
/// a fact — because the only thing it is given is the answer that was already computed.
/// </para>
/// <para>
/// The consequences are all in the right direction. With no model configured, every
/// answer still works. With a bad model, the phrasing is worse and the facts are the
/// same. With a good one, the operator gets a sentence in their own language instead of a
/// table. And a question the router does not recognise says so, rather than being routed
/// somewhere plausible and answered with confidence.
/// </para>
/// </remarks>
public sealed class SessionAssistant
{
    private readonly SessionQuestions _questions;
    private readonly OllamaClient? _client;

    public SessionAssistant(SessionQuestions questions, OllamaClient? client = null)
    {
        _questions = questions;
        _client = client;
    }

    /// <summary>
    /// How long a local model is given before the deterministic answer is shown alone.
    /// </summary>
    /// <remarks>
    /// A chat that stalls is worse than a chat that answers plainly. The computed answer
    /// is already correct and already on screen; the model is an improvement to it, and
    /// an improvement is not worth waiting a minute for.
    /// </remarks>
    private static readonly TimeSpan PhrasingBudget = TimeSpan.FromSeconds(45);

    public async Task<AssistantReply> AskAsync(
        string question,
        AnswerDetail detail,
        string language,
        string? model,
        CancellationToken cancellationToken = default)
    {
        SessionAnswer answer = _questions.Answer(question, detail);

        if (answer.Kind == SessionQuestionKind.OpenEnded)
        {
            // Nothing recognised. Rather than routing it somewhere plausible, say what
            // can be asked — a wrong answer to a question nobody asked is the failure
            // mode this whole design exists to avoid.
            return new AssistantReply
            {
                Question = question,
                Answer = answer with
                {
                    Text = "I did not recognise that as a question about this session.",
                    Evidence = Suggestions(),
                },
                ModelNote = "not sent to a model: there was no measured answer for it to phrase",
            };
        }

        if (_client is null || model is not { Length: > 0 })
        {
            return new AssistantReply
            {
                Question = question,
                Answer = answer,
                ModelNote = "no model configured — this is the measured answer",
            };
        }

        try
        {
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            budget.CancelAfter(PhrasingBudget);

            string phrased = await _client
                .GenerateAsync(model, BuildPrompt(question, answer, detail, language), budget.Token)
                .ConfigureAwait(false);

            phrased = phrased.Trim();

            return new AssistantReply
            {
                Question = question,
                Answer = answer,
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
                Answer = answer,
                ModelNote = $"the model did not answer within {PhrasingBudget.TotalSeconds:0}s — this is the measured answer",
            };
        }
        catch (OllamaException ex)
        {
            return new AssistantReply
            {
                Question = question,
                Answer = answer,
                ModelNote = $"the model could not be reached ({ex.Message}) — this is the measured answer",
            };
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
    /// Written for a small model, which means: one job, stated first; the facts second;
    /// and an explicit prohibition on the failure mode. "Do not add anything" is the whole
    /// safety property — everything below the facts line is already true, and the model's
    /// only way to make it false is to invent.
    /// </para>
    /// <para>
    /// Length is capped hard. Left unbounded, small models pad an answer to look
    /// thorough, and the operator asked for short and clear.
    /// </para>
    /// </remarks>
    private static string BuildPrompt(string question, SessionAnswer answer, AnswerDetail detail, string language)
    {
        string languageName = language.StartsWith("tr", StringComparison.OrdinalIgnoreCase)
            ? "Turkish"
            : "English";

        var prompt = new StringBuilder();

        prompt.AppendLine($"Rewrite the finding below as a direct answer in {languageName}.");
        prompt.AppendLine();
        prompt.AppendLine("Rules:");
        prompt.AppendLine("- Answer the question in the first sentence.");
        prompt.AppendLine(detail == AnswerDetail.Detailed
            ? "- Then explain what each entry is and why it matters. Stay under 200 words."
            : "- Then at most two short sentences of context. Stay under 60 words.");
        prompt.AppendLine("- Use ONLY the facts given. Do not add examples, causes, or advice that is not there.");
        prompt.AppendLine("- If a fact is not present, do not mention that topic at all.");
        prompt.AppendLine("- Keep file paths, registry keys and names exactly as written.");
        prompt.AppendLine("- No preamble, no closing offer to help.");
        prompt.AppendLine();
        prompt.AppendLine($"Question: {question}");
        prompt.AppendLine();
        prompt.AppendLine($"Measured answer: {answer.Text}");
        prompt.AppendLine();
        prompt.AppendLine("Facts:");
        prompt.AppendLine(Truncate(answer.Facts, 4000));

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
        "What services did it install?",
        "What scheduled tasks did it register?",
        "Which hosts did it connect to?",
        "Did it open any ports?",
        "What files did it write?",
        "What did it change in the registry?",
        "What processes did it start?",
        "Did anything inject into another process?",
        "Summarise this session.",
    };

    private static string Truncate(string text, int max)
        => text.Length <= max ? text : text[..max] + "\n… (truncated)";
}
