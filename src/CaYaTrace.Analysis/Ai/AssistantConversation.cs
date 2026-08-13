namespace CaYaTrace.Analysis.Ai;

/// <summary>What a follow-up asks the assistant to do with the previous answer.</summary>
public enum FollowUpIntent
{
    /// <summary>Not a follow-up — a question that stands on its own.</summary>
    None,

    /// <summary>"Only the relevant one." Narrow the previous answer.</summary>
    Narrow,

    /// <summary>"Which is more critical?" Rank the previous answer.</summary>
    Rank,

    /// <summary>"Write that as a one-line PowerShell command."</summary>
    Command,

    /// <summary>"What is it, what does it do?"</summary>
    Explain,

    /// <summary>"Say more about that." Same question, more detail.</summary>
    Expand,
}

/// <summary>One exchange, kept so the next one can refer to it.</summary>
public sealed record ConversationTurn
{
    public required string Question { get; init; }

    public required SessionQuestionKind Kind { get; init; }

    /// <summary>What the question named, so "that one" has something to point at.</summary>
    public QuestionEntities Entities { get; init; } = QuestionEntities.None;

    /// <summary>The measured answer's headline, for the model's benefit.</summary>
    public string Headline { get; init; } = string.Empty;

    /// <summary>
    /// The rows the previous answer produced.
    /// </summary>
    /// <remarks>
    /// Kept because narrowing and ranking operate on the previous answer's rows, not on a
    /// fresh query. "Which of those is more critical" means those, and re-running the
    /// query would silently answer about a different set if anything had changed.
    /// </remarks>
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}

/// <summary>
/// The recent history of a chat about one session.
/// </summary>
/// <remarks>
/// <para>
/// Every question used to be routed on its own, and a conversation is not a series of
/// unrelated questions. From a real transcript: "which addresses are suspicious", then
/// "which is more critical" — not recognised; "how do I remove these services", then "write
/// that as a one-line PowerShell command" — answered with a command about files. Each of
/// those is a perfectly clear follow-up and none of them means anything without the turn
/// before it.
/// </para>
/// <para>
/// Bounded on purpose. The operator's questions are short and the useful context is the
/// last few, while an unbounded history is a slow prompt and, on a small model, a worse
/// answer — they lose the question in the middle of a long context. It is cleared on
/// request, because a session chat can wander onto something the operator would rather not
/// carry forward.
/// </para>
/// </remarks>
public sealed class AssistantConversation
{
    /// <summary>
    /// How many exchanges are remembered.
    /// </summary>
    /// <remarks>
    /// Six is two or three questions and their follow-ups, which is as far back as
    /// "that one" ever reaches in practice.
    /// </remarks>
    public const int Capacity = 6;

    private readonly List<ConversationTurn> _turns = new();

    public IReadOnlyList<ConversationTurn> Turns => _turns;

    public ConversationTurn? Last => _turns.Count > 0 ? _turns[^1] : null;

    public bool IsEmpty => _turns.Count == 0;

    public void Remember(ConversationTurn turn)
    {
        _turns.Add(turn);
        if (_turns.Count > Capacity) _turns.RemoveRange(0, _turns.Count - Capacity);
    }

    public void Clear() => _turns.Clear();

    /// <summary>
    /// The last turn that produced a real answer about the session.
    /// </summary>
    /// <remarks>
    /// A follow-up refers to the last thing that was actually answered, not to the last
    /// thing that was typed — otherwise one unrecognised question in the middle breaks the
    /// thread for everything after it.
    /// </remarks>
    public ConversationTurn? LastAnswered() =>
        _turns.LastOrDefault(static t => t.Kind != SessionQuestionKind.OpenEnded);

    private static readonly (FollowUpIntent Intent, string[] Words)[] Signals =
    {
        (FollowUpIntent.Command, new[]
        {
            "powershell", "command line", "one line", "one-line", "single line", "cmd",
            "script", "komut", "tek satır", "tek bir satır", "terminal",
        }),
        (FollowUpIntent.Rank, new[]
        {
            "which is more", "which one is", "most critical", "most important", "most dangerous",
            "rank", "worst", "priority", "riskiest",
            "hangisi daha", "en kritik", "en önemli", "en tehlikeli", "en riskli", "öncelik",
            "hangisi önce",
        }),
        (FollowUpIntent.Narrow, new[]
        {
            "only the", "just the", "relevant", "narrow", "filter", "that one", "which of those",
            "sadece", "yalnızca", "ilgili olan", "bununla ilgili", "sadece bunu", "onu",
        }),
        (FollowUpIntent.Explain, new[]
        {
            "what is it", "what does it do", "what is this", "what are these", "why",
            "explain", "purpose", "meaning",
            "ne işe yar", "ne yapıyor", "bu ne", "bunlar ne", "neden", "açıkla", "amacı",
        }),
        (FollowUpIntent.Expand, new[]
        {
            "more detail", "tell me more", "go on", "elaborate", "in detail",
            "daha fazla", "detay", "ayrıntı", "devam",
        }),
    };

    /// <summary>
    /// Reads a question as a follow-up, when it is one.
    /// </summary>
    /// <remarks>
    /// Longest match wins for the same reason topic matching uses it: "tek bir satır" and
    /// "satır" would otherwise be decided by declaration order.
    /// </remarks>
    public static FollowUpIntent ReadFollowUp(string question)
    {
        string lower = question.ToLowerInvariant();

        FollowUpIntent best = FollowUpIntent.None;
        int bestLength = 0;

        foreach ((FollowUpIntent intent, string[] words) in Signals)
        {
            foreach (string word in words)
            {
                if (word.Length <= bestLength) continue;
                if (!lower.Contains(word, StringComparison.Ordinal)) continue;

                best = intent;
                bestLength = word.Length;
            }
        }

        return best;
    }

    /// <summary>
    /// Renders the history for a model prompt.
    /// </summary>
    /// <remarks>
    /// Questions and headlines only — never the evidence rows. A small model given several
    /// turns of full evidence answers about the wrong turn, and the rows for the current
    /// question are already in the prompt below this.
    /// </remarks>
    public string Describe()
    {
        if (_turns.Count == 0) return string.Empty;

        var text = new System.Text.StringBuilder();
        foreach (ConversationTurn turn in _turns)
        {
            text.Append("Q: ").AppendLine(turn.Question.Trim());
            if (turn.Headline.Length > 0) text.Append("A: ").AppendLine(turn.Headline.Trim());
        }

        return text.ToString().TrimEnd();
    }
}
