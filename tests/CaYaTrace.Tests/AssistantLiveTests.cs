using CaYaTrace.Analysis.Ai;
using CaYaTrace.Analysis.Persistence;
using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Model;
using CaYaTrace.Storage;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// Drives the assistant over a real session, optionally with a real model.
/// </summary>
/// <remarks>
/// <para>
/// Skipped unless <c>CAYATRACE_LIVE_SESSION</c> points at a recorded session, because it
/// needs one and CI has none. Set <c>CAYATRACE_LIVE_MODEL</c> as well to put a local model
/// in the loop.
/// </para>
/// <para>
/// This exists because the assistant's failures were never visible from the unit tests.
/// Routing and narrowing can each be right while the answer an operator reads is still
/// wrong, and the only way to see that is to ask the questions they asked and read what
/// comes back.
/// </para>
/// </remarks>
public sealed class AssistantLiveTests
{
    private readonly ITestOutputHelper _sink;
    private readonly System.Text.StringBuilder _log = new();

    public AssistantLiveTests(ITestOutputHelper output) => _sink = output;

    /// <summary>
    /// Writes to the test output and to a transcript file.
    /// </summary>
    /// <remarks>
    /// The file is the point. A passing test's output is not shown by the runner, and the
    /// whole value of this harness is reading what the assistant said — a green tick tells
    /// you nothing about whether the answer was any good.
    /// </remarks>
    private void Say(string line)
    {
        _sink.WriteLine(line);
        _log.AppendLine(line);
    }

    private static string? SessionPath => Environment.GetEnvironmentVariable("CAYATRACE_LIVE_SESSION");

    private static string? Model => Environment.GetEnvironmentVariable("CAYATRACE_LIVE_MODEL");

    /// <summary>
    /// The transcript, replayed in order.
    /// </summary>
    /// <remarks>
    /// Kept as the operator typed them, mistakes and all — "şühpeli" is misspelled in the
    /// original and the assistant still has to cope, because operators type quickly.
    /// </remarks>
    private static readonly string[] Transcript =
    {
        "example.com e bağlantı yapan varmı",
        "sadece ilgili olanı istiyorum",
        "hangi adresler şüpheli bağlantılar arasından",
        "servisleri varmı",
        "peki hangisi daha kritik",
        "yerel ağda uygulamalar haberleşmişmi",
        "127.0.0.1",
        "hangi programlar açıldı kayıt esnasında",
        "hangi dosya işlemleri virüs şühpeli",
        "bu şüpheli servisleri nasıl kaldırırım",
        "tek satırda powershell komutu olarak yaz bunu",
        "Bu oturumu özetle.",
    };

    [Fact]
    public async Task TheTranscriptIsAnswered()
    {
        // No session, nothing to drive. Returning rather than failing keeps this in the
        // normal test run as a no-op, so it cannot rot unnoticed the way a test nobody
        // ever compiles does.
        if (SessionPath is null || !File.Exists(SessionPath))
        {
            Say("set CAYATRACE_LIVE_SESSION to a recorded session to run this");
            return;
        }

        using SessionStore store = SessionStore.Open(SessionPath!);
        SessionInfo? session = store.LoadSessionInfo();
        Assert.NotNull(session);

        List<ProcessNode> processes = store.LoadProcesses();
        var byKey = new Dictionary<ProcessKey, ProcessNode>();
        foreach (ProcessNode node in processes) byKey.TryAdd(node.Key, node);

        IReadOnlyList<PersistenceRecord> persistence =
            new PersistenceAnalyzer(byKey.GetValueOrDefault).Analyze(store.Query());

        var questions = new SessionQuestions(store, session!, persistence, processes);

        OllamaClient? client = Model is null ? null : new OllamaClient(new Uri("http://localhost:11434"));
        var assistant = new SessionAssistant(questions, client, persistence, processes);

        Say($"session   {SessionPath}");
        Say($"model     {Model ?? "(none)"}");
        Say($"processes {processes.Count}   persistence {persistence.Count}");
        Say(new string('=', 78));

        int unrecognised = 0;

        foreach (string question in Transcript)
        {
            AssistantReply reply = await assistant.AskAsync(
                question, AnswerDetail.Brief, "tr", Model, CancellationToken.None);

            Say($"Q  {question}");
            Say($"   kind={reply.Answer.Kind} followUp={reply.FollowUp} matches={reply.Answer.MatchCount}");
            Say($"A  {reply.Answer.Text}");

            foreach (string row in reply.Answer.Evidence.Take(6)) Say($"     {row}");
            if (reply.Answer.Evidence.Count > 6)
                Say($"     … {reply.Answer.Evidence.Count - 6} more");

            if (reply.Command is { } command)
            {
                Say(command.Refused
                    ? $"!  refused: {command.Rationale}"
                    : $">  {string.Join(" ; ", command.Lines)}");
            }

            if (reply.Phrased is { Length: > 0 } phrased) Say($"M  {phrased}");
            if (reply.ModelNote is { Length: > 0 } note) Say($"   ({note})");

            Say(string.Empty);

            if (!reply.Understood) unrecognised++;
        }

        client?.Dispose();

        Say(new string('=', 78));
        Say($"unrecognised: {unrecognised} of {Transcript.Length}");

        if (Environment.GetEnvironmentVariable("CAYATRACE_LIVE_OUT") is { Length: > 0 } path)
            File.WriteAllText(path, _log.ToString());

        // Every question in this transcript is one an operator asked in earnest. Four of
        // them used to come back as "I did not recognise that as a question about this
        // session"; none of them should now.
        Assert.Equal(0, unrecognised);
    }
}
