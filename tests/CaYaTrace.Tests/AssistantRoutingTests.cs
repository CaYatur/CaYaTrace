using CaYaTrace.Analysis.Ai;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// How a question is read before anything is looked up.
/// </summary>
/// <remarks>
/// Every case here is a question from a real transcript that the assistant got wrong. They
/// are kept as the operator typed them, in the language they typed them in, because the
/// failures were specific to that: Turkish attaches suffixes, and a substring match on a
/// two-letter keyword reads a question about programs as a question about sockets.
/// </remarks>
public sealed class AssistantRoutingTests
{
    [Theory]
    // "which programs opened during the recording" — matched the listener keyword "aç"
    // inside "açıldı" and answered with seventy-three listening sockets.
    [InlineData("hangi programlar açıldı kayıt esnasında", SessionQuestionKind.ProcessesStarted)]
    [InlineData("hangi uygulamalar açıldı kayıt esnasında", SessionQuestionKind.ProcessesStarted)]

    // "did programs communicate on the local network" — answered "no" and then listed
    // five hosts on the internet, while the loopback conversations sat unread.
    [InlineData("yerel ağda uygulamalar haberleşmişmi", SessionQuestionKind.LocalConversations)]
    [InlineData("did anything talk to each other on this machine", SessionQuestionKind.LocalConversations)]
    [InlineData("127.0.0.1 bağlantısı gerçekleşmemişmi", SessionQuestionKind.LocalConversations)]

    // These still have to route where they always did.
    [InlineData("example.com e bağlantı yapan varmı", SessionQuestionKind.NetworkDestinations)]
    [InlineData("servisleri varmı", SessionQuestionKind.Services)]
    [InlineData("hangi dosya işlemleri virüs şüpheli", SessionQuestionKind.FilesDropped)]
    [InlineData("did it open any ports", SessionQuestionKind.Listeners)]
    [InlineData("what scheduled tasks did it register", SessionQuestionKind.ScheduledTasks)]
    public void QuestionsRouteWhereTheyMean(string question, SessionQuestionKind expected)
    {
        Assert.Equal(expected, SessionQuestions.Classify(question));
    }

    /// <summary>
    /// A keyword has to be a word, not a run of letters inside one.
    /// </summary>
    /// <remarks>
    /// Only the start is anchored. Turkish suffixes are the reason: "servis" must still
    /// match "servisleri" and "bağlan" must still match "bağlantı", so anchoring the end
    /// would break far more questions than it fixed.
    /// </remarks>
    [Theory]
    [InlineData("servisleri kaldır", SessionQuestionKind.Services)]
    [InlineData("bağlantıları göster", SessionQuestionKind.NetworkDestinations)]
    [InlineData("dosyaları listele", SessionQuestionKind.FilesDropped)]
    public void SuffixesStillMatch(string question, SessionQuestionKind expected)
    {
        Assert.Equal(expected, SessionQuestions.Classify(question));
    }

    [Theory]
    [InlineData("sadece ilgili olanı istiyorum", FollowUpIntent.Narrow)]
    [InlineData("peki hangisi daha kritik", FollowUpIntent.Rank)]
    [InlineData("tek bir satırda powershell komutu olarak yaz bunu", FollowUpIntent.Command)]
    [InlineData("which is more critical", FollowUpIntent.Rank)]
    [InlineData("what does it do", FollowUpIntent.Explain)]
    [InlineData("bu ne işe yarıyor", FollowUpIntent.Explain)]
    [InlineData("daha fazla detay ver", FollowUpIntent.Expand)]
    [InlineData("which hosts did it connect to", FollowUpIntent.None)]
    public void FollowUpsAreRecognised(string question, FollowUpIntent expected)
    {
        Assert.Equal(expected, AssistantConversation.ReadFollowUp(question));
    }

    [Fact]
    public void AFollowUpSkipsPastAQuestionThatWasNotUnderstood()
    {
        var conversation = new AssistantConversation();

        conversation.Remember(new ConversationTurn
        {
            Question = "servisleri varmı",
            Kind = SessionQuestionKind.Services,
            Headline = "4 service(s).",
        });

        conversation.Remember(new ConversationTurn
        {
            Question = "asdfgh",
            Kind = SessionQuestionKind.OpenEnded,
        });

        // "Which is more critical" refers to the services, not to the question in between
        // that produced nothing.
        Assert.Equal(SessionQuestionKind.Services, conversation.LastAnswered()!.Kind);
    }

    [Fact]
    public void TheConversationForgetsTheOldestTurnsRatherThanGrowing()
    {
        var conversation = new AssistantConversation();

        for (int i = 0; i < AssistantConversation.Capacity + 4; i++)
        {
            conversation.Remember(new ConversationTurn
            {
                Question = $"question {i}",
                Kind = SessionQuestionKind.Services,
            });
        }

        Assert.Equal(AssistantConversation.Capacity, conversation.Turns.Count);
        Assert.Equal($"question {AssistantConversation.Capacity + 3}", conversation.Last!.Question);
    }

    [Fact]
    public void ClearingLeavesNothingBehind()
    {
        var conversation = new AssistantConversation();
        conversation.Remember(new ConversationTurn { Question = "q", Kind = SessionQuestionKind.Services });

        conversation.Clear();

        Assert.True(conversation.IsEmpty);
        Assert.Null(conversation.LastAnswered());
        Assert.Equal(string.Empty, conversation.Describe());
    }

    /// <summary>The history never carries evidence rows into the prompt.</summary>
    /// <remarks>
    /// A small model given several turns of full evidence answers about the wrong turn,
    /// and the rows for the current question are already in the prompt below it.
    /// </remarks>
    [Fact]
    public void TheHistorySentToAModelIsQuestionsAndHeadlinesOnly()
    {
        var conversation = new AssistantConversation();
        conversation.Remember(new ConversationTurn
        {
            Question = "servisleri varmı",
            Kind = SessionQuestionKind.Services,
            Headline = "4 service(s).",
            Evidence = new[] { "Service · 61df826a3fa71fa6 → C:\\WINDOWS\\SysWOW64\\7669\\b87745ac3eb33a07.exe" },
        });

        string described = conversation.Describe();

        Assert.Contains("servisleri varmı", described, StringComparison.Ordinal);
        Assert.Contains("4 service(s).", described, StringComparison.Ordinal);
        Assert.DoesNotContain("b87745ac3eb33a07", described, StringComparison.Ordinal);
    }
}
