using CaYaTrace.Analysis.Ai;
using CaYaTrace.Analysis.Persistence;
using CaYaTrace.Core.Graph;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// The two places a chat answer stops being a chat answer and starts being an action.
/// </summary>
/// <remarks>
/// Narrowing decides which records the operator is looking at; command generation decides
/// what they are about to run against their machine. Both were being done by a language
/// model, and both went wrong in the same session: five hosts returned for a question
/// about one, and removal steps for four services when one was asked about — including
/// Network Location Awareness, which Windows needs.
/// </remarks>
public sealed class AssistantGroundingTests
{
    private static SessionAnswer FiveHosts() => new()
    {
        Kind = SessionQuestionKind.NetworkDestinations,
        Text = "5 host(s).",
        MatchCount = 5,
        Evidence = new[]
        {
            "dns.msftncsi.com  (unattributed, lookup only)",
            "ipv6.msftconnecttest.com  (unattributed, lookup only)",
            "1d.tlu.dl.delivery.mp.microsoft.com  (unattributed, lookup only)",
            "v10.events.data.microsoft.com  (unattributed, lookup only)",
            "www.example.com  (unattributed, lookup only)",
        },
        Facts = "…",
    };

    [Fact]
    public void AskingAboutOneHostAnswersAboutThatHost()
    {
        var vocabulary = new SessionVocabulary();
        vocabulary.AddHost("www.example.com");
        vocabulary.AddHost("dns.msftncsi.com");

        QuestionEntities entities = vocabulary.Extract("example.com e bağlantı yapan varmı");

        SessionAnswer narrowed = SessionQuestions.Narrow(FiveHosts(), entities);

        Assert.Equal(1, narrowed.MatchCount);
        Assert.Single(narrowed.Evidence);
        Assert.Contains("example.com", narrowed.Evidence[0], StringComparison.Ordinal);
        Assert.DoesNotContain(narrowed.Evidence, e => e.Contains("msftncsi", StringComparison.Ordinal));
    }

    /// <summary>
    /// A question that names nothing gets the whole answer, unchanged.
    /// </summary>
    [Fact]
    public void AskingAboutTheTopicAnswersAboutTheTopic()
    {
        var vocabulary = new SessionVocabulary();
        vocabulary.AddHost("www.example.com");

        QuestionEntities entities = vocabulary.Extract("which hosts did it connect to");

        Assert.Equal(5, SessionQuestions.Narrow(FiveHosts(), entities).MatchCount);
    }

    /// <summary>
    /// A name the session never saw is answered with "no", not with everything else.
    /// </summary>
    /// <remarks>
    /// Both of the obvious alternatives are wrong. Listing the other twenty-nine hosts
    /// does not answer the question that was asked, and returning an empty result reads as
    /// though the session recorded no network activity at all. The rows stay as context
    /// under an answer that says the name is not among them.
    /// </remarks>
    [Fact]
    public void ANameTheSessionNeverSawIsAnsweredAsAbsent()
    {
        var vocabulary = new SessionVocabulary();
        QuestionEntities entities = vocabulary.Extract("did anything reach updates.badhost.example");

        SessionAnswer narrowed = SessionQuestions.Narrow(FiveHosts(), entities);

        Assert.Contains("updates.badhost.example", narrowed.Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Nothing here matches", narrowed.Text, StringComparison.Ordinal);

        // The evidence stays, so the operator can see what the session does hold.
        Assert.Equal(5, narrowed.Evidence.Count);

        // But the model is told the answer, not the rows — given the rows it answers
        // about them instead, which is the confusion this exists to prevent.
        Assert.DoesNotContain("msftncsi", narrowed.Facts, StringComparison.Ordinal);
    }

    [Fact]
    public void AServiceIsRecognisedByAnameOnlyTheSessionCouldKnow()
    {
        var vocabulary = new SessionVocabulary();
        vocabulary.AddService("a1b2c3d4e5f60718");
        vocabulary.AddService("DelayedSvc");

        QuestionEntities entities = vocabulary.Extract("delayedsvc servisini kaldırmak istiyorum");

        Assert.Contains("DelayedSvc", entities.Services);
        Assert.DoesNotContain("a1b2c3d4e5f60718", entities.Services);
    }

    [Fact]
    public void AFileIsRecognisedByItsLeafName()
    {
        var vocabulary = new SessionVocabulary();
        vocabulary.AddFile(@"C:\WINDOWS\SysWOW64\helper64.dll");

        QuestionEntities entities = vocabulary.Extract("helper64.dll nedir");

        Assert.Contains(entities.Files, f => f.Contains("helper64.dll", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("127.0.0.1 bağlantısı var mı", "127.0.0.1")]
    [InlineData("what happened on 192.168.1.50", "192.168.1.50")]
    public void AddressesAreRecognisedEvenWhenTheSessionNeverSawThem(string question, string expected)
    {
        Assert.Contains(expected, new SessionVocabulary().Extract(question).Addresses);
    }

    private static PersistenceRecord Record(string identity, RiskLevel risk, PersistenceKind kind, string? command)
        => new()
        {
            Kind = kind,
            Identity = identity,
            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{identity}",
            Command = command,
            Risk = risk,
            Reasons = new[] { "runs as LocalSystem", "name has no meaning" },
        };

    /// <summary>
    /// The failure this whole path exists to prevent.
    /// </summary>
    /// <remarks>
    /// NlaSvc is Network Location Awareness. A model handed a list of four services and
    /// asked for removal steps wrote them for all four, and an operator following that
    /// advice loses their network stack. The scoring already knew it was unremarkable; the
    /// command path now asks.
    /// </remarks>
    [Fact]
    public void SomethingTheAnalyzerFoundUnremarkableGetsNoRemovalCommand()
    {
        GeneratedCommand command = RemediationCommands.ForPersistence(
            Record("NlaSvc", RiskLevel.Low, PersistenceKind.Service, null));

        Assert.True(command.Refused);
        Assert.Empty(command.Lines);
        Assert.Contains("NlaSvc", command.Rationale, StringComparison.Ordinal);
    }

    [Fact]
    public void ASuspiciousServiceGetsStoppedBeforeItIsDeleted()
    {
        GeneratedCommand command = RemediationCommands.ForPersistence(Record(
            "a1b2c3d4e5f60718", RiskLevel.High, PersistenceKind.Service,
            @"C:\WINDOWS\SysWOW64\7669\f0e1d2c3b4a59687.exe"));

        Assert.False(command.Refused);
        Assert.Equal(3, command.Lines.Count);

        // Order is not cosmetic: a running service holds its image open, so deleting the
        // file first fails and leaves the service registered.
        Assert.StartsWith("sc.exe stop", command.Lines[0], StringComparison.Ordinal);
        Assert.StartsWith("sc.exe delete", command.Lines[1], StringComparison.Ordinal);
        Assert.Contains("f0e1d2c3b4a59687.exe", command.Lines[2], StringComparison.Ordinal);
    }

    /// <summary>
    /// A service command is a command line, not a path.
    /// </summary>
    /// <remarks>
    /// Passing the whole string to a delete would either fail or, worse, delete something
    /// whose name happened to parse out of the arguments.
    /// </remarks>
    [Theory]
    [InlineData(@"""C:\Program Files\X\x.exe"" -service", @"C:\Program Files\X\x.exe")]
    [InlineData(@"C:\WINDOWS\system32\svcworker.exe /run", @"C:\WINDOWS\system32\svcworker.exe")]
    public void OnlyTheExecutableIsDeleted(string command, string expected)
    {
        GeneratedCommand generated = RemediationCommands.ForPersistence(
            Record("DelayedSvc", RiskLevel.High, PersistenceKind.Service, command));

        Assert.Contains(generated.Lines, l => l.Contains(expected, StringComparison.Ordinal));
        Assert.DoesNotContain(generated.Lines, l => l.Contains("/run", StringComparison.Ordinal));
        Assert.DoesNotContain(generated.Lines, l => l.Contains("-service", StringComparison.Ordinal));
    }

    /// <summary>
    /// A driver registered by a relative path is not turned into a delete.
    /// </summary>
    [Fact]
    public void ARelativeImagePathIsNotDeleted()
    {
        GeneratedCommand command = RemediationCommands.ForPersistence(
            Record("Revoflt", RiskLevel.High, PersistenceKind.Service, @"system32\DRIVERS\revoflt.sys"));

        Assert.DoesNotContain(command.Lines, l => l.Contains("Remove-Item", StringComparison.Ordinal));
    }

    [Fact]
    public void AScheduledTaskIsDeletedThroughTheScheduler()
    {
        GeneratedCommand command = RemediationCommands.ForPersistence(
            Record(@"\Microsoft\Windows\Xyz\Updater", RiskLevel.High, PersistenceKind.ScheduledTask, null));

        Assert.Contains("schtasks.exe /Delete", command.Lines[0], StringComparison.Ordinal);
        Assert.Contains(@"\Microsoft\Windows\Xyz\Updater", command.Lines[0], StringComparison.Ordinal);
    }

    [Fact]
    public void TheReasonsForRemovalAreTheAnalyzersOwn()
    {
        GeneratedCommand command = RemediationCommands.ForPersistence(
            Record("a1b2c3d4e5f60718", RiskLevel.High, PersistenceKind.Service, null));

        Assert.Contains("runs as LocalSystem", command.Rationale, StringComparison.Ordinal);
    }
}
