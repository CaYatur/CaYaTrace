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
    /// Narrowing that matches nothing leaves the answer alone.
    /// </summary>
    /// <remarks>
    /// The operator asked about a topic the session has rows for. Returning "0 host(s)"
    /// because the entity matcher was too strict would be the tool hiding evidence it
    /// holds; the full answer is a worse answer than the narrow one and a far better one
    /// than nothing.
    /// </remarks>
    [Fact]
    public void ANarrowingThatMatchesNothingKeepsTheAnswer()
    {
        var vocabulary = new SessionVocabulary();
        QuestionEntities entities = vocabulary.Extract("did anything reach example.invalid");

        Assert.Equal(5, SessionQuestions.Narrow(FiveHosts(), entities).MatchCount);
    }

    [Fact]
    public void AServiceIsRecognisedByAnameOnlyTheSessionCouldKnow()
    {
        var vocabulary = new SessionVocabulary();
        vocabulary.AddService("61df826a3fa71fa6");
        vocabulary.AddService("WinDelay");

        QuestionEntities entities = vocabulary.Extract("windelay servisini kaldırmak istiyorum");

        Assert.Contains("WinDelay", entities.Services);
        Assert.DoesNotContain("61df826a3fa71fa6", entities.Services);
    }

    [Fact]
    public void AFileIsRecognisedByItsLeafName()
    {
        var vocabulary = new SessionVocabulary();
        vocabulary.AddFile(@"C:\WINDOWS\SysWOW64\msdatacomp64.dll");

        QuestionEntities entities = vocabulary.Extract("msdatacomp64.dll nedir");

        Assert.Contains(entities.Files, f => f.Contains("msdatacomp64.dll", StringComparison.OrdinalIgnoreCase));
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
            "61df826a3fa71fa6", RiskLevel.High, PersistenceKind.Service,
            @"C:\WINDOWS\SysWOW64\7669\b87745ac3eb33a07.exe"));

        Assert.False(command.Refused);
        Assert.Equal(3, command.Lines.Count);

        // Order is not cosmetic: a running service holds its image open, so deleting the
        // file first fails and leaves the service registered.
        Assert.StartsWith("sc.exe stop", command.Lines[0], StringComparison.Ordinal);
        Assert.StartsWith("sc.exe delete", command.Lines[1], StringComparison.Ordinal);
        Assert.Contains("b87745ac3eb33a07.exe", command.Lines[2], StringComparison.Ordinal);
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
    [InlineData(@"C:\WINDOWS\system32\windelayer.exe /run", @"C:\WINDOWS\system32\windelayer.exe")]
    public void OnlyTheExecutableIsDeleted(string command, string expected)
    {
        GeneratedCommand generated = RemediationCommands.ForPersistence(
            Record("WinDelay", RiskLevel.High, PersistenceKind.Service, command));

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
            Record("61df826a3fa71fa6", RiskLevel.High, PersistenceKind.Service, null));

        Assert.Contains("runs as LocalSystem", command.Rationale, StringComparison.Ordinal);
    }
}
