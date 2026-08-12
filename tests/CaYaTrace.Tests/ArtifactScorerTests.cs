using CaYaTrace.Analysis;
using CaYaTrace.Analysis.Ai;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// The deterministic scorer decides which handful of artifacts a model ever sees, and
/// it is the only part of the analysis an analyst can audit. If it ranks wrongly, the
/// model is handed the wrong needle no matter how good it is.
/// </summary>
public sealed class ArtifactScorerTests
{
    private static readonly ArtifactScorer Scorer = new();

    private static Observation Make(EventCategory category, EventAction action, string target, string? target2 = null)
        => new()
        {
            Seq = 1,
            Timestamp = DateTimeOffset.UtcNow,
            Category = category,
            Action = action,
            Actor = ProcessKey.FromStartKey(100, 0xABC, DateTimeOffset.UtcNow),
            Confidence = AttributionConfidence.Direct,
            Target = target,
            Target2 = target2,
        };

    [Fact]
    public void AutostartOutranksAnOrdinaryFileWrite()
    {
        ScoredArtifact autostart = Scorer.Score(Make(
            EventCategory.Autorun, EventAction.AutorunAdd,
            @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Updater"));

        ScoredArtifact ordinary = Scorer.Score(Make(
            EventCategory.File, EventAction.FileWrite, @"%APPDATA%\Vendor\notes.txt"));

        Assert.True(autostart.Score > ordinary.Score);
        Assert.True(autostart.Risk >= RiskLevel.High);
    }

    [Fact]
    public void CodeInjectionScoresAboveEverythingRoutine()
    {
        ScoredArtifact injection = Scorer.Score(Make(
            EventCategory.Process, EventAction.RemoteThread, "notepad.exe (4812)"));

        Assert.Equal(RiskLevel.Critical, injection.Risk);
        Assert.Contains(injection.Reasons, static r => r.Contains("injection", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void EveryScoreCarriesItsReasons()
    {
        // A score an analyst cannot interrogate is worse than no score.
        ScoredArtifact scored = Scorer.Score(Make(
            EventCategory.File, EventAction.FileCreate, @"%APPDATA%\Vendor\payload.exe"));

        Assert.NotEmpty(scored.Reasons);
        Assert.Contains(scored.Reasons, static r => r.Contains("executable", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(scored.Reasons, static r => r.Contains("user-writable", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UnattributedChangesAreRankedLowerButNotDiscarded()
    {
        Observation attributed = Make(EventCategory.File, EventAction.FileCreate, @"%APPDATA%\V\a.exe");
        Observation orphan = attributed with { Actor = ProcessKey.None, Confidence = AttributionConfidence.None };

        Assert.True(Scorer.Score(orphan).Score < Scorer.Score(attributed).Score);
        Assert.True(Scorer.Score(orphan).Score > 0);
    }

    [Fact]
    public void RepeatedTouchesOfOneArtifactCollapseToOneFinding()
    {
        var observations = Enumerable.Range(0, 50)
            .Select(i => Make(EventCategory.File, EventAction.FileWrite, @"%APPDATA%\V\payload.exe") with { Seq = i })
            .ToList();

        Assert.Single(Scorer.TopFindings(observations));
    }

    [Fact]
    public void AnOrdinaryDocumentWriteIsNotAFinding()
    {
        // Writing a text file into the user's own data is what software does. Scoring
        // it above zero would bury the real findings under routine behaviour — and it
        // is the model's input list, so noise here wastes the model's attention too.
        var observations = new[]
        {
            Make(EventCategory.File, EventAction.FileWrite, @"%APPDATA%\Vendor\notes.txt"),
        };

        Assert.Empty(Scorer.TopFindings(observations));
    }

    [Fact]
    public void ReadsNeverReachTheFindingsList()
    {
        var observations = new[]
        {
            Make(EventCategory.File, EventAction.FileRead, @"%WINDIR%\System32\kernel32.dll"),
            Make(EventCategory.Registry, EventAction.KeyOpen, @"HKLM\SOFTWARE\Microsoft"),
        };

        Assert.Empty(Scorer.TopFindings(observations));
    }

    [Fact]
    public void FindingsComeBackHighestFirst()
    {
        var observations = new[]
        {
            Make(EventCategory.File, EventAction.FileWrite, @"%APPDATA%\V\readme.txt"),
            Make(EventCategory.Service, EventAction.ServiceInstall, "VendorSync"),
            Make(EventCategory.File, EventAction.FileCreate, @"%APPDATA%\V\tool.exe"),
        };

        IReadOnlyList<ScoredArtifact> ranked = Scorer.TopFindings(observations);

        Assert.Equal("VendorSync", ranked[0].Observation.Target);
        Assert.True(ranked[0].Score >= ranked[^1].Score);
    }
}

/// <summary>
/// Parsing behaviour that keeps a weak model's output usable, tested without needing a
/// model present.
/// </summary>
public sealed class OllamaParsingTests
{
    [Fact]
    public void ObjectWrappedInProseIsRecovered()
    {
        // Small models add commentary despite a schema. Salvaging beats discarding.
        const string reply = "Sure! Here is the answer:\n```json\n{\"label\": \"persistence\"}\n```\nHope that helps.";

        string? extracted = OllamaClient.ExtractFirstJsonObject(reply);

        Assert.Equal("{\"label\": \"persistence\"}", extracted);
    }

    [Fact]
    public void NestedBracesDoNotTruncateTheObject()
    {
        const string reply = "{\"a\": {\"b\": 1}, \"c\": 2}";

        Assert.Equal(reply, OllamaClient.ExtractFirstJsonObject(reply));
    }

    [Fact]
    public void BracesInsideStringsAreNotCountedAsStructure()
    {
        // Registry and GUID paths routinely contain braces.
        const string reply = @"{""target"": ""HKCR\\CLSID\\{3F2504E0-4F89}"", ""label"": ""config""}";

        Assert.Equal(reply, OllamaClient.ExtractFirstJsonObject(reply));
    }

    [Fact]
    public void EscapedQuotesDoNotEndTheString()
    {
        const string reply = @"{""note"": ""he said \""hi\"" loudly"", ""label"": ""log""}";

        Assert.Equal(reply, OllamaClient.ExtractFirstJsonObject(reply));
    }

    [Fact]
    public void TextWithNoObjectYieldsNothing()
    {
        Assert.Null(OllamaClient.ExtractFirstJsonObject("I cannot help with that request."));
    }
}

/// <summary>
/// The checks that keep a weak model from turning a correct finding into a wrong one.
/// </summary>
public sealed class ModelGuardrailTests
{
    [Fact]
    public void ScorerFlagsRegistryRunKeyWritesAsAutostart()
    {
        // A write to a Run key is categorised as Registry, not Autorun. If the
        // disagreement check keyed on category alone, a model calling this "cache"
        // would go unchallenged — which is the exact case that slipped through.
        var scorer = new ArtifactScorer();

        ScoredArtifact scored = scorer.Score(new Observation
        {
            Seq = 1,
            Timestamp = DateTimeOffset.UtcNow,
            Category = EventCategory.Registry,
            Action = EventAction.ValueSet,
            Target = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            Target2 = "Updater",
            Confidence = AttributionConfidence.Direct,
        });

        Assert.True(scored.Risk >= RiskLevel.High);
        Assert.Contains(scored.Reasons, static r => r.Contains("auto-start", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CacheAndLogPathsDoNotReachAutostartRisk()
    {
        var scorer = new ArtifactScorer();

        ScoredArtifact log = scorer.Score(new Observation
        {
            Seq = 1,
            Timestamp = DateTimeOffset.UtcNow,
            Category = EventCategory.File,
            Action = EventAction.FileWrite,
            Target = @"%PROGRAMDATA%\Vendor\logs\install.log",
            Confidence = AttributionConfidence.Direct,
        });

        Assert.True(log.Risk < RiskLevel.High);
    }
}
