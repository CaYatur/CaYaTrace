using CaYaTrace.Analysis;
using CaYaTrace.Core.Model;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Templating decides what a removal package will match on a machine it has never
/// seen. A variable slot that is too eager widens a removal; one that is too timid
/// makes the package match nothing. Both failures are silent.
/// </summary>
public sealed class PathTemplateTests
{
    [Fact]
    public void SegmentsThatDifferAcrossMachinesBecomeVariables()
    {
        // The case the whole feature exists for: one dropper, two VMs, different
        // random working directories.
        PathTemplate? template = PathTemplater.FromObservations(new[]
        {
            @"%APPDATA%\a8f3c1d0\svc.exe",
            @"%APPDATA%\d92b4711\svc.exe",
        });

        Assert.NotNull(template);
        Assert.Equal(TemplateEvidence.Observed, template.Evidence);
        Assert.Equal(@"%APPDATA%\{*}\svc.exe", template.Pattern);
        Assert.True(template.Matches(@"%APPDATA%\0f11ab99\svc.exe"));
    }

    [Fact]
    public void SegmentsThatAgreeStayLiteral()
    {
        PathTemplate? template = PathTemplater.FromObservations(new[]
        {
            @"%PROGRAMFILES%\Example\app.exe",
            @"%PROGRAMFILES%\Example\app.exe",
        });

        Assert.NotNull(template);
        Assert.False(template.HasVariables);
        Assert.False(template.Matches(@"%PROGRAMFILES%\Other\app.exe"));
    }

    [Fact]
    public void DifferingDepthsAreNotAlignedIntoOneTemplate()
    {
        // Forcing an alignment across depths would produce a template that matches
        // paths neither observation supports.
        PathTemplate? template = PathTemplater.FromObservations(new[]
        {
            @"%APPDATA%\Example\app.exe",
            @"%APPDATA%\Example\sub\app.exe",
        });

        Assert.Null(template);
    }

    [Fact]
    public void TemplatesDoNotMatchAcrossDirectoryDepth()
    {
        // %APPDATA%\{*}\svc.exe must not authorize removing %APPDATA%\a\b\svc.exe.
        PathTemplate? template = PathTemplater.FromObservations(new[]
        {
            @"%APPDATA%\a8f3c1d0\svc.exe",
            @"%APPDATA%\d92b4711\svc.exe",
        });

        Assert.NotNull(template);
        Assert.False(template.Matches(@"%APPDATA%\a\b\svc.exe"));
    }

    [Theory]
    [InlineData(@"{3F2504E0-4F89-11D3-9A0C-0305E82C3301}")]
    [InlineData("3F2504E0-4F89-11D3-9A0C-0305E82C3301")]
    [InlineData("a8f3c1d0e5b27a94")]
    [InlineData("tmp4f8a92")]
    [InlineData("20260811143022")]
    public void GeneratedDirectoryNamesAreInferredAsVariable(string segment)
        => Assert.True(PathTemplater.LooksVariable(segment));

    [Theory]
    [InlineData("Example")]
    [InlineData("Microsoft")]
    [InlineData("bin")]
    [InlineData("v2")]
    [InlineData("Common Files")]
    [InlineData("net8.0-windows")]
    public void OrdinaryDirectoryNamesStayLiteral(string segment)
        => Assert.False(PathTemplater.LooksVariable(segment));

    [Theory]
    [InlineData("setup.exe")]
    [InlineData("SetupHelper64.exe")]
    [InlineData("app-config-v2.json")]
    [InlineData("vcruntime140.dll")]
    public void OrdinaryFileNamesAreNeverTreatedAsRandom(string name)
        => Assert.False(PathTemplater.LooksStronglyRandom(name));

    [Fact]
    public void SingleObservationIsMarkedInferredNotObserved()
    {
        // An inferred template is a guess, and a removal plan must be able to tell.
        PathTemplate template = PathTemplater.Infer(@"%APPDATA%\a8f3c1d0e5b27a94\svc.exe");

        Assert.Equal(TemplateEvidence.Inferred, template.Evidence);
        Assert.True(template.HasVariables);
    }

    [Fact]
    public void EntropySeparatesGeneratedNamesFromWords()
    {
        Assert.True(PathTemplater.ShannonEntropy("xK7pQ2mZ9wT4") > PathTemplater.ShannonEntropy("installer"));
    }
}

/// <summary>
/// Merging several machines' observations into one picture.
/// </summary>
public sealed class ArtifactMergerTests
{
    private static Observation Change(string target, long seq, EventAction action = EventAction.FileCreate)
        => new()
        {
            Seq = seq,
            Timestamp = DateTimeOffset.UtcNow,
            Category = action.InferCategory(),
            Action = action,
            Target = target,
        };

    [Fact]
    public void SameArtifactWithDifferentRandomSegmentsMergesToOneFinding()
    {
        var merger = new ArtifactMerger();

        MergeReport report = merger.Merge(new Dictionary<string, IReadOnlyList<Observation>>
        {
            ["vm-a"] = new[] { Change(@"%APPDATA%\a8f3c1d0\svc.exe", 1) },
            ["vm-b"] = new[] { Change(@"%APPDATA%\d92b4711\svc.exe", 2) },
        });

        MergedArtifact artifact = Assert.Single(report.Artifacts);
        Assert.Equal(Consistency.Universal, artifact.Consistency);
        Assert.Equal(@"%APPDATA%\{*}\svc.exe", artifact.Template.Pattern);
        Assert.Equal(TemplateEvidence.Observed, artifact.Template.Evidence);
        Assert.Equal(2, artifact.ByOrigin.Count);
    }

    [Fact]
    public void ArtifactSeenOnOneMachineOnlyIsFlaggedUnique()
    {
        var merger = new ArtifactMerger();

        MergeReport report = merger.Merge(new Dictionary<string, IReadOnlyList<Observation>>
        {
            ["vm-a"] = new[]
            {
                Change(@"%PROGRAMFILES%\Example\app.exe", 1),
                Change(@"%APPDATA%\Example\oneoff.dat", 2),
            },
            ["vm-b"] = new[] { Change(@"%PROGRAMFILES%\Example\app.exe", 3) },
        });

        MergedArtifact shared = report.Artifacts.Single(a => a.Template.Pattern.Contains("app.exe"));
        MergedArtifact oneOff = report.Artifacts.Single(a => a.Template.Pattern.Contains("oneoff"));

        Assert.Equal(Consistency.Universal, shared.Consistency);
        Assert.Equal(Consistency.Unique, oneOff.Consistency);
    }

    [Fact]
    public void RepeatedWritesOnOneMachineDoNotFakeAgreement()
    {
        // Counting the same machine twice would make a one-machine observation look
        // corroborated, which is exactly the confidence a removal plan keys on.
        var merger = new ArtifactMerger();

        MergeReport report = merger.Merge(new Dictionary<string, IReadOnlyList<Observation>>
        {
            ["vm-a"] = new[]
            {
                Change(@"%APPDATA%\Example\config.json", 1, EventAction.FileWrite),
                Change(@"%APPDATA%\Example\config.json", 2, EventAction.FileWrite),
                Change(@"%APPDATA%\Example\config.json", 3, EventAction.FileWrite),
            },
            ["vm-b"] = Array.Empty<Observation>(),
        });

        MergedArtifact artifact = Assert.Single(report.Artifacts);
        Assert.Equal(1, artifact.SeenOn);
        Assert.Equal(Consistency.Unique, artifact.Consistency);
    }

    [Fact]
    public void ReadsAreExcludedFromTheComparison()
    {
        var merger = new ArtifactMerger();

        MergeReport report = merger.Merge(new Dictionary<string, IReadOnlyList<Observation>>
        {
            ["vm-a"] = new[] { Change(@"%WINDIR%\System32\kernel32.dll", 1, EventAction.FileRead) },
        });

        Assert.Empty(report.Artifacts);
    }
}

/// <summary>
/// Regressions from comparing two real recordings of a program that randomizes its
/// working directory.
/// </summary>
public sealed class MergerRegressionTests
{
    private static Observation Change(string target, long seq, EventAction action)
        => new()
        {
            Seq = seq,
            Timestamp = DateTimeOffset.UtcNow,
            Category = action.InferCategory(),
            Action = action,
            Target = target,
        };

    [Fact]
    public void CreationOfARandomDirectoryMergesAcrossMachines()
    {
        // The random name is the leaf here, not an intermediate segment. Bucketing on
        // the strict file-name test left these unmerged, so the same directory was
        // reported twice as machine-specific — observed on a live comparison where the
        // two runs chose 243177376889 and 2474163949748.
        var merger = new ArtifactMerger();

        MergeReport report = merger.Merge(new Dictionary<string, IReadOnlyList<Observation>>
        {
            ["vm-a"] = new[] { Change(@"%LOCALAPPDATA%\Demo\243177376889", 1, EventAction.DirectoryCreate) },
            ["vm-b"] = new[] { Change(@"%LOCALAPPDATA%\Demo\2474163949748", 2, EventAction.DirectoryCreate) },
        });

        MergedArtifact artifact = Assert.Single(report.Artifacts);
        Assert.Equal(Consistency.Universal, artifact.Consistency);
        Assert.Equal(@"%LOCALAPPDATA%\Demo\{*}", artifact.Template.Pattern);
    }

    [Fact]
    public void StableSiblingsStayLiteralWhileTheRandomOneTemplates()
    {
        var merger = new ArtifactMerger();

        MergeReport report = merger.Merge(new Dictionary<string, IReadOnlyList<Observation>>
        {
            ["vm-a"] = new[]
            {
                Change(@"%LOCALAPPDATA%\Demo\243177376889\svc.exe", 1, EventAction.FileCreate),
                Change(@"%LOCALAPPDATA%\Demo\settings.json", 2, EventAction.FileCreate),
            },
            ["vm-b"] = new[]
            {
                Change(@"%LOCALAPPDATA%\Demo\2474163949748\svc.exe", 3, EventAction.FileCreate),
                Change(@"%LOCALAPPDATA%\Demo\settings.json", 4, EventAction.FileCreate),
            },
        });

        MergedArtifact svc = report.Artifacts.Single(a => a.Template.Pattern.EndsWith(@"svc.exe", StringComparison.Ordinal));
        MergedArtifact settings = report.Artifacts.Single(a => a.Template.Pattern.EndsWith("settings.json", StringComparison.Ordinal));

        Assert.Equal(@"%LOCALAPPDATA%\Demo\{*}\svc.exe", svc.Template.Pattern);
        Assert.True(svc.Template.HasVariables);
        Assert.False(settings.Template.HasVariables);
        Assert.Equal(Consistency.Universal, settings.Consistency);
    }
}
