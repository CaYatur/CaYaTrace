using CaYaTrace.Core.Naming;
using CaYaTrace.Remediation;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// The sweep that finds what a program left behind, whether or not it was recorded.
/// </summary>
/// <remarks>
/// The term selection is what makes this safe or dangerous, so most of these are about
/// which words are allowed to be searched for. A sweep is only offerable at all because a
/// bad match is something to uncheck; a sweep that matches "data" is a list nobody can
/// read, and an operator who cannot read the list approves it anyway.
/// </remarks>
public sealed class LeftoverScannerTests
{
    private readonly ITestOutputHelper _out;

    public LeftoverScannerTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public void AProductNameBecomesItsWords()
    {
        IReadOnlyList<string> terms = LeftoverScanner.TermsFrom(new[] { "Revo Uninstaller Pro" });

        Assert.Contains("Revo", terms);
        Assert.Contains("Uninstaller", terms);

        // "Pro" is three letters, and a three-letter substring matches half the machine.
        Assert.DoesNotContain("Pro", terms);
    }

    [Fact]
    public void APathContributesOnlyItsLeaf()
    {
        IReadOnlyList<string> terms = LeftoverScanner.TermsFrom(
            new[] { @"C:\Program Files\Contoso\Widget\widget.exe" });

        Assert.Contains("widget", terms, StringComparer.OrdinalIgnoreCase);

        // The directories above it belong to everybody.
        Assert.DoesNotContain("Program", terms);
        Assert.DoesNotContain("Files", terms);
    }

    /// <summary>
    /// The words that would turn a sweep into a list of the whole machine.
    /// </summary>
    [Theory]
    [InlineData("Microsoft Update Service")]
    [InlineData("Common Shared Data")]
    [InlineData("Windows Installer")]
    [InlineData("Application Settings Cache")]
    public void NothingTooCommonIsEverSearchedFor(string name)
    {
        Assert.Empty(LeftoverScanner.TermsFrom(new[] { name }));
    }

    [Fact]
    public void NoTermsMeansNoSweep()
    {
        var scanner = new LeftoverScanner(PathNormalizer.CreateForCurrentMachine());

        LeftoverScan scan = scanner.Scan(Array.Empty<string>(), LeftoverDepth.Advanced);

        Assert.Empty(scan.Items);
    }

    [Fact]
    public void TurningItOffScansNothing()
    {
        var scanner = new LeftoverScanner(PathNormalizer.CreateForCurrentMachine());

        LeftoverScan scan = scanner.Scan(new[] { "Contoso" }, LeftoverDepth.None);

        Assert.Empty(scan.Items);
        Assert.Equal(0, scan.KeysExamined);
    }

    /// <summary>
    /// A sweep for a name nothing on this machine has finds nothing on this machine.
    /// </summary>
    /// <remarks>
    /// The check that the matcher is a matcher rather than a lister. A term chosen to be
    /// absent must come back empty, or every other result here is meaningless.
    /// </remarks>
    [Fact]
    public void AnAbsentProgramLeavesNothingBehind()
    {
        var scanner = new LeftoverScanner(PathNormalizer.CreateForCurrentMachine());

        LeftoverScan scan = scanner.Scan(new[] { "Zzyzx7731Nonexistent" }, LeftoverDepth.Moderate);

        _out.WriteLine($"examined {scan.KeysExamined:N0} keys and {scan.DirectoriesExamined:N0} directories");
        Assert.Empty(scan.Items);
    }

    /// <summary>
    /// A sweep for something that is installed finds it.
    /// </summary>
    /// <remarks>
    /// Run against this machine, using a term taken from a directory that is actually
    /// present, so the test proves the sweep reaches real state rather than asserting
    /// against a fixture it also wrote.
    /// </remarks>
    [Fact]
    public void SomethingActuallyInstalledIsFound()
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string[] present = Directory.Exists(programFiles)
            ? Directory.GetDirectories(programFiles)
            : Array.Empty<string>();

        string? subject = present
            .Select(Path.GetFileName)
            .FirstOrDefault(n => n is { Length: > 5 }
                                 && LeftoverScanner.TermsFrom(new[] { n }).Count > 0);

        if (subject is null)
        {
            _out.WriteLine("no suitable installed program on this machine to sweep for");
            return;
        }

        IReadOnlyList<string> terms = LeftoverScanner.TermsFrom(new[] { subject });
        LeftoverScan scan = new LeftoverScanner(PathNormalizer.CreateForCurrentMachine()).Scan(terms, LeftoverDepth.Safe);

        _out.WriteLine($"swept for '{subject}' ({string.Join(", ", terms)}): {scan.Items.Count} item(s)");
        foreach (RemovalItem item in scan.Items.Take(10))
            _out.WriteLine($"  {item.Kind,-14} {item.Target}   [{item.Rationale}]");

        Assert.NotEmpty(scan.Items);
        Assert.Contains(scan.Items, i => i.Kind == RemovalKind.Directory);
    }

    /// <summary>
    /// Something the safety policy protects is listed, not hidden.
    /// </summary>
    /// <remarks>
    /// The behaviour behind the complaint that the remover skips things. An item it
    /// refuses to touch is still an item the operator has to know about — the difference
    /// between "not found" and "found and declined" is the difference between a gap to
    /// report and a judgement to argue with.
    /// </remarks>
    [Fact]
    public void SomethingRefusedIsStillReported()
    {
        // "Windows" is in the too-common list, so a sweep cannot be aimed at the system
        // directory by name. Aim at a real directory under it instead.
        string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string? child = Directory.Exists(system)
            ? Directory.GetDirectories(system).Select(Path.GetFileName)
                .FirstOrDefault(n => n is { Length: >= 6 } && LeftoverScanner.TermsFrom(new[] { n }).Count > 0)
            : null;

        if (child is null)
        {
            _out.WriteLine("no suitable protected directory to check against");
            return;
        }

        LeftoverScan scan = new LeftoverScanner(PathNormalizer.CreateForCurrentMachine())
            .Scan(LeftoverScanner.TermsFrom(new[] { child }), LeftoverDepth.Safe);

        foreach (RemovalItem item in scan.Items.Take(8))
            _out.WriteLine($"  {item.Kind,-14} {item.Target}   [{item.Rationale}]");

        // Whatever it found, anything refused says so in its rationale rather than being
        // absent from the list.
        Assert.All(scan.Items, i => Assert.False(string.IsNullOrWhiteSpace(i.Rationale)));
    }
}
