using CaYaTrace.Core.Model;
using CaYaTrace.Export;
using CaYaTrace.Remediation;
using Xunit;

namespace CaYaTrace.Tests;

public sealed class CsvExporterTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("has,comma", "\"has,comma\"")]
    [InlineData("has\"quote", "\"has\"\"quote\"")]
    [InlineData("has\nnewline", "\"has\nnewline\"")]
    public void ValuesAreQuotedOnlyWhenTheyNeedToBe(string input, string expected)
        => Assert.Equal(expected, CsvExporter.Cell(input));

    /// <summary>
    /// The formula guard is a security control, not formatting.
    /// </summary>
    /// <remarks>
    /// Every target in a session is a string the observed program chose. A program that
    /// creates a file named <c>=cmd|'/c calc'!A1</c> has written a DDE payload into the
    /// report, and Excel offers to run it when the analyst opens the export. A forensics
    /// tool that turns evidence into execution on the analyst's own machine has failed
    /// worse than one that lost the evidence.
    /// </remarks>
    [Theory]
    [InlineData("=cmd|'/c calc'!A1")]
    [InlineData("+1+1")]
    [InlineData("-2+3")]
    [InlineData("@SUM(A1)")]
    public void SpreadsheetFormulasAreDefused(string payload)
    {
        string cell = CsvExporter.Cell(payload);
        Assert.StartsWith("'", cell.TrimStart('"'), StringComparison.Ordinal);
        Assert.DoesNotContain("\n", cell, StringComparison.Ordinal);
    }

    [Fact]
    public void EmptyValuesStayEmpty()
    {
        Assert.Equal(string.Empty, CsvExporter.Cell(null));
        Assert.Equal(string.Empty, CsvExporter.Cell(string.Empty));
    }

    [Fact]
    public void TheEncodingCarriesAByteOrderMark()
    {
        // Without it Excel reads the file as the system code page, and every path
        // containing ş, ü, or any non-ASCII character is mangled on the machine most
        // likely to open it.
        Assert.NotEmpty(CsvExporter.FileEncoding.GetPreamble());
    }
}

public sealed class ExportRequestTests
{
    [Fact]
    public void MinimalDropsTheTreeAndFullKeepsEverything()
    {
        Assert.False(new ExportRequest { Scope = ExportScope.Minimal }.IncludeTree);
        Assert.True(new ExportRequest { Scope = ExportScope.Standard }.IncludeTree);

        Assert.False(new ExportRequest { Scope = ExportScope.Standard }.IncludeReads);
        Assert.True(new ExportRequest { Scope = ExportScope.Full }.IncludeReads);
        Assert.True(new ExportRequest { Scope = ExportScope.Full }.IncludeOutOfScope);
    }

    [Fact]
    public void LimitsGrowWithScopeRatherThanShrinking()
    {
        int minimal = new ExportRequest { Scope = ExportScope.Minimal }.FindingLimit;
        int standard = new ExportRequest { Scope = ExportScope.Standard }.FindingLimit;
        int full = new ExportRequest { Scope = ExportScope.Full }.FindingLimit;

        Assert.True(minimal < standard && standard < full);
    }

    [Fact]
    public void AnEmptyCategorySelectionMeansEverything()
    {
        var all = new ExportRequest();
        Assert.True(all.Allows(EventCategory.File));
        Assert.True(all.Allows(EventCategory.Http));

        var some = new ExportRequest { Categories = new[] { EventCategory.Registry } };
        Assert.True(some.Allows(EventCategory.Registry));
        Assert.False(some.Allows(EventCategory.File));
    }

    [Fact]
    public void EachFormatSuggestsItsOwnExtension()
    {
        Assert.Equal(".html", new ExportRequest { Format = ExportFormat.Html }.DefaultExtension);
        Assert.Equal(".csv", new ExportRequest { Format = ExportFormat.Csv }.DefaultExtension);
        Assert.Equal(".ctpkg", new ExportRequest { Format = ExportFormat.Package }.DefaultExtension);
    }
}

/// <summary>
/// The plan the workbench shows has to be the plan the runner will carry out.
/// </summary>
/// <remarks>
/// Both go through <see cref="SafetyPolicy.Evaluate(RemovalItem)"/>. If the UI used a
/// different rule, an operator could approve a list and get a different one.
/// </remarks>
public sealed class SafetyPolicyDispatchTests
{
    private static readonly SafetyPolicy Policy =
        new(CaYaTrace.Core.Naming.PathNormalizer.CreateForCurrentMachine());

    private static RemovalItem Item(RemovalKind kind, string target, string? valueName = null)
        => new() { Kind = kind, Target = target, ValueName = valueName, Rationale = "test" };

    [Fact]
    public void WindowsOwnedPathsAreForbiddenWhicheverKindAsks()
    {
        Assert.Equal(SafetyVerdict.Forbidden,
            Policy.Evaluate(Item(RemovalKind.File, @"%WINDIR%\System32\kernel32.dll")).Verdict);

        Assert.Equal(SafetyVerdict.Forbidden,
            Policy.Evaluate(Item(RemovalKind.Directory, @"%WINDIR%\System32")).Verdict);
    }

    [Fact]
    public void AnOrdinaryInstallPathIsAllowed()
        => Assert.Equal(SafetyVerdict.Allowed,
            Policy.Evaluate(Item(RemovalKind.File, @"%LOCALAPPDATA%\Example\app.exe")).Verdict);

    [Fact]
    public void AnAutorunValueIsEvaluatedAsTheRegistryValueItIs()
    {
        SafetyDecision decision = Policy.Evaluate(Item(
            RemovalKind.AutorunEntry,
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "ExampleUpdater"));

        Assert.NotEqual(SafetyVerdict.Forbidden, decision.Verdict);
    }

    [Fact]
    public void WindowsOwnScheduledTasksAreNeverRemoved()
        => Assert.Equal(SafetyVerdict.Forbidden,
            Policy.Evaluate(Item(RemovalKind.ScheduledTask, @"\Microsoft\Windows\Defrag\ScheduledDefrag")).Verdict);

    [Fact]
    public void ADoubleColonTargetIsSplitIntoKeyAndValue()
    {
        // The planner writes registry values both ways; both have to reach the same
        // verdict or the plan disagrees with itself.
        SafetyDecision joined = Policy.Evaluate(Item(
            RemovalKind.RegistryValue, @"HKCU\Software\Example::Setting"));
        SafetyDecision split = Policy.Evaluate(Item(
            RemovalKind.RegistryValue, @"HKCU\Software\Example", "Setting"));

        Assert.Equal(split.Verdict, joined.Verdict);
    }
}
