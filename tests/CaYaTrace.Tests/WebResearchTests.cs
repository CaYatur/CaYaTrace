using CaYaTrace.Analysis.Ai;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// The web lookup, including one call that actually leaves the machine.
/// </summary>
/// <remarks>
/// The live case is skipped unless <c>CAYATRACE_LIVE_WEB</c> is set, because a test that
/// reaches the internet has no business running by default. It exists because scraping a
/// search page keys on class names somebody else controls: if they move, the feature
/// returns an empty list and reports nothing wrong, which is precisely the failure this
/// release was spent eliminating from HTTPS interception.
/// </remarks>
public sealed class WebResearchTests
{
    private readonly ITestOutputHelper _out;

    public WebResearchTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public async Task NothingLeavesTheMachineUntilItIsSwitchedOn()
    {
        var research = new WebResearch();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => research.SearchAsync("svcworker.exe"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => research.FetchAsync("https://example.com/"));

        Assert.Empty(research.Published);
    }

    /// <summary>
    /// A name out of a recorded session is untrusted input.
    /// </summary>
    /// <remarks>
    /// Whatever was being recorded chose it. Without this, a session could name a host on
    /// the operator's own network and have the tool fetch from it on their behalf.
    /// </remarks>
    [Theory]
    [InlineData("http://127.0.0.1:8080/admin")]
    [InlineData("http://localhost/status")]
    [InlineData("http://192.168.1.1/")]
    [InlineData("http://10.0.0.5/")]
    [InlineData("http://172.16.4.4/")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("file:///C:/Windows/System32/config/SAM")]
    [InlineData("ftp://example.com/x")]
    [InlineData("not a url at all")]
    public async Task PrivateAndNonWebAddressesAreNeverFetched(string url)
    {
        var research = new WebResearch { Enabled = true };

        Assert.Equal(string.Empty, await research.FetchAsync(url));

        // Refused before the request, so nothing about it was published either.
        Assert.Empty(research.Published);
    }

    [Fact]
    public async Task AnEmptyTermIsNotASearch()
    {
        var research = new WebResearch { Enabled = true };

        Assert.Empty(await research.SearchAsync("   "));
        Assert.Empty(research.Published);
    }

    /// <summary>Findings are labelled as coming from outside, or they are not shown.</summary>
    [Fact]
    public void FindingsAreMarkedAsUnverified()
    {
        string described = WebResearch.Describe(new[]
        {
            new WebFinding("svcworker.exe", "https://example.com/a", "some claim"),
        });

        Assert.Contains("NOT measured on this machine", described, StringComparison.Ordinal);
        Assert.Contains("unverified", described, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NoFindingsProduceNoSection()
    {
        Assert.Equal(string.Empty, WebResearch.Describe(Array.Empty<WebFinding>()));
    }

    /// <summary>
    /// The one test that proves the scraping still works.
    /// </summary>
    /// <remarks>
    /// Searching for a term with an unmistakable answer, so a result that parses but is
    /// wrong is as visible as one that does not parse at all.
    /// </remarks>
    [Fact]
    public async Task ARealSearchReturnsRealResults()
    {
        if (Environment.GetEnvironmentVariable("CAYATRACE_LIVE_WEB") is not { Length: > 0 })
        {
            _out.WriteLine("set CAYATRACE_LIVE_WEB=1 to run this");
            return;
        }

        var research = new WebResearch { Enabled = true };

        IReadOnlyList<WebFinding> findings = await research.SearchAsync("svchost.exe what is it");

        foreach (WebFinding finding in findings)
            _out.WriteLine($"{finding.Title}\n    {finding.Snippet}\n    {finding.Url}\n");

        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.NotEmpty(f.Title));

        // A result whose URL is still the search engine's redirect wrapper means the
        // unwrapping stopped matching, which is a silent failure rather than a loud one.
        Assert.All(findings, f => Assert.StartsWith("http", f.Url, StringComparison.Ordinal));
        Assert.DoesNotContain(findings, f => f.Url.Contains("duckduckgo.com/l/", StringComparison.Ordinal));

        Assert.Single(research.Published);
    }
}
