using CaYaTrace.Analysis.Reputation;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Reputation parsing, verified without touching the network.
/// </summary>
public sealed class ReputationTests
{
    private const string Sha = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    /// <summary>
    /// Builds a response body by concatenation rather than interpolation. The payload
    /// is dense with braces, and a raw string literal here spends more attention on
    /// escaping than on the test.
    /// </summary>
    private static string Response(int malicious, int suspicious, int harmless, int undetected,
        string? label = null)
    {
        string classification = label is null
            ? string.Empty
            : ",\"popular_threat_classification\":{\"suggested_threat_label\":\"" + label + "\"}";

        return "{\"data\":{\"attributes\":{"
             + "\"last_analysis_stats\":{"
             + "\"malicious\":" + malicious + ","
             + "\"suspicious\":" + suspicious + ","
             + "\"harmless\":" + harmless + ","
             + "\"undetected\":" + undetected + "},"
             + "\"first_submission_date\":1700000000"
             + classification
             + "}}}";
    }

    [Fact]
    public void NoDetectionsAmongManyEnginesIsClean()
    {
        ReputationResult result = VirusTotalClient.Parse(Sha, Response(0, 0, 60, 10));

        Assert.Equal(ReputationVerdict.Clean, result.Verdict);
        Assert.Equal(70, result.Total);
    }

    [Fact]
    public void ASingleDetectionIsSuspiciousNotMalicious()
    {
        // One or two hits on a widely scanned file is usually a false positive.
        // Calling that "malicious" trains an analyst to ignore the field entirely.
        ReputationResult result = VirusTotalClient.Parse(Sha, Response(1, 0, 60, 9));

        Assert.Equal(ReputationVerdict.Suspicious, result.Verdict);
    }

    [Fact]
    public void WidespreadDetectionIsMalicious()
    {
        ReputationResult result = VirusTotalClient.Parse(Sha, Response(48, 3, 5, 4, "trojan.agent/generic"));

        Assert.Equal(ReputationVerdict.Malicious, result.Verdict);
        Assert.Equal(48, result.Malicious);
        Assert.Contains("trojan", result.Summarize(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FirstSubmissionDateIsSurfaced()
    {
        // A file first seen minutes ago behaves very differently in an investigation
        // from one the world has known for years.
        ReputationResult result = VirusTotalClient.Parse(Sha, Response(0, 0, 60, 10));

        Assert.NotNull(result.FirstSeen);
        Assert.Equal(2023, result.FirstSeen!.Value.Year);
    }

    [Fact]
    public void AMalformedResponseDegradesInsteadOfThrowing()
    {
        ReputationResult result = VirusTotalClient.Parse(Sha, "not json at all");

        Assert.Equal(ReputationVerdict.Unknown, result.Verdict);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void AResponseWithoutAttributesIsReportedAsUnknown()
    {
        ReputationResult result = VirusTotalClient.Parse(Sha, """{"data":{}}""");

        Assert.Equal(ReputationVerdict.Unknown, result.Verdict);
    }

    [Fact]
    public void AnEmptyKeyIsRejectedRatherThanSentAsAnAnonymousRequest()
    {
        Assert.Throws<ArgumentException>(static () => new VirusTotalClient("   "));
    }

    [Fact]
    public void NonHashInputNeverReachesTheNetwork()
    {
        // A short or malformed digest would be a wasted request against a rate-limited
        // quota, and would leak the malformed value to the service.
        using var client = new VirusTotalClient("dummy-key-not-used");

        ReputationResult result = client.LookupAsync("too-short").GetAwaiter().GetResult();

        Assert.Equal(ReputationVerdict.Unknown, result.Verdict);
        Assert.Contains("SHA-256", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MissingFilesAreReportedRatherThanSilentlySkipped()
    {
        Assert.Null(ReputationEnricher.ComputeSha256(
            Path.Combine(Path.GetTempPath(), "cayatrace-does-not-exist-" + Guid.NewGuid().ToString("n"))));
    }
}
