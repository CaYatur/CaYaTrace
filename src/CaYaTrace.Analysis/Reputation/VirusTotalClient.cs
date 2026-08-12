using System.Diagnostics;
using System.Net;
using System.Text.Json;

namespace CaYaTrace.Analysis.Reputation;

public enum ReputationVerdict
{
    /// <summary>Never asked, or the service could not be reached.</summary>
    Unknown = 0,

    /// <summary>The service has never seen this file.</summary>
    NotFound = 1,

    /// <summary>Known, and no engine flagged it.</summary>
    Clean = 2,

    /// <summary>A small number of engines flagged it. Often a false positive.</summary>
    Suspicious = 3,

    /// <summary>Widely flagged.</summary>
    Malicious = 4,
}

public sealed record ReputationResult(
    string Sha256,
    ReputationVerdict Verdict,
    int Malicious,
    int Suspicious,
    int Total,
    DateTimeOffset? FirstSeen,
    string? PopularName,
    string? Error)
{
    public static ReputationResult Unavailable(string sha256, string error)
        => new(sha256, ReputationVerdict.Unknown, 0, 0, 0, null, null, error);

    public string Summarize() => Verdict switch
    {
        ReputationVerdict.NotFound => "not known to VirusTotal",
        ReputationVerdict.Clean => $"clean ({Total} engines)",
        ReputationVerdict.Suspicious => $"{Malicious}/{Total} engines flagged it" +
                                        (PopularName is { Length: > 0 } ? $" — {PopularName}" : string.Empty),
        ReputationVerdict.Malicious => $"{Malicious}/{Total} engines flagged it" +
                                        (PopularName is { Length: > 0 } ? $" — {PopularName}" : string.Empty),
        _ => Error ?? "not checked",
    };
}

/// <summary>
/// Looks up file reputation by hash.
/// </summary>
/// <remarks>
/// <para>
/// <b>Hash lookup only. This client cannot upload a file, by construction.</b>
/// </para>
/// <para>
/// That is a deliberate limit rather than an unfinished feature. Submitting a sample to
/// VirusTotal <em>publishes</em> it: the file becomes retrievable by anyone with a paid
/// account, permanently. For the work this tool is built for that is frequently
/// unacceptable — an installer from an internal build, a document a user was tricked
/// into opening, a binary carrying embedded credentials or customer data. An operator
/// who wants to submit a sample can do so deliberately on the website, having decided
/// it is safe to disclose; a monitoring tool should never make that decision on their
/// behalf, and certainly not as a side effect of "analyse this session".
/// </para>
/// <para>
/// A hash lookup discloses far less, but it is not nothing: it tells VirusTotal that
/// someone is interested in this exact file. That is why lookups are opt-in per session
/// and the fact is stated where the key is configured.
/// </para>
/// </remarks>
public sealed class VirusTotalClient : IDisposable
{
    private const string BaseUrl = "https://www.virustotal.com/api/v3/files/";

    /// <summary>
    /// Public API keys allow four requests per minute. Exceeding it earns HTTP 429 and,
    /// repeated, a temporary block — so the limit is enforced client-side rather than
    /// discovered.
    /// </summary>
    private static readonly TimeSpan PublicRateInterval = TimeSpan.FromSeconds(16);

    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly string _apiKey;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, ReputationResult> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Stopwatch _sinceLastRequest = Stopwatch.StartNew();

    public TimeSpan RateInterval { get; init; } = PublicRateInterval;

    public VirusTotalClient(string apiKey, HttpClient? http = null)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("an API key is required", nameof(apiKey));

        _apiKey = apiKey.Trim();
        _ownsClient = http is null;
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>Files already looked up, so a repeated artifact costs no quota.</summary>
    public int CachedCount { get { lock (_cache) return _cache.Count; } }

    public async Task<ReputationResult> LookupAsync(string sha256, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sha256) || sha256.Length != 64)
            return ReputationResult.Unavailable(sha256, "not a SHA-256 digest");

        lock (_cache)
        {
            if (_cache.TryGetValue(sha256, out ReputationResult? cached)) return cached;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Re-check inside the gate: several artifacts sharing a hash would
            // otherwise each spend a request while the first was still in flight.
            lock (_cache)
            {
                if (_cache.TryGetValue(sha256, out ReputationResult? cached)) return cached;
            }

            TimeSpan wait = RateInterval - _sinceLastRequest.Elapsed;
            if (wait > TimeSpan.Zero)
                await Task.Delay(wait, cancellationToken).ConfigureAwait(false);

            ReputationResult result = await FetchAsync(sha256, cancellationToken).ConfigureAwait(false);
            _sinceLastRequest.Restart();

            lock (_cache) _cache[sha256] = result;
            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ReputationResult> FetchAsync(string sha256, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, BaseUrl + sha256);

        // The key goes in a header and is never written to a log, an export, or a
        // session file. It is a credential for the operator's account.
        request.Headers.Add("x-apikey", _apiKey);
        request.Headers.Add("Accept", "application/json");

        try
        {
            using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return new ReputationResult(sha256, ReputationVerdict.NotFound, 0, 0, 0, null, null, null);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return ReputationResult.Unavailable(sha256, "the API key was rejected");

            if ((int)response.StatusCode == 429)
                return ReputationResult.Unavailable(sha256, "rate limit reached; try again shortly");

            if (!response.IsSuccessStatusCode)
                return ReputationResult.Unavailable(sha256, $"service returned {(int)response.StatusCode}");

            string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return Parse(sha256, body);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return ReputationResult.Unavailable(sha256, $"could not reach the service: {ex.Message}");
        }
    }

    internal static ReputationResult Parse(string sha256, string json)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);

            if (!doc.RootElement.TryGetProperty("data", out JsonElement data)
                || !data.TryGetProperty("attributes", out JsonElement attributes))
            {
                return ReputationResult.Unavailable(sha256, "unexpected response shape");
            }

            int malicious = 0, suspicious = 0, harmless = 0, undetected = 0;
            if (attributes.TryGetProperty("last_analysis_stats", out JsonElement stats))
            {
                malicious = ReadInt(stats, "malicious");
                suspicious = ReadInt(stats, "suspicious");
                harmless = ReadInt(stats, "harmless");
                undetected = ReadInt(stats, "undetected");
            }

            int total = malicious + suspicious + harmless + undetected;

            DateTimeOffset? firstSeen = null;
            if (attributes.TryGetProperty("first_submission_date", out JsonElement first)
                && first.TryGetInt64(out long epoch))
            {
                firstSeen = DateTimeOffset.FromUnixTimeSeconds(epoch);
            }

            string? popularName = null;
            if (attributes.TryGetProperty("popular_threat_classification", out JsonElement classification)
                && classification.TryGetProperty("suggested_threat_label", out JsonElement label))
            {
                popularName = label.GetString();
            }

            // Thresholds, not a percentage. One or two detections on a widely scanned
            // file is usually a false positive, and presenting that as "malicious"
            // trains an analyst to ignore the field entirely.
            ReputationVerdict verdict = malicious switch
            {
                0 when total > 0 => ReputationVerdict.Clean,
                0 => ReputationVerdict.NotFound,
                <= 3 => ReputationVerdict.Suspicious,
                _ => ReputationVerdict.Malicious,
            };

            return new ReputationResult(sha256, verdict, malicious, suspicious, total, firstSeen, popularName, null);
        }
        catch (JsonException ex)
        {
            return ReputationResult.Unavailable(sha256, $"could not read the response: {ex.Message}");
        }
    }

    private static int ReadInt(JsonElement element, string name)
        => element.TryGetProperty(name, out JsonElement value) && value.TryGetInt32(out int result) ? result : 0;

    /// <summary>
    /// Reads the API key from the environment.
    /// </summary>
    /// <remarks>
    /// Environment variable rather than a config file in the session directory, so the
    /// key cannot be swept up by an export or committed alongside evidence.
    /// </remarks>
    public static string? ReadKeyFromEnvironment()
    {
        string? key = Environment.GetEnvironmentVariable("CAYATRACE_VT_API_KEY")
                      ?? Environment.GetEnvironmentVariable("VT_API_KEY");
        return string.IsNullOrWhiteSpace(key) ? null : key.Trim();
    }

    public void Dispose()
    {
        _gate.Dispose();
        if (_ownsClient) _http.Dispose();
    }
}
