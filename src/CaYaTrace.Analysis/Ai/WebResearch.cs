using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace CaYaTrace.Analysis.Ai;

/// <summary>One thing found on the web about a name from the session.</summary>
public sealed record WebFinding(string Title, string Url, string Snippet)
{
    public override string ToString() => $"{Title} — {Snippet} [{Url}]";
}

/// <summary>
/// Looks up a name from a session on the web, when the operator has asked it to.
/// </summary>
/// <remarks>
/// <para>
/// An unfamiliar service called <c>DelayedSvc</c> running <c>svcworker.exe</c> is either a
/// product nobody in the room has heard of or something pretending to be one, and the
/// session cannot tell the difference — that answer is not on the machine. This is how the
/// question gets asked.
/// </para>
/// <para>
/// <b>Off unless switched on, and it says so.</b> Searching publishes what is searched for.
/// A file name from a targeted intrusion is itself sensitive: looking it up tells a search
/// engine, and anyone with access to that query stream, that somebody is investigating it.
/// That is the operator's call to make, not a default to inherit, and it follows the same
/// shape as the VirusTotal option — which looks up hashes and never uploads a file,
/// because submitting a sample publishes it permanently.
/// </para>
/// <para>
/// Names, hashes and domains only. File <em>contents</em> are never sent anywhere by this
/// class and there is no code path here that could: it takes a string that came from a
/// session's index, not from a file's bytes.
/// </para>
/// </remarks>
public sealed class WebResearch
{
    private readonly HttpClient _http;

    /// <summary>
    /// Kept short. This runs while the operator is waiting on a chat reply, and a lookup
    /// that takes longer than the answer is worth is one they will stop using.
    /// </summary>
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(20);

    public WebResearch(HttpClient? http = null)
    {
        _http = http ?? new HttpClient(new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        });

        _http.Timeout = Budget;

        // Identifies itself rather than impersonating a browser. A tool that lies about
        // what it is in its own user agent has picked a side, and it is not the operator's.
        if (!_http.DefaultRequestHeaders.UserAgent.TryParseAdd("CaYaTrace/0.4 (+https://github.com/CaYatur/CaYaTrace)"))
            _http.DefaultRequestHeaders.Add("User-Agent", "CaYaTrace/0.4");
    }

    /// <summary>Whether the operator has turned this on for this session.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// The last queries that left this machine.
    /// </summary>
    /// <remarks>
    /// Recorded so the operator can see exactly what was published on their behalf. A
    /// feature that sends data somewhere should be able to show what it sent.
    /// </remarks>
    public IReadOnlyList<string> Published => _published;

    private readonly List<string> _published = new();

    /// <summary>
    /// Searches for a name, returning what the results say about it.
    /// </summary>
    /// <remarks>
    /// Uses DuckDuckGo's no-JavaScript endpoint, which needs no account and no key. A
    /// feature that required the operator to obtain an API key before it could tell them
    /// what a file is would not get used.
    /// </remarks>
    public async Task<IReadOnlyList<WebFinding>> SearchAsync(string term, CancellationToken cancellationToken = default)
    {
        if (!Enabled) throw new InvalidOperationException("web research is switched off for this session");
        if (string.IsNullOrWhiteSpace(term)) return Array.Empty<WebFinding>();

        string query = term.Trim();
        _published.Add(query);

        string url = "https://html.duckduckgo.com/html/?q=" + Uri.EscapeDataString(query);

        string html;
        try
        {
            html = await _http.GetStringAsync(url, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return Array.Empty<WebFinding>();
        }

        return ParseResults(html);
    }

    /// <summary>
    /// Fetches one page and returns its readable text.
    /// </summary>
    /// <remarks>
    /// Only http and https, and never a private address. Without that, a name from a
    /// recorded session — which is untrusted input, chosen by whatever was being recorded —
    /// could point this at the operator's own network and make the tool fetch from it.
    /// </remarks>
    public async Task<string> FetchAsync(string url, CancellationToken cancellationToken = default)
    {
        if (!Enabled) throw new InvalidOperationException("web research is switched off for this session");

        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? target)) return string.Empty;
        if (target.Scheme is not ("http" or "https")) return string.Empty;
        if (IsPrivate(target.Host)) return string.Empty;

        _published.Add(target.ToString());

        try
        {
            string html = await _http.GetStringAsync(target, cancellationToken).ConfigureAwait(false);
            return Readable(html);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return string.Empty;
        }
    }

    private static bool IsPrivate(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return true;
        if (!IPAddress.TryParse(host, out IPAddress? address)) return false;

        if (IPAddress.IsLoopback(address)) return true;

        byte[] octets = address.GetAddressBytes();
        if (octets.Length != 4) return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal;

        return octets[0] switch
        {
            10 => true,
            127 => true,
            169 when octets[1] == 254 => true,
            172 when octets[1] is >= 16 and <= 31 => true,
            192 when octets[1] == 168 => true,
            _ => false,
        };
    }

    private static readonly Regex ResultPattern = new(
        """<a[^>]*class="result__a"[^>]*href="(?<url>[^"]+)"[^>]*>(?<title>.*?)</a>""",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex SnippetPattern = new(
        """<a[^>]*class="result__snippet"[^>]*>(?<text>.*?)</a>""",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex TagPattern = new("<[^>]+>", RegexOptions.Compiled);

    private static List<WebFinding> ParseResults(string html)
    {
        var titles = ResultPattern.Matches(html);
        var snippets = SnippetPattern.Matches(html);

        var findings = new List<WebFinding>();
        for (int i = 0; i < titles.Count && findings.Count < 5; i++)
        {
            string url = WebUtility.HtmlDecode(titles[i].Groups["url"].Value);

            // The endpoint wraps results in its own redirect; the real address is in it.
            Match direct = Regex.Match(url, @"uddg=([^&]+)");
            if (direct.Success) url = Uri.UnescapeDataString(direct.Groups[1].Value);

            string title = Clean(titles[i].Groups["title"].Value);
            string snippet = i < snippets.Count ? Clean(snippets[i].Groups["text"].Value) : string.Empty;

            if (title.Length == 0) continue;
            findings.Add(new WebFinding(title, url, Shorten(snippet, 300)));
        }

        return findings;
    }

    private static string Readable(string html)
    {
        string stripped = Regex.Replace(html, "<(script|style)[^>]*>.*?</\\1>", " ",
            RegexOptions.IgnoreCase | RegexOptions.Singleline);

        return Shorten(Clean(stripped), 4000);
    }

    private static string Clean(string html)
    {
        string text = WebUtility.HtmlDecode(TagPattern.Replace(html, " "));
        return Regex.Replace(text, @"\s+", " ").Trim();
    }

    private static string Shorten(string text, int max) =>
        text.Length <= max ? text : text[..max] + "…";

    /// <summary>Renders findings for a model prompt, marked as coming from outside.</summary>
    /// <remarks>
    /// Labelled explicitly, because everything else the model is given was measured on this
    /// machine and this was not. A search result is somebody's claim about a name, and an
    /// answer built on one should not read like an answer built on evidence.
    /// </remarks>
    public static string Describe(IReadOnlyList<WebFinding> findings)
    {
        if (findings.Count == 0) return string.Empty;

        var text = new StringBuilder();
        text.AppendLine("From a web search (NOT measured on this machine — treat as unverified):");
        foreach (WebFinding finding in findings) text.Append("- ").AppendLine(finding.ToString());

        return text.ToString();
    }
}
