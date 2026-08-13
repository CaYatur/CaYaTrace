using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Checks the shipped string catalogue for the failures that only show up in front of
/// a user.
/// </summary>
/// <remarks>
/// <para>
/// Read from the source file rather than through the app's loader, so this runs without
/// referencing the executable and fails on the thing that actually breaks: someone adds
/// an English string and forgets the Turkish one, or renames a key in one language.
/// </para>
/// <para>
/// The placeholder check matters more than it looks. Turkish word order routinely
/// differs from English, so <c>{0}</c> and <c>{1}</c> legitimately appear in a different order in
/// the two languages — but a translation that <em>drops</em> one produces a sentence with a
/// number missing from it, which reads as a bug in the tool rather than in the string.
/// </para>
/// </remarks>
public sealed class StringCatalogueTests
{
    private static readonly Lazy<JsonDocument> Catalogue = new(Load);

    private static JsonDocument Load()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CaYaTrace.sln")))
            directory = directory.Parent;

        Assert.NotNull(directory);

        string path = Path.Combine(directory!.FullName, "src", "CaYaTrace.App", "Assets", "strings.json");
        Assert.True(File.Exists(path), $"string catalogue not found at {path}");

        return JsonDocument.Parse(File.ReadAllText(path));
    }

    private static Dictionary<string, string> Table(string language)
    {
        JsonElement root = Catalogue.Value.RootElement;
        Assert.True(root.TryGetProperty(language, out JsonElement table), $"no '{language}' section");

        return table.EnumerateObject()
            .Where(static p => p.Value.ValueKind == JsonValueKind.String)
            .ToDictionary(static p => p.Name, static p => p.Value.GetString() ?? string.Empty);
    }

    /// <summary>The shipped page, read from source for the same reason the catalogue is.</summary>
    private static string Markup()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CaYaTrace.sln")))
            directory = directory.Parent;

        Assert.NotNull(directory);

        string path = Path.Combine(directory!.FullName, "src", "CaYaTrace.App", "Assets", "workbench.html");
        Assert.True(File.Exists(path), $"workbench markup not found at {path}");

        return File.ReadAllText(path);
    }

    private static IReadOnlyList<string> Languages() =>
        Catalogue.Value.RootElement.EnumerateObject()
            .Where(static p => !p.Name.StartsWith('_'))
            .Select(static p => p.Name)
            .ToList();

    [Fact]
    public void EnglishIsPresentAndIsTheLargestTable()
    {
        Dictionary<string, string> english = Table("en");
        Assert.NotEmpty(english);

        foreach (string language in Languages().Where(static l => l != "en"))
            Assert.True(Table(language).Count <= english.Count,
                $"'{language}' has keys English does not — English is the fallback for every key");
    }

    [Fact]
    public void EveryLanguageCoversEveryEnglishKey()
    {
        Dictionary<string, string> english = Table("en");

        foreach (string language in Languages().Where(static l => l != "en"))
        {
            Dictionary<string, string> other = Table(language);
            List<string> missing = english.Keys.Where(k => !other.ContainsKey(k)).OrderBy(static k => k).ToList();

            Assert.True(missing.Count == 0,
                $"'{language}' is missing {missing.Count} key(s): {string.Join(", ", missing.Take(12))}");
        }
    }

    [Fact]
    public void NoLanguageInventsKeysOfItsOwn()
    {
        Dictionary<string, string> english = Table("en");

        foreach (string language in Languages().Where(static l => l != "en"))
        {
            List<string> extra = Table(language).Keys
                .Where(k => !english.ContainsKey(k)).OrderBy(static k => k).ToList();

            Assert.True(extra.Count == 0,
                $"'{language}' has {extra.Count} key(s) with no English fallback: {string.Join(", ", extra.Take(12))}");
        }
    }

    [Fact]
    public void PlaceholdersSurviveTranslation()
    {
        Dictionary<string, string> english = Table("en");

        foreach (string language in Languages().Where(static l => l != "en"))
        {
            Dictionary<string, string> other = Table(language);

            foreach ((string key, string source) in english)
            {
                if (!other.TryGetValue(key, out string? translated)) continue;

                HashSet<string> expected = Placeholders(source);
                HashSet<string> actual = Placeholders(translated);

                // Order is free — Turkish may legitimately put {1} before {0} — but a
                // dropped placeholder leaves a sentence with a hole in it.
                Assert.True(expected.SetEquals(actual),
                    $"{language}/{key}: expected {{{string.Join(",", expected.Order())}}}, " +
                    $"got {{{string.Join(",", actual.Order())}}}");
            }
        }
    }

    /// <summary>
    /// Every key the page asks for exists.
    /// </summary>
    /// <remarks>
    /// A missing key does not throw and does not log — it renders as the key itself, so
    /// the failure looks like a design decision. "persistence.title" as a heading is the
    /// sort of thing that ships because everyone who saw it assumed someone else knew
    /// what it meant.
    /// </remarks>
    [Fact]
    public void EveryKeyThePageAsksForExists()
    {
        Dictionary<string, string> english = Table("en");

        var missing = new List<string>();
        foreach (Match match in Regex.Matches(Markup(), @"data-i18n(?:-placeholder)?=""([^""]+)"""))
        {
            string key = match.Groups[1].Value;
            if (key.Length > 0 && !english.ContainsKey(key)) missing.Add(key);
        }

        Assert.True(missing.Count == 0,
            $"the page asks for {missing.Count} key(s) the catalogue does not have: "
            + string.Join(", ", missing.Distinct().Order()));
    }

    /// <summary>
    /// Every key the script looks up exists too.
    /// </summary>
    /// <remarks>
    /// Deliberately limited to the literal <c>t('…')</c> calls. Keys built by
    /// concatenation — a risk level, a persistence kind, an agent state — cannot be
    /// checked this way, and pretending otherwise by matching loosely would produce a
    /// test that fails on strings that are fine.
    /// </remarks>
    [Fact]
    public void EveryLiteralLookupInTheScriptExists()
    {
        Dictionary<string, string> english = Table("en");

        var missing = new List<string>();
        foreach (Match match in Regex.Matches(Markup(), @"\bt\('([a-z][a-z0-9_.]*)'\s*[,)]"))
        {
            string key = match.Groups[1].Value;

            // A key with no dot is a variable name that happened to match, not a key.
            if (!key.Contains('.', StringComparison.Ordinal)) continue;
            if (!english.ContainsKey(key)) missing.Add(key);
        }

        Assert.True(missing.Count == 0,
            $"the script looks up {missing.Distinct().Count()} key(s) the catalogue does not have: "
            + string.Join(", ", missing.Distinct().Order()));
    }

    /// <summary>
    /// Every key the launch-time sweep can report under exists.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The other two coverage tests read the page, so keys looked up from C# are checked by
    /// nothing at all. These particular ones are the worst possible candidates for that
    /// gap: they are the messages shown when the machine cannot reach the network, or when
    /// an interception root is still trusted, and they surface exactly once — on the launch
    /// after the run that went wrong. A missing key would render as
    /// <c>proxy.sweep.winhttp_needs_admin</c> in a dialog box, on the one occasion the text
    /// had to be readable.
    /// </para>
    /// <para>
    /// Every combination is enumerated rather than a representative one, because the flags
    /// are independent and a key is only reachable through its own.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryKeyTheProxySweepCanReportExists()
    {
        Dictionary<string, string> english = Table("en");

        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (bool wininet in new[] { false, true })
        foreach (bool winhttp in new[] { false, true })
        foreach (bool needsAdmin in new[] { false, true })
        foreach (int stale in new[] { 0, 2 })
        foreach (int removed in new[] { 0, 1, 2 })
        {
            var result = new CaYaTrace.Collectors.Proxy.ProxyRestorePoint.SweepResult(
                FoundRestorePoint: true, RestoredWinINet: wininet, RestoredWinHttp: winhttp,
                WinHttpNeedsElevation: needsAdmin, StaleAuthorities: stale, RemovedAuthorities: removed);

            foreach (string key in result.MessageKeys()) keys.Add(key);
        }

        Assert.NotEmpty(keys);

        List<string> missing = keys.Where(k => !english.ContainsKey(k)).Order().ToList();
        Assert.True(missing.Count == 0,
            $"the proxy sweep reports under {missing.Count} key(s) the catalogue does not have: "
            + string.Join(", ", missing));
    }

    /// <summary>
    /// The chat handler must not treat an ordinary reply as a control message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It did, and it shipped. Every reply carries a <c>web</c> field holding the findings,
    /// normally an empty array; the handler's first branch tested <c>payload.web !== undefined</c>
    /// as the acknowledgement for the web-lookup toggle, so every answer matched it, checked
    /// the box and returned before the turn was filled in or the spinner cleared. Asking
    /// anything produced a spinner that never stopped.
    /// </para>
    /// <para>
    /// Checked by reading the page rather than by running it, because the failure is one
    /// line of dispatch and no C# test can reach it — the harness that drives the assistant
    /// calls it directly and never crosses the bridge.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheChatHandlerDoesNotShareAFieldNameBetweenDataAndControl()
    {
        string markup = Markup();

        int handler = markup.IndexOf("bridge.on('chat'", StringComparison.Ordinal);
        Assert.True(handler > 0, "the chat bridge handler was not found");

        // The dispatch is at the top of the handler; the renderer below it may use
        // payload.web freely.
        string dispatch = markup[handler..Math.Min(handler + 900, markup.Length)];

        Assert.DoesNotContain("payload.web !== undefined", dispatch, StringComparison.Ordinal);
        Assert.Contains("payload.webEnabled !== undefined", dispatch, StringComparison.Ordinal);

        // The other half, from the host's source: a field the handler dispatches on must
        // never be one an ordinary reply carries. Reading both sides is the only way to
        // check this at all — the harness that drives the assistant calls it directly and
        // never crosses the bridge, and the page on its own cannot know what is sent to it.
        string host = Source(Path.Combine("src", "CaYaTrace.App", "Modes", "WorkbenchWindow.Analysis.cs"));

        int reply = host.IndexOf("private void PostReply(", StringComparison.Ordinal);
        Assert.True(reply > 0, "PostReply was not found");

        string emitted = host[reply..Math.Min(reply + 2000, host.Length)];

        foreach (string control in new[] { "cleared", "webEnabled" })
        {
            Assert.False(emitted.Contains($"{control} =", StringComparison.Ordinal),
                $"PostReply emits '{control}', which the chat handler treats as a control message — "
                + "every answer would be swallowed by that branch");
        }
    }

    /// <summary>Reads a source file from the repository, the way the catalogue is read.</summary>
    private static string Source(string relative)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CaYaTrace.sln")))
            directory = directory.Parent;

        Assert.NotNull(directory);

        string path = Path.Combine(directory!.FullName, relative);
        Assert.True(File.Exists(path), $"source not found at {path}");

        return File.ReadAllText(path);
    }

    [Fact]
    public void NothingIsLeftUntranslatedByAccident()
    {
        // Identical strings are legitimate — "CaYaTrace", "DNS", "TLS", "CSV" — but a
        // long sentence identical in both languages is a copied placeholder nobody came
        // back to.
        Dictionary<string, string> english = Table("en");

        foreach (string language in Languages().Where(static l => l != "en"))
        {
            Dictionary<string, string> other = Table(language);

            List<string> suspicious = english
                .Where(kv => kv.Value.Length > 60
                             && other.TryGetValue(kv.Key, out string? t)
                             && string.Equals(t, kv.Value, StringComparison.Ordinal))
                .Select(static kv => kv.Key)
                .ToList();

            Assert.True(suspicious.Count == 0,
                $"'{language}' repeats the English text verbatim for: {string.Join(", ", suspicious)}");
        }
    }

    [Fact]
    public void NoStringCanEscapeTheScriptElementItIsEmbeddedIn()
    {
        // The catalogue is injected into the page inside a <script type="application/json">
        // block. A literal closing tag in any value would end that element early and turn
        // the rest of the catalogue into markup.
        foreach (string language in Languages())
        {
            foreach ((string key, string value) in Table(language))
            {
                Assert.False(value.Contains("</script", StringComparison.OrdinalIgnoreCase),
                    $"{language}/{key} contains a closing script tag");
            }
        }
    }

    private static HashSet<string> Placeholders(string text)
        => Regex.Matches(text, @"\{(\d+)\}")
            .Select(static m => m.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);
}
