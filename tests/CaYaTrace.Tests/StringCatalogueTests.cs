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
