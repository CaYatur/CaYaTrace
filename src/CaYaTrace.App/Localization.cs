using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace CaYaTrace.App;

/// <summary>
/// The product's string catalogue, shared by the native shell, the workbench, and the
/// exported HTML report.
/// </summary>
/// <remarks>
/// <para>
/// English is the default and the fallback for every key. The tool follows the system
/// UI language when that language is one it has, which in practice means a Turkish
/// Windows opens a Turkish workbench without anyone configuring anything, and every
/// other Windows opens an English one.
/// </para>
/// <para>
/// A missing translation renders the English string rather than the key. A report is
/// read by people who did not run the tool; a stray <c>findings.no_match</c> in the
/// middle of a sentence tells them nothing, while the English sentence tells them
/// something.
/// </para>
/// </remarks>
public static class Strings
{
    private const string Resource = "CaYaTrace.Assets.strings.json";

    public const string DefaultLanguage = "en";

    private static readonly Lazy<JsonDocument> Catalogue = new(Load, LazyThreadSafetyMode.ExecutionAndPublication);

    private static string _language = DefaultLanguage;

    /// <summary>The active language tag, always one the catalogue actually contains.</summary>
    public static string Language
    {
        get => _language;
        set => _language = Supports(value) ? Normalize(value) : DefaultLanguage;
    }

    /// <summary>Language tags present in the catalogue, English first.</summary>
    public static IReadOnlyList<string> Available =>
        Catalogue.Value.RootElement.EnumerateObject()
            .Where(static p => !p.Name.StartsWith('_'))
            .Select(static p => p.Name)
            .OrderByDescending(static n => n == DefaultLanguage)
            .ToList();

    public static bool Supports(string? tag) =>
        tag is not null && Catalogue.Value.RootElement.TryGetProperty(Normalize(tag), out _);

    /// <summary>
    /// Picks the language for this run.
    /// </summary>
    /// <remarks>
    /// Order matters and is deliberate: an explicit switch beats a remembered
    /// preference, which beats the system language, which beats English. Anything a
    /// person typed most recently wins over anything inferred about them.
    /// </remarks>
    public static string Resolve(string? explicitTag, string? remembered)
    {
        if (Supports(explicitTag)) return Normalize(explicitTag!);
        if (Supports(remembered)) return Normalize(remembered!);

        string system = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        return Supports(system) ? system : DefaultLanguage;
    }

    /// <summary>Looks a key up in the active language, falling back to English.</summary>
    public static string T(string key)
    {
        if (TryGet(_language, key, out string? value)) return value;
        if (_language != DefaultLanguage && TryGet(DefaultLanguage, key, out value)) return value;

        // Reaching here means the key is in no language at all — a typo in calling code,
        // not a translation gap. Returning the key makes that visible instead of silent.
        return key;
    }

    /// <summary>
    /// Substitutes positional placeholders.
    /// </summary>
    /// <remarks>
    /// Positional rather than named, and substituted here rather than through
    /// <see cref="string.Format(string, object?[])"/>, because catalogue strings contain
    /// literal braces — a registry template like <c>{*}</c> or a JSON example would throw
    /// a format exception the moment it reached a formatter.
    /// </remarks>
    public static string Format(string key, params object?[] args)
    {
        string template = T(key);
        var sb = new StringBuilder(template);
        for (int i = 0; i < args.Length; i++)
            sb.Replace("{" + i.ToString(CultureInfo.InvariantCulture) + "}", args[i]?.ToString() ?? string.Empty);
        return sb.ToString();
    }

    /// <summary>
    /// The whole catalogue as JSON, for injection into the page.
    /// </summary>
    /// <remarks>
    /// Both languages are shipped, not just the active one. The workbench has a language
    /// switch that must work without a reload, and an exported report should stay
    /// readable by a colleague whose Windows is set to the other language.
    /// </remarks>
    public static string CatalogueJson => Catalogue.Value.RootElement.GetRawText();

    private static bool TryGet(string language, string key, out string value)
    {
        value = string.Empty;
        if (!Catalogue.Value.RootElement.TryGetProperty(language, out JsonElement table)) return false;
        if (!table.TryGetProperty(key, out JsonElement entry)) return false;
        if (entry.ValueKind != JsonValueKind.String) return false;

        value = entry.GetString() ?? string.Empty;
        return true;
    }

    private static string Normalize(string tag)
    {
        string trimmed = tag.Trim().ToLowerInvariant();
        int dash = trimmed.IndexOf('-', StringComparison.Ordinal);
        return dash > 0 ? trimmed[..dash] : trimmed;
    }

    private static JsonDocument Load()
    {
        Assembly assembly = typeof(Strings).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(Resource);

        if (stream is null)
        {
            throw new InvalidOperationException(
                $"embedded resource '{Resource}' is missing. Available: " +
                string.Join(", ", assembly.GetManifestResourceNames()));
        }

        return JsonDocument.Parse(stream);
    }
}

/// <summary>
/// The handful of preferences worth remembering between runs.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately tiny, and deliberately outside the executable's own folder — CaYaTrace
/// is meant to run from a read-only share or a write-protected stick, and a tool that
/// cannot start because it failed to write a settings file beside itself is a broken
/// portable tool.
/// </para>
/// <para>
/// Nothing secret is stored here. An API key typed into the workbench lives in memory
/// for that run and is gone when the process exits; writing it to a plain file in the
/// user profile would quietly turn a one-off into a credential at rest.
/// </para>
/// </remarks>
public sealed class UserSettings
{
    public string? Language { get; set; }

    public string? SessionRoot { get; set; }

    public string? OllamaEndpoint { get; set; }

    public int FleetPort { get; set; } = 47921;

    private static string FilePath
    {
        get
        {
            string root = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData,
                Environment.SpecialFolderOption.Create);
            return Path.Combine(root, "CaYaDev", "CaYaTrace", "settings.json");
        }
    }

    public static UserSettings Load()
    {
        try
        {
            string path = FilePath;
            if (!File.Exists(path)) return new UserSettings();

            return JsonSerializer.Deserialize<UserSettings>(File.ReadAllText(path)) ?? new UserSettings();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // A corrupt or unreadable settings file is not a reason to refuse to start.
            return new UserSettings();
        }
    }

    public void Save()
    {
        try
        {
            string path = FilePath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Preferences are a convenience. Losing them is not worth an error dialog.
        }
    }

    /// <summary>Where sessions are written when the operator has not chosen otherwise.</summary>
    public static string DefaultSessionRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments, Environment.SpecialFolderOption.Create),
        "CaYaTrace", "sessions");
}
