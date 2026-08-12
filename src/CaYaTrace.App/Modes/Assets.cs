using System.Reflection;
using System.Text;

namespace CaYaTrace.App.Modes;

/// <summary>
/// Loads the embedded UI and assembles it into a single self-contained document.
/// </summary>
/// <remarks>
/// The stylesheet is inlined rather than referenced. That is what lets one artifact
/// serve as both the live workbench and the exported report: an export has to survive
/// being emailed, copied to a USB stick, or opened with no network, and a page that
/// pulls in a separate CSS file does not.
/// </remarks>
public static class Assets
{
    private const string HtmlResource = "CaYaTrace.Assets.workbench.html";
    private const string CssResource = "CaYaTrace.Assets.theme.css";
    private const string CssPlaceholder = "/*__THEME_CSS__*/";
    private const string I18nPlaceholder = "/*__I18N__*/";
    private const string DataPlaceholder = "<!--__CAYATRACE_DATA__-->";

    private static readonly Lazy<string> Document = new(Compose, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>The workbench markup with its stylesheet inlined and no data.</summary>
    public static string Workbench => Document.Value;

    /// <summary>
    /// The same document with a session baked in, ready to write to disk and open in
    /// any browser.
    /// </summary>
    /// <remarks>
    /// Substituted into an explicit placeholder, the same way the stylesheet and the
    /// string catalogue are. An earlier version searched for the page's own
    /// <c>&lt;script&gt;</c> element by text; that string contains a newline, so under a
    /// checkout with CRLF line endings the search missed and the fallback inserted the
    /// payload <em>inside</em> the existing script element — a nested tag, a syntax error, and
    /// a report that renders its own source as visible text. Placeholders do not have
    /// line endings.
    /// </remarks>
    public static string RenderStatic(string sessionJson)
    {
        string payload = $"<script>window.__CAYATRACE_DATA__ = {sessionJson};</script>";

        if (!Document.Value.Contains(DataPlaceholder, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"the workbench document has no {DataPlaceholder} placeholder to write the session into");
        }

        return Document.Value.Replace(DataPlaceholder, payload, StringComparison.Ordinal);
    }

    private static string Compose()
    {
        string html = Read(HtmlResource);
        string css = Read(CssResource);

        // The catalogue goes in as the content of a JSON script element, which is inert:
        // the browser does not execute it and does not parse HTML inside it. The one
        // sequence that would escape that element is a literal closing script tag, which
        // no string in the catalogue contains — but it is escaped anyway, because the
        // cost is a Replace and the failure mode is script injection into every report
        // this tool ever writes.
        string catalogue = Strings.CatalogueJson
            .Replace("</script", @"<\/script", StringComparison.OrdinalIgnoreCase);

        return html
            .Replace(CssPlaceholder, css, StringComparison.Ordinal)
            .Replace(I18nPlaceholder, catalogue, StringComparison.Ordinal);
    }

    private static string Read(string name)
    {
        Assembly assembly = typeof(Assets).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(name);

        if (stream is null)
        {
            throw new InvalidOperationException(
                $"embedded resource '{name}' is missing. Available: " +
                string.Join(", ", assembly.GetManifestResourceNames()));
        }

        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
