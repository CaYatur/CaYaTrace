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

    private static readonly Lazy<string> Document = new(Compose, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>The workbench markup with its stylesheet inlined and no data.</summary>
    public static string Workbench => Document.Value;

    /// <summary>
    /// The same document with a session baked in, ready to write to disk and open in
    /// any browser.
    /// </summary>
    public static string RenderStatic(string sessionJson)
    {
        // Injected before the first script so the page finds data already present and
        // never attempts the WebView2 bridge path.
        string payload = $"<script>window.__CAYATRACE_DATA__ = {sessionJson};</script>";

        // Anchored on the page's own script element rather than the first "<script>" in
        // the file, because the i18n block is a script tag too and inserting ahead of it
        // would put the data before the catalogue it is rendered with.
        const string anchor = "<script>\n\"use strict\";";
        int marker = Document.Value.IndexOf(anchor, StringComparison.Ordinal);
        if (marker < 0) marker = Document.Value.IndexOf("\"use strict\"", StringComparison.Ordinal);

        return marker < 0
            ? Document.Value + payload
            : Document.Value.Insert(marker, payload + Environment.NewLine);
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
