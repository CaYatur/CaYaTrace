using System.Globalization;
using System.Text;
using CaYaTrace.Core.Model;
using CaYaTrace.Storage;

namespace CaYaTrace.Export;

/// <summary>
/// Writes a session as one row per observation, for a spreadsheet.
/// </summary>
/// <remarks>
/// The lossy export, and deliberately so: it flattens a causal graph into a table
/// because that is what a spreadsheet can sort and filter. Use JSON when nothing may be
/// lost.
/// </remarks>
public static class CsvExporter
{
    private static readonly string[] Header =
    {
        "seq", "timestamp", "category", "action", "pid", "process", "target", "target2",
        "old_value", "new_value", "status", "bytes", "source", "confidence", "thread",
        "caused_by_seq", "origin",
    };

    public static void Write(TextWriter writer, SessionStore store, ExportRequest request)
    {
        // Excel reads the list separator from the machine's locale, so on a Turkish or
        // German Windows a comma-separated file lands entirely in column A. The hint
        // line fixes that, and is emitted only where it is needed: on a machine that
        // already expects commas it would be a stray row for every other CSV reader.
        if (CultureInfo.CurrentCulture.TextInfo.ListSeparator != ",")
            writer.WriteLine("sep=,");

        writer.WriteLine(string.Join(',', Header));

        var byKey = new Dictionary<ProcessKey, string>();
        var inScope = new HashSet<ProcessKey>();
        foreach (ProcessNode node in store.LoadProcesses())
        {
            byKey.TryAdd(node.Key, node.ImageName);
            if (node.InScope) inScope.Add(node.Key);
        }

        var query = new ObservationQuery
        {
            Categories = request.Categories?.ToList(),
        };

        foreach (Observation o in store.Query(query))
        {
            if (!request.IncludeOutOfScope && o.Actor != ProcessKey.None && !inScope.Contains(o.Actor))
                continue;

            if (!request.IncludeReads && IsRead(o.Action)) continue;

            writer.WriteLine(string.Join(',',
                Cell(o.Seq.ToString(CultureInfo.InvariantCulture)),
                Cell(o.Timestamp.ToString("O", CultureInfo.InvariantCulture)),
                Cell(o.Category.ToString()),
                Cell(o.Action.ToString()),
                Cell(o.Actor == ProcessKey.None ? string.Empty : o.Actor.Pid.ToString(CultureInfo.InvariantCulture)),
                Cell(byKey.GetValueOrDefault(o.Actor, string.Empty)),
                Cell(o.Target),
                Cell(o.Target2),
                Cell(o.OldValue),
                Cell(o.NewValue),
                Cell(o.Status.ToString()),
                Cell(o.Bytes == 0 ? string.Empty : o.Bytes.ToString(CultureInfo.InvariantCulture)),
                Cell(o.Source.ToString()),
                Cell(o.Confidence.ToString()),
                Cell(o.ThreadId == 0 ? string.Empty : o.ThreadId.ToString(CultureInfo.InvariantCulture)),
                Cell(o.CausedBySeq == 0 ? string.Empty : o.CausedBySeq.ToString(CultureInfo.InvariantCulture)),
                Cell(o.OriginId)));
        }
    }

    /// <summary>The encoding matters as much as the content — see the remarks.</summary>
    /// <remarks>
    /// A byte-order mark, which is the only thing that makes Excel read the file as
    /// UTF-8. Without it a path containing ş, ü, or any non-ASCII character is mangled
    /// on the machine most likely to open it.
    /// </remarks>
    public static Encoding FileEncoding { get; } = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);

    /// <summary>
    /// Operations that observe without changing anything.
    /// </summary>
    /// <remarks>
    /// <c>FileOpen</c> and <c>KeyOpen</c> count as reads here even though an open can precede
    /// a write, because the write is recorded separately. Treating them as changes would
    /// put an entry in the report for every DLL the loader touched.
    /// </remarks>
    private static bool IsRead(EventAction action)
        => action is EventAction.FileRead or EventAction.FileOpen or EventAction.KeyOpen;

    /// <summary>
    /// Quotes a value for CSV, and defuses it as a spreadsheet formula.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The formula guard is not cosmetic. Every <c>target</c> in this file is a string the
    /// observed program chose — a filename, a registry value, a URL. A program that
    /// creates a file named <c>=cmd|'/c calc'!A1</c> has written a DDE payload into the
    /// report, and Excel will offer to run it when the analyst opens the export. A
    /// forensics tool that turns evidence into execution on the analyst's own machine
    /// has done something considerably worse than losing the evidence.
    /// </para>
    /// <para>
    /// The mitigation is a leading apostrophe, which Excel strips on display and treats
    /// as "this is text". It does change the byte on disk, which is why the JSON export
    /// exists and is documented as the lossless one.
    /// </para>
    /// </remarks>
    internal static string Cell(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;

        string text = value;
        if (text[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            text = "'" + text;

        bool needsQuotes = text.Contains(',', StringComparison.Ordinal)
                           || text.Contains('"', StringComparison.Ordinal)
                           || text.Contains('\n', StringComparison.Ordinal)
                           || text.Contains('\r', StringComparison.Ordinal);

        if (!needsQuotes) return text;

        return '"' + text.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
    }
}
