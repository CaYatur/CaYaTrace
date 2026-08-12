using System.Globalization;
using System.Text;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;
using CaYaTrace.Storage;

namespace CaYaTrace.Export;

/// <summary>
/// Renders the causal tree as text.
/// </summary>
/// <remarks>
/// The layout intentionally matches what an analyst would draw by hand: the process
/// lineage is the spine, verbs are the branches, and concrete artifacts are the leaves.
/// Keeping the text form a first-class output — not a debug afterthought — means
/// sessions can be diffed with ordinary tools, pasted into tickets, and read over SSH on
/// a machine with no GUI.
/// </remarks>
public static class TreeTextExporter
{
    public static string Render(SessionInfo session, IReadOnlyList<CausalNode> roots, SessionStore store)
    {
        var sb = new StringBuilder();

        sb.AppendLine(CultureInfo.InvariantCulture, $"CaYaTrace session {session.SessionId}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  name      {session.Name}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  started   {session.StartedAt:u}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  duration  {session.Duration.TotalSeconds:F1}s");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  machine   {session.Machine.MachineName} · {session.Machine.OsBuild} · {session.Machine.Architecture}");
        if (session.Machine.IsVirtualMachine)
            sb.AppendLine(CultureInfo.InvariantCulture, $"  virtual   {session.Machine.Hypervisor}");
        if (session.TargetPath is { Length: > 0 })
            sb.AppendLine(CultureInfo.InvariantCulture, $"  target    {session.TargetPath}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  events    {store.CountObservations():N0}");

        Dictionary<EventCategory, long> byCategory = store.CountByCategory();
        if (byCategory.Count > 0)
        {
            IEnumerable<string> parts = byCategory
                .Where(static kv => kv.Key != EventCategory.Session)
                .OrderByDescending(static kv => kv.Value)
                .Select(static kv => $"{kv.Key.ToString().ToLowerInvariant()} {kv.Value:N0}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"            {string.Join(" · ", parts)}");
        }

        string? degraded = session.Quality.Summarize();
        if (degraded is not null)
        {
            sb.AppendLine();
            sb.AppendLine("  ⚠ DATA QUALITY");
            sb.AppendLine(CultureInfo.InvariantCulture, $"    {degraded}");
            sb.AppendLine("    Findings below are incomplete. Treat absence of evidence accordingly.");
        }

        foreach (string skipped in session.Quality.SkippedForPrivilege)
            sb.AppendLine(CultureInfo.InvariantCulture, $"  ⚠ skipped: {skipped}");

        sb.AppendLine();

        if (roots.Count == 0)
        {
            sb.AppendLine("(no in-scope activity recorded)");
            return sb.ToString();
        }

        foreach (CausalNode root in roots)
            Write(sb, root, prefix: string.Empty, isLast: true, isRoot: true);

        return sb.ToString();
    }

    private static void Write(StringBuilder sb, CausalNode node, string prefix, bool isLast, bool isRoot)
    {
        if (isRoot)
        {
            sb.AppendLine(Describe(node));
        }
        else
        {
            sb.Append(prefix).Append(isLast ? "└─ " : "├─ ").AppendLine(Describe(node));
        }

        string childPrefix = isRoot ? string.Empty : prefix + (isLast ? "   " : "│  ");

        // Facts sit above children so a registry transition reads immediately under the
        // value it belongs to rather than after a long artifact list.
        for (int i = 0; i < node.Facts.Count; i++)
        {
            bool lastFact = i == node.Facts.Count - 1 && node.Children.Count == 0 && node.TruncatedChildren == 0;
            sb.Append(childPrefix)
              .Append(lastFact ? "└─ " : "├─ ")
              .Append(node.Facts[i].Key)
              .Append(": ")
              .AppendLine(Collapse(node.Facts[i].Value));
        }

        for (int i = 0; i < node.Children.Count; i++)
        {
            bool lastChild = i == node.Children.Count - 1 && node.TruncatedChildren == 0;
            Write(sb, node.Children[i], childPrefix, lastChild, isRoot: false);
        }

        if (node.TruncatedChildren > 0)
        {
            sb.Append(childPrefix)
              .Append("└─ ")
              .AppendLine(CultureInfo.InvariantCulture, $"… {node.TruncatedChildren:N0} more not shown");
        }
    }

    private static string Describe(CausalNode node)
    {
        var sb = new StringBuilder(node.Label);

        if (node.Sublabel is { Length: > 0 })
            sb.Append("  (").Append(Collapse(node.Sublabel)).Append(')');

        if (node.Kind == CausalNodeKind.ActionGroup && node.EventCount > 0)
            sb.Append(CultureInfo.InvariantCulture, $"  [{node.EventCount:N0}]");

        if (node.BytesWritten > 0)
            sb.Append("  ").Append(FormatBytes(node.BytesWritten)).Append(" written");

        if (node.BytesSent > 0 || node.BytesReceived > 0)
        {
            sb.Append("  ")
              .Append(FormatBytes(node.BytesSent))
              .Append(" sent / ")
              .Append(FormatBytes(node.BytesReceived))
              .Append(" received");
        }

        // Attribution quality is shown inline, not hidden in a detail pane: an edge that
        // was inferred rather than observed changes what the analyst can claim.
        if (node.Confidence is AttributionConfidence.Probable or AttributionConfidence.Weak)
            sb.Append("  ~").Append(node.Confidence.ToString().ToLowerInvariant());

        if (node.Source == EvidenceSource.SnapshotDiff)
            sb.Append("  [snapshot diff]");

        return sb.ToString();
    }

    private static string Collapse(string value)
    {
        string flat = value.ReplaceLineEndings(" ").Trim();
        return flat.Length <= 300 ? flat : flat[..300] + "…";
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        double kb = bytes / 1024.0;
        if (kb < 1024) return kb.ToString("0.#", CultureInfo.InvariantCulture) + " KB";
        double mb = kb / 1024.0;
        return mb < 1024
            ? mb.ToString("0.#", CultureInfo.InvariantCulture) + " MB"
            : (mb / 1024.0).ToString("0.##", CultureInfo.InvariantCulture) + " GB";
    }
}
