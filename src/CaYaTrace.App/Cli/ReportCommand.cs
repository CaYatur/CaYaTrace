using System.Globalization;
using System.Text;
using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;
using CaYaTrace.Storage;

namespace CaYaTrace.App.Cli;

/// <summary>Renders a recorded session without collecting anything new.</summary>
public static class ReportCommand
{
    public static int Run(CommandLine cmd)
    {
        string path = ResolveSessionPath(cmd.Require("session"));

        using SessionStore store = SessionStore.Open(path);
        SessionInfo? session = store.LoadSessionInfo();
        if (session is null)
        {
            Console.Error.WriteLine($"cayatrace: {path} does not contain a CaYaTrace session");
            return 1;
        }

        var processes = new ProcessTable();
        foreach (ProcessNode node in store.LoadProcesses()) processes.AddOrUpdate(node);

        var flows = new FlowTable();
        foreach (NetworkFlow flow in store.LoadFlows())
            flows.NoteConnect(flow.Key, flow.Owner, flow.FirstSeen, flow.OwnerEvidence ?? "stored");

        if (cmd.Has("export-package"))
            return ExportPackage(cmd, store, session);

        var query = new ObservationQuery
        {
            Categories = ParseCategories(cmd.Get("categories")),
        };

        var options = new CausalGraphOptions
        {
            IncludeReads = cmd.Flag("include-reads"),
            IncludeOutOfScope = cmd.Flag("include-out-of-scope"),
            MaxArtifactsPerGroup = cmd.Int("max-per-group", 400),
            OriginId = cmd.Get("origin"),

            // Anchor on the subject unless the analyst explicitly asks for the whole
            // machine, so the tree does not open on the shell that launched the tool.
            RootProcess = cmd.Flag("whole-machine") || session.RootProcess == ProcessKey.None
                ? null
                : session.RootProcess,
        };

        var builder = new CausalGraphBuilder(processes, flows);
        IReadOnlyList<CausalNode> roots = builder.Build(store.Query(query), options);

        string format = (cmd.Get("format") ?? "tree").ToLowerInvariant();
        string rendered = format switch
        {
            "tree" => TreeRenderer.Render(session, roots, store),
            "json" => JsonRenderer.Render(session, roots),

            // The HTML report is the workbench markup with the session inlined, so a
            // reader who will never install the tool sees exactly what the analyst saw.
            "html" => Modes.Assets.RenderStatic(Modes.WorkbenchWindow.BuildPayload(store, session, options)),

            _ => throw new CommandLineException(
                $"unsupported format '{format}'; use tree, json, or html"),
        };

        if (format == "html" && cmd.Get("out") is null)
            throw new CommandLineException("--out is required for --format html");

        string? outPath = cmd.Get("out");
        if (outPath is null)
        {
            Console.WriteLine(rendered);
        }
        else
        {
            File.WriteAllText(outPath, rendered, new UTF8Encoding(false));
            Console.WriteLine($"written: {Path.GetFullPath(outPath)}");
        }

        return 0;
    }

    /// <summary>
    /// Produces a portable removal package from a recorded session.
    /// </summary>
    /// <remarks>
    /// The package is what makes the tool useful beyond the machine it recorded on:
    /// observe an installer in a VM, carry the resulting <c>.ctpkg</c> to a machine that
    /// has never run CaYaTrace, and clean it there. The plan is a proposal — every
    /// item is re-verified against the target machine before anything is touched.
    /// </remarks>
    private static int ExportPackage(CommandLine cmd, SessionStore store, SessionInfo session)
    {
        var planner = new Remediation.RemovalPlanner(store, options: new Remediation.RemovalPlannerOptions
        {
            ScopedOnly = !cmd.Flag("include-out-of-scope"),
            IncludeModifiedFiles = cmd.Flag("include-modified"),
            ExcludeTemporary = !cmd.Flag("include-temp"),
            MinimumOriginAgreement = cmd.Int("min-origins", 1),
        });

        List<Remediation.RemovalItem> items = planner.Build(session);

        string output = cmd.Get("export-package")
                        ?? Path.Combine(Environment.CurrentDirectory, $"{session.Name}{Remediation.RemovalPackage.Extension}");

        if (!output.EndsWith(Remediation.RemovalPackage.Extension, StringComparison.OrdinalIgnoreCase))
            output += Remediation.RemovalPackage.Extension;

        Remediation.RemovalPlanner.Export(output, session, items,
            cmd.Flag("with-evidence") ? store.Query(new ObservationQuery { PersistentChangesOnly = true }) : null);

        Console.WriteLine($"package  {Path.GetFullPath(output)}");
        Console.WriteLine($"items    {items.Count}");

        foreach (IGrouping<Remediation.RemovalKind, Remediation.RemovalItem> group in
                 items.GroupBy(static i => i.Kind).OrderBy(static g => g.Key))
        {
            Console.WriteLine($"  {group.Key,-16} {group.Count()}");
        }

        if (items.Count == 0)
        {
            Console.WriteLine();
            Console.WriteLine("No persistent changes were attributed to the subject. Either it genuinely");
            Console.WriteLine("changed nothing, or the session was recorded without kernel tracing.");
        }

        Console.WriteLine();
        Console.WriteLine($"Preview it with:  CaYaTrace remediate --package \"{Path.GetFullPath(output)}\"");
        return 0;
    }

    private static string ResolveSessionPath(string input)
    {
        string full = Path.GetFullPath(input);

        if (Directory.Exists(full))
        {
            string candidate = Path.Combine(full, "session.ctdb");
            if (File.Exists(candidate)) return candidate;

            // Accept the session root as well, taking the most recent session in it.
            string? newest = Directory.EnumerateDirectories(full, "session_*")
                .Select(static d => Path.Combine(d, "session.ctdb"))
                .Where(File.Exists)
                .OrderByDescending(static f => File.GetLastWriteTimeUtc(f))
                .FirstOrDefault();

            if (newest is not null) return newest;
            throw new CommandLineException($"no session database found under {full}");
        }

        if (File.Exists(full)) return full;
        throw new CommandLineException($"session not found: {full}");
    }

    private static List<EventCategory>? ParseCategories(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var result = new List<EventCategory>();
        foreach (string token in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (Enum.TryParse(token, ignoreCase: true, out EventCategory category)) result.Add(category);
            else throw new CommandLineException($"unknown category '{token}'");
        }
        return result;
    }
}

/// <summary>
/// Renders the causal tree as text.
/// </summary>
/// <remarks>
/// The layout intentionally matches what an analyst would draw by hand: the process
/// lineage is the spine, verbs are the branches, and concrete artifacts are the
/// leaves. Keeping the text form a first-class output — not a debug afterthought —
/// means sessions can be diffed with ordinary tools, pasted into tickets, and read
/// over SSH on a machine with no GUI.
/// </remarks>
public static class TreeRenderer
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

        // Facts sit above children so a registry transition reads immediately under
        // the value it belongs to rather than after a long artifact list.
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

        // Attribution quality is shown inline, not hidden in a detail pane: an edge
        // that was inferred rather than observed changes what the analyst can claim.
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

internal static class JsonRenderer
{
    public static string Render(SessionInfo session, IReadOnlyList<CausalNode> roots)
        => System.Text.Json.JsonSerializer.Serialize(new { session, tree = roots },
            new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            });
}
