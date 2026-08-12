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

        List<EventCategory>? categories = ParseCategories(cmd.Get("categories"));
        string format = (cmd.Get("format") ?? "tree").ToLowerInvariant();
        string? outPath = cmd.Get("out");

        var request = new Export.ExportRequest
        {
            Format = format switch
            {
                "json" => Export.ExportFormat.Json,
                "csv" => Export.ExportFormat.Csv,
                "html" => Export.ExportFormat.Html,
                "tree" => Export.ExportFormat.Tree,
                _ => throw new CommandLineException(
                    $"unsupported format '{format}'; use tree, json, csv, or html"),
            },
            Scope = cmd.Get("scope")?.ToLowerInvariant() switch
            {
                "minimal" => Export.ExportScope.Minimal,
                "full" => Export.ExportScope.Full,
                _ => cmd.Flag("include-reads") || cmd.Flag("include-out-of-scope")
                    ? Export.ExportScope.Full
                    : Export.ExportScope.Standard,
            },
            Categories = categories,
            Language = Strings.Language,
        };

        // CSV streams to the destination rather than being built in memory: a full
        // session is millions of rows, and materialising that as one string is the
        // difference between an export that works and one that runs the machine out
        // of memory.
        if (request.Format == Export.ExportFormat.Csv)
        {
            if (outPath is null) throw new CommandLineException("--out is required for --format csv");

            using var writer = new StreamWriter(outPath, append: false, Export.CsvExporter.FileEncoding);
            Export.CsvExporter.Write(writer, store, request);
            Console.WriteLine($"written: {Path.GetFullPath(outPath)}");
            return 0;
        }

        var options = new CausalGraphOptions
        {
            IncludeReads = cmd.Flag("include-reads") || request.IncludeReads,
            IncludeOutOfScope = cmd.Flag("include-out-of-scope") || request.IncludeOutOfScope,
            MaxArtifactsPerGroup = cmd.Int("max-per-group", request.MaxArtifactsPerGroup),
            OriginId = cmd.Get("origin"),

            // Anchor on the subject unless the analyst explicitly asks for the whole
            // machine, so the tree does not open on the shell that launched the tool.
            RootProcess = cmd.Flag("whole-machine") || session.RootProcess == ProcessKey.None
                ? null
                : session.RootProcess,
        };

        var builder = new CausalGraphBuilder(processes, flows);
        IReadOnlyList<CausalNode> roots = builder.Build(
            store.Query(new ObservationQuery { Categories = categories }), options);

        string rendered = request.Format switch
        {
            Export.ExportFormat.Tree => Export.TreeTextExporter.Render(session, roots, store),
            Export.ExportFormat.Json => System.Text.Json.JsonSerializer.Serialize(
                Export.SessionProjection.BuildModel(store, session, request),
                new System.Text.Json.JsonSerializerOptions(Export.SessionProjection.Json) { WriteIndented = true }),

            // The HTML report is the workbench markup with the session inlined, so a
            // reader who will never install the tool sees exactly what the analyst saw.
            _ => Modes.Assets.RenderStatic(Export.SessionProjection.Build(store, session, request)),
        };

        if (request.Format == Export.ExportFormat.Html && outPath is null)
            throw new CommandLineException("--out is required for --format html");

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
