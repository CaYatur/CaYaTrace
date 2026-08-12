using CaYaTrace.Analysis;
using CaYaTrace.Core.Model;
using CaYaTrace.Storage;

namespace CaYaTrace.App.Cli;

/// <summary>
/// Compares recordings of the same program from several machines.
/// </summary>
/// <remarks>
/// <para>
/// Running the same installer on two VMs produces two artifact sets that differ in ways
/// that mean nothing — a random working directory, a per-install GUID, a timestamped
/// log. A plain diff reports all of it. What an analyst wants is the inverse: the parts
/// that recur on every machine, which are the program's actual behaviour, separated
/// from the parts that do not.
/// </para>
/// <para>
/// The comparison also produces materially better removal packages. With one machine
/// the variable parts of a path can only be guessed; with two they are <em>measured</em>, and
/// the resulting package matches on a third machine that spells them differently again.
/// </para>
/// </remarks>
public static class CompareCommand
{
    public static int Run(CommandLine cmd)
    {
        List<string> inputs = cmd.Positional.ToList();
        if (cmd.Get("sessions") is { Length: > 0 } list)
            inputs.AddRange(list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        if (inputs.Count < 2)
            throw new CommandLineException("compare needs at least two sessions: CaYaTrace compare <dirA> <dirB> [...]");

        var stores = new List<SessionStore>();
        var byOrigin = new Dictionary<string, IReadOnlyList<Observation>>(StringComparer.OrdinalIgnoreCase);
        var labels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (string input in inputs)
            {
                SessionStore store = SessionStore.Open(ResolveSession(input));
                stores.Add(store);

                SessionInfo? info = store.LoadSessionInfo();
                if (info is null)
                {
                    Console.Error.WriteLine($"cayatrace: {input} does not contain a CaYaTrace session");
                    return 1;
                }

                // Sessions recorded on cloned VMs can share a machine id, so the key is
                // made unique per session — otherwise two machines would collapse into
                // one and their agreement would be invented.
                string origin = $"{info.Machine.MachineName}#{info.SessionId}";
                labels[origin] = $"{info.Machine.MachineName} ({info.Machine.OsBuild})" +
                                 (info.Machine.IsVirtualMachine ? $" [{info.Machine.Hypervisor}]" : string.Empty);

                byOrigin[origin] = LoadScoped(store, cmd.Flag("include-out-of-scope"));
            }

            MergeReport report = new ArtifactMerger().Merge(byOrigin);
            Render(report, labels);

            if (cmd.Get("export-package") is { Length: > 0 } packagePath)
                return ExportMergedPackage(cmd, report, stores[0], packagePath);

            return 0;
        }
        finally
        {
            foreach (SessionStore store in stores) store.Dispose();
        }
    }

    /// <summary>
    /// Loads the persistent changes a session attributed to the subject's process tree.
    /// </summary>
    /// <remarks>
    /// Scope filtering matters more here than anywhere else. Two recordings taken on
    /// the same busy desktop agree on a great deal that has nothing to do with the
    /// subject — antivirus logs, browser caches, search indexer journals — and every
    /// one of those looks like consistent, corroborated behaviour to a merger that
    /// cannot see who caused it. Without this filter the comparison's most confident
    /// findings are other people's software, and a package built from it proposes
    /// deleting them.
    ///
    /// Snapshot-derived changes are kept despite having no actor: they are unattributed
    /// by construction, and dropping them would discard exactly the persistence that
    /// live capture is worst at seeing.
    /// </remarks>
    private static IReadOnlyList<Observation> LoadScoped(SessionStore store, bool includeOutOfScope)
    {
        List<Observation> changes = store
            .Query(new ObservationQuery { PersistentChangesOnly = true })
            .ToList();

        if (includeOutOfScope) return changes;

        var inScope = new HashSet<ProcessKey>(
            store.LoadProcesses().Where(static p => p.InScope).Select(static p => p.Key));

        return changes
            .Where(o => o.Actor == ProcessKey.None
                ? o.Source == EvidenceSource.SnapshotDiff
                : inScope.Contains(o.Actor))
            .ToList();
    }

    private static void Render(MergeReport report, Dictionary<string, string> labels)
    {
        Console.WriteLine("CaYaTrace comparison");
        foreach (string origin in report.Origins)
            Console.WriteLine($"  {labels.GetValueOrDefault(origin, origin)}");

        Console.WriteLine();
        Console.WriteLine(report.Summarize());
        Console.WriteLine();

        Section("ON EVERY MACHINE — the program's fixed behaviour",
            report.Artifacts.Where(static a => a.Consistency == Consistency.Universal));

        Section("ON SOME MACHINES — conditional behaviour, or a missed capture",
            report.Artifacts.Where(static a => a.Consistency == Consistency.Common));

        Section("ON ONE MACHINE ONLY — machine-specific, or done exactly once",
            report.Artifacts.Where(static a => a.Consistency == Consistency.Unique));

        IReadOnlyList<MergedArtifact> varying = report.Varying.ToList();
        if (varying.Count > 0)
        {
            Console.WriteLine("RUN-SPECIFIC NAMES");
            Console.WriteLine("  These paths differ per installation. A package built from this comparison");
            Console.WriteLine("  carries the pattern, so it still matches on a machine that names them differently.");
            Console.WriteLine();
            foreach (MergedArtifact artifact in varying.Take(60))
            {
                Console.WriteLine($"  {artifact.Template.Pattern}");
                foreach ((string origin, string concrete) in artifact.ByOrigin)
                    Console.WriteLine($"      {labels.GetValueOrDefault(origin, origin)}: {concrete}");
            }
            Console.WriteLine();
        }
    }

    private static void Section(string title, IEnumerable<MergedArtifact> artifacts)
    {
        List<MergedArtifact> items = artifacts.ToList();
        if (items.Count == 0) return;

        Console.WriteLine($"{title}  [{items.Count:N0}]");
        foreach (MergedArtifact artifact in items.Take(120))
        {
            string marker = artifact.Template.HasVariables ? "~" : " ";
            Console.WriteLine($"  {marker} {artifact.Action,-18} {artifact.Template.Pattern}");
        }
        if (items.Count > 120) Console.WriteLine($"    … {items.Count - 120:N0} more");
        Console.WriteLine();
    }

    private static int ExportMergedPackage(CommandLine cmd, MergeReport report, SessionStore reference, string output)
    {
        SessionInfo? session = reference.LoadSessionInfo();
        if (session is null) return 1;

        int minimum = cmd.Int("min-origins", report.Origins.Count);

        // Shared with the workbench, so the same comparison cannot yield two different
        // packages depending on which surface asked for it.
        List<Remediation.RemovalItem> items = Remediation.RemovalPlanner.FromComparison(report, minimum);

        if (!output.EndsWith(Remediation.RemovalPackage.Extension, StringComparison.OrdinalIgnoreCase))
            output += Remediation.RemovalPackage.Extension;

        Remediation.RemovalPlanner.Export(output, session, items);

        Console.WriteLine($"package  {Path.GetFullPath(output)}");
        Console.WriteLine($"items    {items.Count} (seen on at least {minimum} of {report.Origins.Count} machines)");
        Console.WriteLine($"         {items.Count(static i => i.TargetPattern is not null)} carry a measured path pattern");
        return 0;
    }

    private static string ResolveSession(string input)
    {
        string full = Path.GetFullPath(input);

        if (File.Exists(full)) return full;

        if (Directory.Exists(full))
        {
            string direct = Path.Combine(full, "session.ctdb");
            if (File.Exists(direct)) return direct;

            string? newest = Directory.EnumerateDirectories(full, "session_*")
                .Select(static d => Path.Combine(d, "session.ctdb"))
                .Where(File.Exists)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();

            if (newest is not null) return newest;
        }

        throw new CommandLineException($"session not found: {full}");
    }
}
