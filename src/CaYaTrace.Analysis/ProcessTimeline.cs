using CaYaTrace.Analysis.Persistence;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;

namespace CaYaTrace.Analysis;

/// <summary>One program's life during a session, with what it did while it ran.</summary>
public sealed record ProcessTimelineEntry
{
    public required ProcessKey Key { get; init; }
    public required uint Pid { get; init; }
    public uint ParentPid { get; init; }
    public ProcessKey ParentKey { get; init; }

    public required string Name { get; init; }
    public string? Path { get; init; }
    public string? CommandLine { get; init; }
    public string? User { get; init; }

    public DateTimeOffset Started { get; init; }
    public DateTimeOffset? Exited { get; init; }
    public int? ExitCode { get; init; }

    /// <summary>Null while the process was still running when recording stopped.</summary>
    public TimeSpan? Lifetime { get; init; }

    public bool InScope { get; init; }
    public bool PreExisting { get; init; }
    public bool IsElevated { get; init; }
    public SignatureState Signature { get; init; }
    public string? Signer { get; init; }
    public string? Sha256 { get; init; }

    /// <summary>How deep in the launch chain, counting the session's subject as zero.</summary>
    public int Depth { get; init; }

    public int FilesWritten { get; init; }
    public int RegistryChanges { get; init; }
    public int ModulesLoaded { get; init; }
    public int Connections { get; init; }
    public int ChildrenStarted { get; init; }

    /// <summary>Persistence entries this process installed, by name.</summary>
    public IReadOnlyList<string> Installed { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Plain statements about this process worth an analyst's attention.
    /// </summary>
    /// <remarks>
    /// Statements, not verdicts. "Ran for 0.3 seconds and exited" is a fact; whether it
    /// matters depends on what the program was supposed to be doing, which this cannot
    /// know.
    /// </remarks>
    public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();
}

/// <summary>
/// The session read as a sequence of programs running.
/// </summary>
/// <remarks>
/// <para>
/// Answers a question the causal tree does not: what ran, in what order, for how long,
/// and what did each one do while it was alive. An installer that starts eleven helpers,
/// nine of which live for under a second, is a completely different thing from one that
/// starts a single long-running service, and neither is visible from a list of file
/// writes.
/// </para>
/// <para>
/// <b>What this deliberately does not claim.</b> Windows does not report which process
/// asked another to close — that needs either a kernel driver or process-termination
/// auditing turned on, and this tool ships neither. So a process that was killed and one
/// that exited on its own are both shown as exits, with their exit status, and the
/// timeline says how it ended rather than who ended it. Inventing an answer from
/// coincidence in timing would produce exactly the kind of confident, wrong attribution
/// this codebase refuses elsewhere.
/// </para>
/// </remarks>
public sealed class ProcessTimeline
{
    /// <summary>
    /// Below this, a process did essentially nothing but start and stop.
    /// </summary>
    /// <remarks>
    /// Worth flagging because it is the signature of a launcher, a dropper stage, or a
    /// probe — and because on a normal desktop almost nothing a person starts lives this
    /// briefly.
    /// </remarks>
    private static readonly TimeSpan Fleeting = TimeSpan.FromSeconds(2);

    private readonly PathNormalizer _paths;

    public ProcessTimeline(PathNormalizer? paths = null)
        => _paths = paths ?? PathNormalizer.CreateForCurrentMachine();

    public IReadOnlyList<ProcessTimelineEntry> Build(
        IReadOnlyList<ProcessNode> nodes,
        IEnumerable<Observation> observations,
        IReadOnlyList<PersistenceRecord>? persistence = null,
        ProcessKey subject = default)
    {
        var byKey = new Dictionary<ProcessKey, ProcessNode>();
        foreach (ProcessNode node in nodes) byKey.TryAdd(node.Key, node);

        var files = new Dictionary<ProcessKey, int>();
        var registry = new Dictionary<ProcessKey, int>();
        var modules = new Dictionary<ProcessKey, int>();
        var connections = new Dictionary<ProcessKey, int>();
        var children = new Dictionary<ProcessKey, int>();

        foreach (Observation o in observations)
        {
            if (o.Actor == ProcessKey.None) continue;

            switch (o.Category)
            {
                case EventCategory.File when o.Action.IsPersistentChange():
                    Bump(files, o.Actor);
                    break;
                case EventCategory.Registry when o.Action.IsPersistentChange():
                    Bump(registry, o.Actor);
                    break;
                case EventCategory.Module:
                    Bump(modules, o.Actor);
                    break;
                case EventCategory.Network when o.Action is EventAction.Connect or EventAction.Accept:
                    Bump(connections, o.Actor);
                    break;
                case EventCategory.Process when o.Action == EventAction.Start:
                    Bump(children, o.Actor);
                    break;
            }
        }

        var installedBy = new Dictionary<ProcessKey, List<string>>();
        foreach (PersistenceRecord record in persistence ?? Array.Empty<PersistenceRecord>())
        {
            if (record.Actor == ProcessKey.None) continue;
            if (!installedBy.TryGetValue(record.Actor, out List<string>? list))
                installedBy[record.Actor] = list = new List<string>();
            list.Add(record.Describe());
        }

        var depths = new Dictionary<ProcessKey, int>();

        int DepthOf(ProcessKey key, int guard)
        {
            if (guard > 64) return guard;
            if (depths.TryGetValue(key, out int known)) return known;
            if (!byKey.TryGetValue(key, out ProcessNode? node)) return 0;

            int depth = node.ParentKey == ProcessKey.None || node.ParentKey == key
                ? 0
                : DepthOf(node.ParentKey, guard + 1) + 1;

            depths[key] = depth;
            return depth;
        }

        return nodes
            .OrderBy(static n => n.StartTime)
            .ThenBy(static n => n.Pid)
            .Select(node => Describe(
                node,
                files.GetValueOrDefault(node.Key),
                registry.GetValueOrDefault(node.Key),
                modules.GetValueOrDefault(node.Key),
                connections.GetValueOrDefault(node.Key),
                children.GetValueOrDefault(node.Key),
                installedBy.GetValueOrDefault(node.Key) ?? new List<string>(),
                DepthOf(node.Key, 0),
                subject))
            .ToList();
    }

    private ProcessTimelineEntry Describe(
        ProcessNode node,
        int files,
        int registry,
        int modules,
        int connections,
        int children,
        List<string> installed,
        int depth,
        ProcessKey subject)
    {
        TimeSpan? lifetime = node.ExitTime is { } exit ? exit - node.StartTime : null;
        var notes = new List<string>();

        if (node.PreExisting)
        {
            notes.Add("was already running when recording started");
        }
        else if (lifetime is { } life && life < Fleeting && life >= TimeSpan.Zero)
        {
            notes.Add($"ran for {life.TotalSeconds:0.##} seconds");
        }

        if (node.ExitCode is { } code && code != 0)
        {
            // Shown as hex for the negative NTSTATUS values, which are the ones that say
            // something went wrong rather than something returned a count.
            notes.Add(code is < 0 or > 0xFF
                ? $"exited with 0x{code:X8}"
                : $"exited with code {code}");
        }

        if (node.ExitTime is null && !node.PreExisting)
            notes.Add("was still running when recording stopped");

        string token = string.IsNullOrEmpty(node.ImagePath) ? string.Empty : _paths.Tokenize(node.ImagePath);

        if (token.StartsWith("%TEMP%", StringComparison.OrdinalIgnoreCase))
            notes.Add("ran from a temporary directory");

        if (node.Signature == SignatureState.Unsigned && !node.PreExisting)
            notes.Add("is not signed");
        else if (node.Signature is SignatureState.SignedExpired or SignatureState.SignedInvalid
                 or SignatureState.SignedUntrustedRoot)
            notes.Add($"has a signature that did not verify ({node.Signature})");

        if (node.IsElevated && depth > 0)
            notes.Add("ran with administrator rights");

        if (installed.Count > 0)
            notes.Add($"installed {installed.Count} thing(s) that survive a reboot");

        if (node.Key == subject && subject != ProcessKey.None)
            notes.Add("is the subject of this session");

        return new ProcessTimelineEntry
        {
            Key = node.Key,
            Pid = node.Pid,
            ParentPid = node.ParentPid,
            ParentKey = node.ParentKey,
            Name = node.ImageName,
            Path = string.IsNullOrEmpty(node.ImagePath) ? null : node.ImagePath,
            CommandLine = node.CommandLine,
            User = node.UserName,
            Started = node.StartTime,
            Exited = node.ExitTime,
            ExitCode = node.ExitCode,
            Lifetime = lifetime,
            InScope = node.InScope,
            PreExisting = node.PreExisting,
            IsElevated = node.IsElevated,
            Signature = node.Signature,
            Signer = node.Signer,
            Sha256 = node.Sha256,
            Depth = depth,
            FilesWritten = files,
            RegistryChanges = registry,
            ModulesLoaded = modules,
            Connections = connections,
            ChildrenStarted = children,
            Installed = installed,
            Notes = notes,
        };
    }

    private static void Bump(Dictionary<ProcessKey, int> counter, ProcessKey key)
        => counter[key] = counter.GetValueOrDefault(key) + 1;
}
