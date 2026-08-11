using System.Globalization;
using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Core.Graph;

public sealed class CausalGraphOptions
{
    /// <summary>
    /// Include processes that were never linked to the investigation target. Off by
    /// default: on a live desktop the rest of the machine produces far more events
    /// than the subject does, and mixing them in destroys the signal.
    /// </summary>
    public bool IncludeOutOfScope { get; init; }

    /// <summary>
    /// Include read-only operations. Off by default. Reads dominate event volume by
    /// roughly an order of magnitude and almost never change the answer, but they do
    /// matter when profiling what an unknown binary is looking for.
    /// </summary>
    public bool IncludeReads { get; init; }

    /// <summary>Artifacts rendered per action group before truncation kicks in.</summary>
    public int MaxArtifactsPerGroup { get; init; } = 400;

    /// <summary>Suppress nodes scored below this level.</summary>
    public RiskLevel MinRisk { get; init; } = RiskLevel.None;

    /// <summary>Restrict to one machine's observations. Null means all machines.</summary>
    public string? OriginId { get; init; }

    /// <summary>
    /// Render the tree from this process rather than from the machine's process roots.
    /// </summary>
    /// <remarks>
    /// Without it, a session that watched one program still renders every ancestor of
    /// that program — the shell that launched CaYaTrace, the terminal that launched the
    /// shell, and so on up to the session manager. The subject then appears indented a
    /// dozen levels under processes that have nothing to do with it. When a session has
    /// a designated target, that target is the root the analyst wants.
    /// </remarks>
    public ProcessKey? RootProcess { get; init; }

    /// <summary>
    /// Collapse a directory whose children are all leaf files into a single node.
    /// Keeps an installer that drops 4000 files readable.
    /// </summary>
    public bool CollapseDirectories { get; init; } = true;

    /// <summary>Minimum siblings in one directory before collapsing applies.</summary>
    public int DirectoryCollapseThreshold { get; init; } = 12;

    public static CausalGraphOptions Default { get; } = new();
}

/// <summary>
/// Projects a flat observation stream into the process-rooted causal tree.
/// </summary>
/// <remarks>
/// The tree answers one question at every level: <em>what did this process cause?</em>
/// Child processes come first because they carry the most consequence, then the
/// system-change verbs in a fixed order so two sessions of the same installer are
/// visually diffable, then network activity, which is usually what the analyst
/// scrolls to.
/// </remarks>
public sealed class CausalGraphBuilder
{
    private readonly ProcessTable _processes;
    private readonly FlowTable? _flows;

    /// <summary>
    /// Endpoint-keyed view of the flow table, built once per <see cref="Build"/>.
    /// Rebuilding it per flow node would copy the whole table hundreds of times on a
    /// network-active subject.
    /// </summary>
    private Dictionary<string, NetworkFlow>? _flowsByEndpoint;

    public CausalGraphBuilder(ProcessTable processes, FlowTable? flows = null)
    {
        _processes = processes;
        _flows = flows;
    }

    public IReadOnlyList<CausalNode> Build(
        IEnumerable<Observation> observations,
        CausalGraphOptions? options = null)
    {
        options ??= CausalGraphOptions.Default;

        _flowsByEndpoint = null;
        if (_flows is not null)
        {
            _flowsByEndpoint = new Dictionary<string, NetworkFlow>(StringComparer.OrdinalIgnoreCase);
            foreach (NetworkFlow flow in _flows.Snapshot())
            {
                // Several ephemeral local ports can talk to the same endpoint; the
                // first flow seen wins, and its byte totals are the representative ones.
                _flowsByEndpoint.TryAdd(FlowKey.Format(flow.Key.RemoteAddress, flow.Key.RemotePort), flow);
            }
        }

        var byProcess = new Dictionary<ProcessKey, List<Observation>>();
        var orphans = new List<Observation>();

        foreach (Observation o in observations)
        {
            if (options.OriginId is not null && !string.Equals(o.OriginId ?? string.Empty, options.OriginId, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!options.IncludeReads && IsRead(o.Action))
                continue;
            if (o.Category == EventCategory.Session)
                continue;

            if (o.Actor == ProcessKey.None)
            {
                orphans.Add(o);
                continue;
            }

            if (!byProcess.TryGetValue(o.Actor, out List<Observation>? list))
            {
                list = new List<Observation>();
                byProcess[o.Actor] = list;
            }
            list.Add(o);
        }

        var roots = new List<CausalNode>();
        var built = new Dictionary<ProcessKey, CausalNode>();

        // A designated subject anchors the tree. Everything above it in the OS process
        // hierarchy is how the analyst happened to launch it, not part of what it did.
        ProcessNode? designated = options.RootProcess is { } rootKey ? _processes.Get(rootKey) : null;

        if (designated is not null)
        {
            roots.Add(BuildProcess(designated, byProcess, options, built, depth: 0));
        }
        else
        {
            foreach (ProcessNode process in _processes.Roots())
            {
                if (!options.IncludeOutOfScope && !process.InScope && !HasInScopeDescendant(process))
                    continue;

                roots.Add(BuildProcess(process, byProcess, options, built, depth: 0));
            }
        }

        // A process whose parent was never observed still deserves to be shown.
        foreach ((ProcessKey key, List<Observation> _) in byProcess)
        {
            if (built.ContainsKey(key)) continue;
            ProcessNode? node = _processes.Get(key);
            if (node is null) continue;
            if (!options.IncludeOutOfScope && !node.InScope) continue;
            roots.Add(BuildProcess(node, byProcess, options, built, depth: 0));
        }

        roots.Sort(static (a, b) => a.FirstSeen.CompareTo(b.FirstSeen));

        // Appended after sorting so it is always last. Unattributed activity is
        // background noise from the rest of the machine; sorting it by timestamp
        // regularly put it above the subject, which buries the finding under a
        // thousand lines of antivirus logs and browser caches.
        if (orphans.Count > 0)
            roots.Add(BuildUnattributed(orphans, options));

        return roots;
    }

    private bool HasInScopeDescendant(ProcessNode process)
    {
        foreach (ProcessKey childKey in process.Children)
        {
            ProcessNode? child = _processes.Get(childKey);
            if (child is null) continue;
            if (child.InScope || HasInScopeDescendant(child)) return true;
        }
        return false;
    }

    private CausalNode BuildProcess(
        ProcessNode process,
        Dictionary<ProcessKey, List<Observation>> byProcess,
        CausalGraphOptions options,
        Dictionary<ProcessKey, CausalNode> built,
        int depth)
    {
        if (built.TryGetValue(process.Key, out CausalNode? existing))
            return existing;

        var node = new CausalNode
        {
            Id = $"proc:{process.Key}",
            Kind = CausalNodeKind.Process,
            Label = process.ImageName.Length > 0 ? process.ImageName : $"PID {process.Pid}",
            Sublabel = DescribeProcess(process),
            Category = EventCategory.Process,
            Action = EventAction.Start,
            Process = process.Key,
            FirstSeen = process.StartTime,
            LastSeen = process.ExitTime ?? process.StartTime,
            OriginId = process.OriginId,
            Confidence = AttributionConfidence.Direct,
            Source = EvidenceSource.KernelEtw,
        };

        built[process.Key] = node;

        AddProcessFacts(node, process);

        // Depth guard: a fork bomb or a service restart loop must not blow the stack.
        if (depth < 64)
        {
            foreach (ProcessKey childKey in process.Children)
            {
                ProcessNode? child = _processes.Get(childKey);
                if (child is null) continue;
                if (!options.IncludeOutOfScope && !child.InScope && !HasInScopeDescendant(child)) continue;
                node.Children.Add(BuildProcess(child, byProcess, options, built, depth + 1));
            }
        }

        if (byProcess.TryGetValue(process.Key, out List<Observation>? own))
            AddActionGroups(node, own, options);

        RollUp(node);
        return node;
    }

    private void AddActionGroups(CausalNode parent, List<Observation> observations, CausalGraphOptions options)
    {
        foreach (IGrouping<(EventCategory, EventAction), Observation> group in observations
                     .GroupBy(static o => (o.Category, o.Action))
                     .OrderBy(static g => GroupOrder(g.Key.Item1, g.Key.Item2))
                     .ThenBy(static g => g.Key.Item1))
        {
            (EventCategory category, EventAction action) = group.Key;

            var groupNode = new CausalNode
            {
                Id = $"{parent.Id}/grp:{category}:{action}",
                Kind = CausalNodeKind.ActionGroup,
                Label = GraphLabels.Describe(category, action),
                Category = category,
                Action = action,
                Process = parent.Process,
                OriginId = parent.OriginId,
            };

            if (category is EventCategory.Http)
                AddHttpChildren(groupNode, group, options);
            else if (category is EventCategory.Network)
                AddFlowChildren(groupNode, group, options);
            else
                AddArtifactChildren(groupNode, group, options);

            if (groupNode.Children.Count == 0 && groupNode.EventCount == 0)
                continue;

            RollUp(groupNode);
            if (groupNode.Risk >= options.MinRisk)
                parent.Children.Add(groupNode);
        }
    }

    private static void AddArtifactChildren(
        CausalNode groupNode,
        IEnumerable<Observation> group,
        CausalGraphOptions options)
    {
        var artifacts = new Dictionary<string, CausalNode>(StringComparer.OrdinalIgnoreCase);

        foreach (Observation o in group)
        {
            string target = o.Target.Length > 0 ? o.Target : "(unresolved)";

            // A registry value and a DNS record type both qualify the target rather
            // than repeating it. Keeping them distinct matters for DNS in particular:
            // a name is queried for A and AAAA together, and folding both into one
            // node lets a failed AAAA lookup mask a successful A — reporting a
            // resolution that worked as one that failed.
            string display = o.Target2 is { Length: > 0 } && o.Category is EventCategory.Registry
                ? $"{target}::{o.Target2}"
                : o.Target2 is { Length: > 0 } && o.Category is EventCategory.Dns
                    ? $"{target}  ({o.Target2})"
                    : target;

            if (!artifacts.TryGetValue(display, out CausalNode? node))
            {
                node = new CausalNode
                {
                    Id = $"{groupNode.Id}/art:{artifacts.Count}",
                    Kind = CausalNodeKind.Artifact,
                    Label = display,
                    Category = o.Category,
                    Action = o.Action,
                    Process = o.Actor,
                    OriginId = o.OriginId,
                    Source = o.Source,
                };
                artifacts[display] = node;
            }

            node.Absorb(o);
            AccumulateBytes(node, o);
            AddValueChangeFacts(node, o);
        }

        List<CausalNode> ordered = artifacts.Values
            .OrderBy(static n => n.FirstSeen)
            .ToList();

        if (options.CollapseDirectories && groupNode.Category == EventCategory.File)
            ordered = CollapseByDirectory(groupNode, ordered, options);

        int limit = Math.Max(1, options.MaxArtifactsPerGroup);
        if (ordered.Count > limit)
        {
            groupNode.TruncatedChildren = ordered.Count - limit;
            ordered = ordered.Take(limit).ToList();
        }

        groupNode.Children.AddRange(ordered);
    }

    /// <summary>
    /// Folds many files written into the same directory under one node. An installer
    /// that unpacks 4000 files becomes one readable line rather than 4000.
    /// </summary>
    private static List<CausalNode> CollapseByDirectory(
        CausalNode groupNode,
        List<CausalNode> artifacts,
        CausalGraphOptions options)
    {
        var byDirectory = artifacts
            .GroupBy(static n => DirectoryOf(n.Label), StringComparer.OrdinalIgnoreCase)
            .ToList();

        var result = new List<CausalNode>();
        foreach (IGrouping<string, CausalNode> dir in byDirectory)
        {
            List<CausalNode> members = dir.ToList();
            if (dir.Key.Length == 0 || members.Count < options.DirectoryCollapseThreshold)
            {
                result.AddRange(members);
                continue;
            }

            var folder = new CausalNode
            {
                Id = $"{groupNode.Id}/dir:{result.Count}",
                Kind = CausalNodeKind.Artifact,
                Label = dir.Key + @"\",
                Sublabel = string.Format(CultureInfo.InvariantCulture, "{0} items", members.Count),
                Category = groupNode.Category,
                Action = groupNode.Action,
                Process = groupNode.Process,
                OriginId = groupNode.OriginId,
            };

            int limit = Math.Max(1, options.MaxArtifactsPerGroup);
            folder.Children.AddRange(members.Take(limit));
            if (members.Count > limit) folder.TruncatedChildren = members.Count - limit;

            RollUp(folder);
            result.Add(folder);
        }

        return result.OrderBy(static n => n.FirstSeen).ToList();
    }

    private void AddFlowChildren(CausalNode groupNode, IEnumerable<Observation> group, CausalGraphOptions options)
    {
        var flows = new Dictionary<string, CausalNode>(StringComparer.OrdinalIgnoreCase);

        foreach (Observation o in group)
        {
            string key = o.Target.Length > 0 ? o.Target : "(unknown endpoint)";
            if (!flows.TryGetValue(key, out CausalNode? node))
            {
                node = new CausalNode
                {
                    Id = $"{groupNode.Id}/flow:{flows.Count}",
                    Kind = CausalNodeKind.Flow,
                    Label = key,
                    Sublabel = o.Target2,
                    Category = EventCategory.Network,
                    Action = o.Action,
                    Process = o.Actor,
                    OriginId = o.OriginId,
                    Source = o.Source,
                };
                flows[key] = node;
            }

            node.Absorb(o);
            if (o.Action == EventAction.Send) node.BytesSent += o.Bytes;
            else if (o.Action == EventAction.Receive) node.BytesReceived += o.Bytes;
        }

        foreach (CausalNode flowNode in flows.Values.OrderBy(static n => n.FirstSeen))
        {
            EnrichFromFlowTable(flowNode);
            groupNode.Children.Add(flowNode);
        }

        int limit = Math.Max(1, options.MaxArtifactsPerGroup);
        if (groupNode.Children.Count > limit)
        {
            groupNode.TruncatedChildren = groupNode.Children.Count - limit;
            groupNode.Children.RemoveRange(limit, groupNode.Children.Count - limit);
        }
    }

    private void EnrichFromFlowTable(CausalNode flowNode)
    {
        if (_flowsByEndpoint is null) return;
        if (!_flowsByEndpoint.TryGetValue(flowNode.Label, out NetworkFlow? match)) return;

        if (match.ResolvedHost is { Length: > 0 })
            flowNode.Facts.Add(new("host", match.ResolvedHost));
        if (match.ServerName is { Length: > 0 })
            flowNode.Facts.Add(new("sni", match.ServerName));
        if (match.TlsVersion is { Length: > 0 })
            flowNode.Facts.Add(new("tls", match.TlsVersion));
        if (match.Alpn is { Length: > 0 })
            flowNode.Facts.Add(new("alpn", match.Alpn));
        if (match.ClientFingerprint is { Length: > 0 })
            flowNode.Facts.Add(new("ja3", match.ClientFingerprint));

        if (flowNode.BytesSent == 0) flowNode.BytesSent = match.BytesSent;
        if (flowNode.BytesReceived == 0) flowNode.BytesReceived = match.BytesReceived;
    }

    private static void AddHttpChildren(CausalNode groupNode, IEnumerable<Observation> group, CausalGraphOptions options)
    {
        List<Observation> all = group.ToList();
        var responsesByRequest = all
            .Where(static o => o.Action == EventAction.HttpResponse && o.CausedBySeq != 0)
            .GroupBy(static o => o.CausedBySeq)
            .ToDictionary(static g => g.Key, static g => g.First());

        var exchanges = all
            .Where(static o => o.Action is EventAction.HttpRequest or EventAction.WebSocketMessage)
            .OrderBy(static o => o.Timestamp)
            .ToList();

        int index = 0;
        foreach (Observation request in exchanges)
        {
            responsesByRequest.TryGetValue(request.Seq, out Observation? response);

            var node = new CausalNode
            {
                Id = $"{groupNode.Id}/http:{index++}",
                Kind = CausalNodeKind.HttpExchange,
                Label = $"{request.Target2} {request.Target}".Trim(),
                Sublabel = response is null ? null : $"{response.Target2} {response.NewValue}".Trim(),
                Category = EventCategory.Http,
                Action = request.Action,
                Process = request.Actor,
                OriginId = request.OriginId,
                Source = request.Source,
                BytesSent = request.Bytes,
                BytesReceived = response?.Bytes ?? 0,
            };
            node.Absorb(request);
            if (response is not null) node.Absorb(response);

            node.Children.Add(MetadataLeaf(node, "Request metadata", request));
            if (response is not null)
                node.Children.Add(MetadataLeaf(node, "Response metadata", response));

            node.Children.Add(new CausalNode
            {
                Id = $"{node.Id}/bytes",
                Kind = CausalNodeKind.Detail,
                Label = $"{FormatBytes(node.BytesSent)} sent / {FormatBytes(node.BytesReceived)} received",
                Category = EventCategory.Http,
                Process = node.Process,
                FirstSeen = node.FirstSeen,
                LastSeen = node.LastSeen,
            });

            groupNode.Children.Add(node);

            if (groupNode.Children.Count >= Math.Max(1, options.MaxArtifactsPerGroup))
            {
                groupNode.TruncatedChildren = Math.Max(0, exchanges.Count - groupNode.Children.Count);
                break;
            }
        }
    }

    private static CausalNode MetadataLeaf(CausalNode parent, string label, Observation source)
    {
        var leaf = new CausalNode
        {
            Id = $"{parent.Id}/{label.Replace(' ', '-')}",
            Kind = CausalNodeKind.Detail,
            Label = label,
            Category = source.Category,
            Action = source.Action,
            Process = source.Actor,
            Seq = source.Seq,
            FirstSeen = source.Timestamp,
            LastSeen = source.Timestamp,
            Source = source.Source,
        };
        if (source.Details is { Length: > 0 })
            leaf.Facts.Add(new("details", source.Details));
        return leaf;
    }

    private static CausalNode BuildUnattributed(List<Observation> orphans, CausalGraphOptions options)
    {
        var node = new CausalNode
        {
            Id = "proc:unattributed",
            Kind = CausalNodeKind.Process,
            Label = "(unattributed)",
            Sublabel = "activity that could not be tied to a process",
            Category = EventCategory.Process,
            Confidence = AttributionConfidence.None,
        };

        AddActionGroupsStatic(node, orphans, options);
        RollUp(node);
        return node;
    }

    private static void AddActionGroupsStatic(CausalNode parent, List<Observation> observations, CausalGraphOptions options)
    {
        foreach (IGrouping<(EventCategory, EventAction), Observation> group in observations
                     .GroupBy(static o => (o.Category, o.Action))
                     .OrderBy(static g => GroupOrder(g.Key.Item1, g.Key.Item2)))
        {
            var groupNode = new CausalNode
            {
                Id = $"{parent.Id}/grp:{group.Key.Item1}:{group.Key.Item2}",
                Kind = CausalNodeKind.ActionGroup,
                Label = GraphLabels.Describe(group.Key.Item1, group.Key.Item2),
                Category = group.Key.Item1,
                Action = group.Key.Item2,
            };
            AddArtifactChildren(groupNode, group, options);
            RollUp(groupNode);
            parent.Children.Add(groupNode);
        }
    }

    /// <summary>
    /// Routes an observation's byte count to the right total, or to none.
    /// </summary>
    /// <remarks>
    /// <see cref="Observation.Bytes"/> means different things per category and only some
    /// of them are meaningfully additive. A module load carries the image's size on
    /// disk — summing 28 DLL sizes into one figure and labelling it "sent" invented a
    /// 30 MB transfer out of a process that loaded ordinary system libraries. Sizes
    /// that describe a static object are recorded as a fact on the node instead.
    /// </remarks>
    private static void AccumulateBytes(CausalNode node, Observation o)
    {
        if (o.Bytes <= 0) return;

        switch (o.Category)
        {
            case EventCategory.File:
                node.BytesWritten += o.Bytes;
                break;

            case EventCategory.Network:
            case EventCategory.Http:
                if (o.Action is EventAction.Receive or EventAction.HttpResponse) node.BytesReceived += o.Bytes;
                else node.BytesSent += o.Bytes;
                break;

            case EventCategory.Module:
                // A size, not a transfer. Shown once, not accumulated.
                if (node.Facts.Count == 0)
                    node.Facts.Add(new("image size", FormatBytes(o.Bytes)));
                break;
        }
    }

    private static void AddValueChangeFacts(CausalNode node, Observation o)
    {
        // Only record the first transition; a value written in a loop would otherwise
        // produce thousands of identical facts.
        if (node.Facts.Count > 0) return;

        if (o.OldValue is not null || o.NewValue is not null)
        {
            if (o.OldValue is not null) node.Facts.Add(new("from", Truncate(o.OldValue, 512)));
            if (o.NewValue is not null) node.Facts.Add(new("to", Truncate(o.NewValue, 512)));
        }

        if (o.Action == EventAction.FileRename && o.Target2 is { Length: > 0 })
            node.Facts.Add(new("renamed to", o.Target2));

        if (o.Status is EventStatus.AccessDenied or EventStatus.Failed)
            node.Facts.Add(new("status", o.Status.ToString()));
    }

    private static void AddProcessFacts(CausalNode node, ProcessNode process)
    {
        if (process.CommandLine is { Length: > 0 })
            node.Facts.Add(new("command line", Truncate(process.CommandLine, 2048)));
        if (process.ImagePath.Length > 0)
            node.Facts.Add(new("image", process.ImagePath));
        if (process.UserName is { Length: > 0 })
            node.Facts.Add(new("user", process.UserName));
        if (process.Integrity != IntegrityLevel.Unknown)
            node.Facts.Add(new("integrity", process.Integrity.ToString()));
        if (process.Signature != SignatureState.Unchecked)
            node.Facts.Add(new("signature", process.Signer is { Length: > 0 }
                ? $"{process.Signature} ({process.Signer})"
                : process.Signature.ToString()));
        if (process.Sha256 is { Length: > 0 })
            node.Facts.Add(new("sha256", process.Sha256));
        if (process.ExitCode is not null)
            node.Facts.Add(new("exit code", process.ExitCode.Value.ToString(CultureInfo.InvariantCulture)));
        if (process.ScopeReason is { Length: > 0 } && process.ScopeReason != "root")
            node.Facts.Add(new("scope", process.ScopeReason));
        if (process.PreExisting)
            node.Facts.Add(new("note", "process existed before monitoring started; earlier activity was not observed"));
    }

    /// <summary>Propagates counts, byte totals, and timestamps up from children.</summary>
    private static void RollUp(CausalNode node)
    {
        foreach (CausalNode child in node.Children)
        {
            node.EventCount += child.EventCount;
            node.BytesSent += child.BytesSent;
            node.BytesReceived += child.BytesReceived;
            node.BytesWritten += child.BytesWritten;
            if (child.FirstSeen != default && (node.FirstSeen == default || child.FirstSeen < node.FirstSeen))
                node.FirstSeen = child.FirstSeen;
            if (child.LastSeen > node.LastSeen) node.LastSeen = child.LastSeen;
            if (child.Risk > node.Risk) node.Risk = child.Risk;
        }
    }

    private static string DescribeProcess(ProcessNode p)
    {
        string pid = $"PID {p.Pid}";
        if (p.ExitCode is not null) return $"{pid} · exited {p.ExitCode}";
        if (p.ExitTime is not null) return $"{pid} · exited";
        return pid;
    }

    private static bool IsRead(EventAction action) => action is
        EventAction.FileRead or EventAction.FileOpen or
        EventAction.KeyOpen or EventAction.HandleOpen;

    /// <summary>
    /// Fixed ordering so two runs of the same installer line up visually. Process
    /// creation first, then persistent system changes, then network.
    /// </summary>
    private static int GroupOrder(EventCategory category, EventAction action) => category switch
    {
        EventCategory.Process => 0,
        EventCategory.Module => 1,
        EventCategory.File => 2,
        EventCategory.Registry => 3,
        EventCategory.Service => 4,
        EventCategory.ScheduledTask => 5,
        EventCategory.Autorun => 6,
        EventCategory.Driver => 7,
        EventCategory.Wmi => 8,
        EventCategory.Firewall => 9,
        EventCategory.Dns => 10,
        EventCategory.Network => 11,
        EventCategory.Tls => 12,
        EventCategory.Http => 13,
        _ => 20,
    };

    private static string DirectoryOf(string path)
    {
        int slash = path.LastIndexOf('\\');
        return slash <= 0 ? string.Empty : path[..slash];
    }

    private static string Truncate(string value, int max)
        => value.Length <= max ? value : value[..max] + "…";

    internal static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        double kb = bytes / 1024.0;
        if (kb < 1024) return kb.ToString("0.#", CultureInfo.InvariantCulture) + " KB";
        double mb = kb / 1024.0;
        if (mb < 1024) return mb.ToString("0.#", CultureInfo.InvariantCulture) + " MB";
        return (mb / 1024.0).ToString("0.##", CultureInfo.InvariantCulture) + " GB";
    }
}
