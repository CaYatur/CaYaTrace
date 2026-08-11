using CaYaTrace.Core.Model;

namespace CaYaTrace.Core.Correlation;

/// <summary>
/// Authoritative map from raw OS identifiers (PID, TID) to stable process identity.
/// </summary>
/// <remarks>
/// <para>
/// Most ETW events carry only a PID, and PIDs are recycled. This table keeps every
/// <em>generation</em> of each PID — each distinct process that has held it — ordered
/// by start time, so an event at time T resolves to the generation that was actually
/// alive at T rather than to whichever process happens to hold the PID right now.
/// </para>
/// <para>
/// Thread-safe: ETW callbacks arrive on the trace-processing thread of each session,
/// and a session runs several concurrent sessions (kernel, user-mode, network).
/// </para>
/// </remarks>
public sealed class ProcessTable
{
    /// <summary>
    /// Tolerance applied when matching an event timestamp against a process lifetime.
    /// ETW buffers from different sessions are flushed independently, so an event can
    /// legitimately carry a timestamp a little before the start event we already
    /// processed, or a little after the exit event.
    /// </summary>
    private static readonly TimeSpan ClockTolerance = TimeSpan.FromMilliseconds(250);

    private readonly object _gate = new();
    private readonly Dictionary<uint, List<ProcessNode>> _byPid = new();
    private readonly Dictionary<ulong, ProcessNode> _byStartKey = new();
    private readonly Dictionary<uint, ProcessKey> _threadOwners = new();

    public int Count
    {
        get { lock (_gate) return _byStartKey.Count + _byPid.Values.Sum(v => v.Count(p => !p.Key.IsStrong)); }
    }

    /// <summary>Registers a newly started process, or returns the existing node.</summary>
    public ProcessNode AddOrUpdate(ProcessNode node)
    {
        lock (_gate)
        {
            if (node.Key.IsStrong && _byStartKey.TryGetValue(node.Key.StartKey, out ProcessNode? existing))
            {
                Merge(existing, node);
                return existing;
            }

            if (!_byPid.TryGetValue(node.Pid, out List<ProcessNode>? generations))
            {
                generations = new List<ProcessNode>(1);
                _byPid[node.Pid] = generations;
            }
            else
            {
                // A weak-keyed node may already be here from a rundown or from an
                // event seen before the start event. Unify instead of duplicating.
                ProcessNode? match = generations.FirstOrDefault(g => g.Key == node.Key);
                if (match is not null)
                {
                    Merge(match, node);
                    if (node.Key.IsStrong)
                        _byStartKey[node.Key.StartKey] = match;
                    return match;
                }
            }

            generations.Add(node);
            generations.Sort(static (a, b) => a.StartTime.CompareTo(b.StartTime));

            if (node.Key.IsStrong)
                _byStartKey[node.Key.StartKey] = node;

            LinkToParent(node);
            return node;
        }
    }

    /// <summary>
    /// Resolves a PID observed at a point in time to the process generation that was
    /// alive then. Returns <see cref="ProcessKey.None"/> when the PID is unknown.
    /// </summary>
    public ProcessKey Resolve(uint pid, DateTimeOffset at)
    {
        lock (_gate)
        {
            ProcessNode? node = ResolveNodeLocked(pid, at);
            return node?.Key ?? ProcessKey.None;
        }
    }

    public ProcessNode? ResolveNode(uint pid, DateTimeOffset at)
    {
        lock (_gate) return ResolveNodeLocked(pid, at);
    }

    private ProcessNode? ResolveNodeLocked(uint pid, DateTimeOffset at)
    {
        if (!_byPid.TryGetValue(pid, out List<ProcessNode>? generations) || generations.Count == 0)
            return null;

        if (generations.Count == 1)
            return generations[0];

        // Generations are sorted by start time. Walk backwards to the newest one that
        // had already started by `at` and had not yet exited.
        ProcessNode? bestStarted = null;
        for (int i = generations.Count - 1; i >= 0; i--)
        {
            ProcessNode candidate = generations[i];
            if (candidate.StartTime - ClockTolerance > at)
                continue;

            bestStarted ??= candidate;

            if (candidate.ExitTime is null || at <= candidate.ExitTime.Value + ClockTolerance)
                return candidate;
        }

        // Everything with this PID had already exited by `at`, or the event predates
        // every generation we know of. The closest generation is the best guess.
        return bestStarted ?? generations[0];
    }

    public ProcessNode? Get(ProcessKey key)
    {
        lock (_gate)
        {
            if (key.IsStrong && _byStartKey.TryGetValue(key.StartKey, out ProcessNode? byKey))
                return byKey;

            return _byPid.TryGetValue(key.Pid, out List<ProcessNode>? generations)
                ? generations.FirstOrDefault(g => g.Key == key)
                : null;
        }
    }

    public void MarkExit(ProcessKey key, DateTimeOffset when, int? exitCode)
    {
        lock (_gate)
        {
            ProcessNode? node = Get(key) ?? ResolveNodeLocked(key.Pid, when);
            if (node is null)
                return;

            node.ExitTime = when;
            node.ExitCode = exitCode;

            // Threads of a dead process must not resolve to it any more.
            foreach (uint tid in _threadOwners.Where(kv => kv.Value == node.Key).Select(kv => kv.Key).ToList())
                _threadOwners.Remove(tid);
        }
    }

    public void SetThreadOwner(uint threadId, ProcessKey owner)
    {
        if (threadId == 0) return;
        lock (_gate) _threadOwners[threadId] = owner;
    }

    public void ClearThread(uint threadId)
    {
        lock (_gate) _threadOwners.Remove(threadId);
    }

    /// <summary>
    /// Resolves an event that carries only a thread id. Falls back to
    /// <see cref="ProcessKey.None"/> rather than guessing.
    /// </summary>
    public ProcessKey ResolveByThread(uint threadId)
    {
        lock (_gate) return _threadOwners.TryGetValue(threadId, out ProcessKey k) ? k : ProcessKey.None;
    }

    public IReadOnlyList<ProcessNode> Snapshot()
    {
        lock (_gate) return _byPid.Values.SelectMany(static v => v).ToList();
    }

    public IReadOnlyList<ProcessNode> Roots()
    {
        lock (_gate)
        {
            var all = _byPid.Values.SelectMany(static v => v).ToList();
            var known = new HashSet<ProcessKey>(all.Select(static p => p.Key));
            return all.Where(p => p.ParentKey == ProcessKey.None || !known.Contains(p.ParentKey)).ToList();
        }
    }

    /// <summary>
    /// Marks <paramref name="root"/> and everything reachable from it as in scope.
    /// </summary>
    /// <returns>Number of processes newly brought into scope.</returns>
    public int MarkScope(ProcessKey root, string rootReason = "root")
    {
        lock (_gate)
        {
            ProcessNode? node = Get(root);
            if (node is null) return 0;

            int marked = 0;
            var queue = new Queue<ProcessNode>();
            if (!node.InScope)
            {
                node.InScope = true;
                node.ScopeReason = rootReason;
                marked++;
            }
            queue.Enqueue(node);

            while (queue.Count > 0)
            {
                ProcessNode current = queue.Dequeue();
                foreach (ProcessKey childKey in current.Children)
                {
                    ProcessNode? child = Get(childKey);
                    if (child is null || child.InScope) continue;
                    child.InScope = true;
                    child.ScopeReason = "descendant";
                    marked++;
                    queue.Enqueue(child);
                }
            }

            return marked;
        }
    }

    /// <summary>
    /// Brings a process into scope that the parent chain alone would have missed.
    /// </summary>
    /// <remarks>
    /// Windows breaks causality on purpose in several places: an installer asks the
    /// Service Control Manager to start a service and the new process parents to
    /// services.exe; a COM activation parents to svchost.exe or dllhost.exe; a
    /// scheduled task registered during install parents to taskeng/svchost. Without
    /// adoption those processes — often the interesting ones — sit outside the tree.
    /// </remarks>
    public bool Adopt(ProcessKey key, ProcessKey logicalParent, string reason)
    {
        lock (_gate)
        {
            ProcessNode? node = Get(key);
            if (node is null) return false;

            if (logicalParent != ProcessKey.None)
            {
                ProcessNode? parent = Get(logicalParent);
                if (parent is not null && !parent.Children.Contains(key))
                    parent.Children.Add(key);
                node.ParentKey = logicalParent;
            }

            if (node.InScope) return false;
            node.InScope = true;
            node.ScopeReason = $"adopted:{reason}";
            MarkScope(key, $"adopted:{reason}");
            return true;
        }
    }

    private void LinkToParent(ProcessNode node)
    {
        if (node.ParentKey != ProcessKey.None)
        {
            ProcessNode? parent = Get(node.ParentKey);
            if (parent is not null && !parent.Children.Contains(node.Key))
                parent.Children.Add(node.Key);
            return;
        }

        if (node.ParentPid == 0) return;

        // Resolve the parent to the generation alive when the child started.
        ProcessNode? resolved = ResolveNodeLocked(node.ParentPid, node.StartTime);
        if (resolved is null || resolved.Key == node.Key) return;

        node.ParentKey = resolved.Key;
        if (!resolved.Children.Contains(node.Key))
            resolved.Children.Add(node.Key);

        // Scope is inherited: a child of an in-scope process is in scope.
        if (resolved.InScope && !node.InScope)
        {
            node.InScope = true;
            node.ScopeReason = "descendant";
        }
    }

    private static void Merge(ProcessNode target, ProcessNode incoming)
    {
        if (string.IsNullOrEmpty(target.ImagePath) && !string.IsNullOrEmpty(incoming.ImagePath))
            target.ImagePath = incoming.ImagePath;
        target.CommandLine ??= incoming.CommandLine;
        target.WorkingDirectory ??= incoming.WorkingDirectory;
        target.UserSid ??= incoming.UserSid;
        target.UserName ??= incoming.UserName;
        target.Sha256 ??= incoming.Sha256;
        target.Signer ??= incoming.Signer;
        target.OriginId ??= incoming.OriginId;

        if (target.Signature == SignatureState.Unchecked)
            target.Signature = incoming.Signature;
        if (target.Integrity == IntegrityLevel.Unknown)
            target.Integrity = incoming.Integrity;
        if (target.SessionId == 0)
            target.SessionId = incoming.SessionId;
        if (target.ParentPid == 0)
            target.ParentPid = incoming.ParentPid;
        if (target.ParentKey == ProcessKey.None)
            target.ParentKey = incoming.ParentKey;
        if (target.StartTime == default)
            target.StartTime = incoming.StartTime;
        target.ExitTime ??= incoming.ExitTime;
        target.ExitCode ??= incoming.ExitCode;
        target.IsElevated |= incoming.IsElevated;
        target.PreExisting &= incoming.PreExisting;
    }
}
