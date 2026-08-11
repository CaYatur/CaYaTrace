namespace CaYaTrace.Core.Correlation;

/// <summary>
/// Bounded pointer-to-name cache with least-recently-used eviction.
/// </summary>
/// <remarks>
/// <para>
/// Kernel ETW identifies objects by pointer, not by name. A <c>FileIO/Write</c> event
/// carries a <c>FileObject</c>; a <c>Registry/SetValue</c> carries a key control block
/// address. The name was announced earlier, in a create or rundown event, and is never
/// repeated. Lose that announcement and the event degrades to
/// "wrote 4096 bytes to 0xFFFFCE0812A43B90", which is worthless as evidence.
/// </para>
/// <para>
/// The map is bounded because a long session on a busy machine touches millions of
/// distinct objects and an unbounded dictionary is a slow memory leak. Eviction is
/// LRU and counted: a rising <see cref="Evictions"/> alongside a rising
/// <see cref="Misses"/> is the signature of a cap set too low, and both are surfaced
/// in the session's data-quality panel rather than hidden.
/// </para>
/// </remarks>
public sealed class HandleNameMap
{
    private readonly int _capacity;
    private readonly Dictionary<ulong, LinkedListNode<Entry>> _index;
    private readonly LinkedList<Entry> _recency = new();
    private readonly object _gate = new();

    private long _hits;
    private long _misses;
    private long _evictions;

    private sealed record Entry(ulong Handle, string Name)
    {
        public string Name { get; set; } = Name;
    }

    public HandleNameMap(int capacity = 262_144)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
        _index = new Dictionary<ulong, LinkedListNode<Entry>>(Math.Min(capacity, 8192));
    }

    public long Hits => Interlocked.Read(ref _hits);
    public long Misses => Interlocked.Read(ref _misses);
    public long Evictions => Interlocked.Read(ref _evictions);

    public int Count
    {
        get { lock (_gate) return _index.Count; }
    }

    /// <summary>
    /// Fraction of lookups that resolved. Below roughly 0.95 the causal tree is
    /// missing real edges and the session should be treated as degraded.
    /// </summary>
    public double HitRate
    {
        get
        {
            long h = Hits, m = Misses;
            return h + m == 0 ? 1.0 : (double)h / (h + m);
        }
    }

    public void Set(ulong handle, string name)
    {
        if (handle == 0 || string.IsNullOrEmpty(name)) return;

        lock (_gate)
        {
            if (_index.TryGetValue(handle, out LinkedListNode<Entry>? existing))
            {
                existing.Value.Name = name;
                _recency.Remove(existing);
                _recency.AddFirst(existing);
                return;
            }

            var node = new LinkedListNode<Entry>(new Entry(handle, name));
            _recency.AddFirst(node);
            _index[handle] = node;

            while (_index.Count > _capacity)
            {
                LinkedListNode<Entry>? oldest = _recency.Last;
                if (oldest is null) break;
                _recency.RemoveLast();
                _index.Remove(oldest.Value.Handle);
                Interlocked.Increment(ref _evictions);
            }
        }
    }

    public bool TryGet(ulong handle, out string name)
    {
        name = string.Empty;
        if (handle == 0)
        {
            Interlocked.Increment(ref _misses);
            return false;
        }

        lock (_gate)
        {
            if (_index.TryGetValue(handle, out LinkedListNode<Entry>? node))
            {
                _recency.Remove(node);
                _recency.AddFirst(node);
                name = node.Value.Name;
                Interlocked.Increment(ref _hits);
                return true;
            }
        }

        Interlocked.Increment(ref _misses);
        return false;
    }

    /// <summary>
    /// Removes a mapping. Called on close/cleanup so a recycled pointer cannot
    /// resolve to the object that previously occupied that address.
    /// </summary>
    public void Remove(ulong handle)
    {
        if (handle == 0) return;
        lock (_gate)
        {
            if (!_index.Remove(handle, out LinkedListNode<Entry>? node)) return;
            _recency.Remove(node);
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _index.Clear();
            _recency.Clear();
        }
    }
}
