using CaYaTrace.Core.Naming;

namespace CaYaTrace.Core.Correlation;

/// <summary>
/// Turns kernel file-object pointers back into file paths.
/// </summary>
/// <remarks>
/// <para>
/// The kernel file provider announces a name once, on create or during rundown, and
/// thereafter refers to the object only by pointer. Two different pointers exist and
/// both matter:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>FileObject</b> — per-open handle. Valid from create until cleanup, and
///     recycled immediately afterwards, so it must be released on close or a later
///     unrelated file inherits the name.
///   </description></item>
///   <item><description>
///     <b>FileKey</b> — per-file control block. Shared by every open of the same file
///     and announced by <c>NameCreate</c> and rundown events. Outlives any single
///     handle, which makes it the more durable of the two.
///   </description></item>
/// </list>
/// <para>
/// Lookup tries FileObject first because it is exact for the open in question, then
/// falls back to FileKey. Both maps are bounded independently: FileKey entries are
/// worth keeping far longer than FileObject entries.
/// </para>
/// </remarks>
public sealed class FileObjectResolver
{
    private readonly HandleNameMap _byFileObject;
    private readonly HandleNameMap _byFileKey;
    private readonly PathNormalizer _paths;

    public FileObjectResolver(PathNormalizer paths, int fileObjectCapacity = 131_072, int fileKeyCapacity = 262_144)
    {
        _paths = paths;
        _byFileObject = new HandleNameMap(fileObjectCapacity);
        _byFileKey = new HandleNameMap(fileKeyCapacity);
    }

    public HandleNameMap FileObjects => _byFileObject;
    public HandleNameMap FileKeys => _byFileKey;

    private long _named;
    private long _unnamed;

    /// <summary>
    /// Fraction of operations that produced a usable path.
    /// </summary>
    /// <remarks>
    /// Measured on the <em>outcome</em>, not on internal map lookups. Counting map hits
    /// understated this badly: when the event already carries a resolved name we return
    /// it without consulting either map, so a successful resolution registered as
    /// neither a hit nor a miss while every fallback attempt registered as a miss. The
    /// result was a session reporting "99.8% of file operations unresolved" while the
    /// stored evidence held fully resolved paths — a metric that would have sent an
    /// analyst hunting a non-existent collection failure.
    /// </remarks>
    public double HitRate
    {
        get
        {
            long named = Interlocked.Read(ref _named);
            long unnamed = Interlocked.Read(ref _unnamed);
            return named + unnamed == 0 ? 1.0 : (double)named / (named + unnamed);
        }
    }

    /// <summary>Operations whose object could not be named, and were therefore dropped.</summary>
    public long Unresolved => Interlocked.Read(ref _unnamed);

    /// <summary>
    /// Resolves without recording a measurement, for callers that will retry once the
    /// end-of-session rundown has announced the missing names. Counting a failure here
    /// as well as on the retry would report every deferred operation as two failures.
    /// </summary>
    public bool TryResolve(ulong fileObject, ulong fileKey, string? inlineName, out string path)
    {
        if (!string.IsNullOrEmpty(inlineName))
        {
            string direct = _paths.Normalize(inlineName);
            if (direct.Length > 0 && !LooksLikeBarePointer(direct)) { path = direct; return true; }
        }

        if (fileObject != 0 && _byFileObject.TryGet(fileObject, out path)) return true;
        if (fileKey != 0 && _byFileKey.TryGet(fileKey, out path)) return true;

        path = string.Empty;
        return false;
    }

    public void NoteResolved() => Interlocked.Increment(ref _named);

    public void NoteUnresolved() => Interlocked.Increment(ref _unnamed);

    /// <summary>
    /// Reads are measured apart from changes; see
    /// <see cref="RegistryKeyResolver.HitRate"/> for why.
    /// </summary>
    public double ReadHitRate
    {
        get
        {
            long named = Interlocked.Read(ref _readNamed);
            long unnamed = Interlocked.Read(ref _readUnnamed);
            return named + unnamed == 0 ? 1.0 : (double)named / (named + unnamed);
        }
    }

    private long _readNamed;
    private long _readUnnamed;

    public void NoteReadResolved() => Interlocked.Increment(ref _readNamed);

    public void NoteReadUnresolved() => Interlocked.Increment(ref _readUnnamed);

    /// <summary>Records the name announced by a create/open event.</summary>
    public void NoteOpen(ulong fileObject, ulong fileKey, string? name)
    {
        if (string.IsNullOrEmpty(name)) return;
        string normalized = _paths.Normalize(name);
        if (normalized.Length == 0) return;

        if (fileObject != 0) _byFileObject.Set(fileObject, normalized);
        if (fileKey != 0) _byFileKey.Set(fileKey, normalized);
    }

    /// <summary>
    /// Records a name announced by <c>NameCreate</c> or by the rundown that fires when a
    /// session starts. Rundown is what lets us resolve writes to files that were
    /// already open before monitoring began.
    /// </summary>
    public void NoteName(ulong fileKey, string? name)
    {
        if (fileKey == 0 || string.IsNullOrEmpty(name)) return;
        string normalized = _paths.Normalize(name);
        if (normalized.Length != 0) _byFileKey.Set(fileKey, normalized);
    }

    /// <summary>
    /// Releases a per-handle mapping on cleanup/close. The FileKey mapping is kept:
    /// the file still exists and other handles may reference it.
    /// </summary>
    public void NoteClose(ulong fileObject)
    {
        if (fileObject != 0) _byFileObject.Remove(fileObject);
    }

    /// <summary>Drops a FileKey mapping when the kernel tears down the control block.</summary>
    public void NoteNameDelete(ulong fileKey)
    {
        if (fileKey != 0) _byFileKey.Remove(fileKey);
    }

    /// <summary>
    /// Resolves an operation to a path. <paramref name="inlineName"/> is used directly
    /// when the event already carried one, which some newer providers do.
    /// </summary>
    public string Resolve(ulong fileObject, ulong fileKey, string? inlineName = null)
    {
        // The provider sometimes carries the name already, resolved by the trace
        // reader's own bookkeeping. That is a successful resolution and counts as one.
        if (!string.IsNullOrEmpty(inlineName))
        {
            string direct = _paths.Normalize(inlineName);
            if (direct.Length > 0 && !LooksLikeBarePointer(direct))
            {
                Interlocked.Increment(ref _named);
                return direct;
            }
        }

        if (fileObject != 0 && _byFileObject.TryGet(fileObject, out string byObject))
        {
            Interlocked.Increment(ref _named);
            return byObject;
        }

        if (fileKey != 0 && _byFileKey.TryGet(fileKey, out string byKey))
        {
            Interlocked.Increment(ref _named);
            return byKey;
        }

        Interlocked.Increment(ref _unnamed);
        return string.Empty;
    }

    /// <summary>
    /// Applies a rename so subsequent operations on the same object report the new
    /// path. Returns the old path for the observation's <c>OldValue</c>.
    /// </summary>
    public string ApplyRename(ulong fileObject, ulong fileKey, string newName)
    {
        string oldPath = Resolve(fileObject, fileKey);
        string normalized = _paths.Normalize(newName);
        if (normalized.Length == 0) return oldPath;

        if (fileObject != 0) _byFileObject.Set(fileObject, normalized);
        if (fileKey != 0) _byFileKey.Set(fileKey, normalized);
        return oldPath;
    }

    public void Clear()
    {
        _byFileObject.Clear();
        _byFileKey.Clear();
    }

    /// <summary>
    /// Some providers put a formatted pointer in the name field when the real name is
    /// unavailable. Treating that as a path would poison the artifact list.
    /// </summary>
    private static bool LooksLikeBarePointer(string value)
        => value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
           && value.Length <= 20
           && !value.Contains('\\');
}
