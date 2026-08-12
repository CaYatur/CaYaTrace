using CaYaTrace.Core.Naming;

namespace CaYaTrace.Core.Correlation;

/// <summary>
/// Turns kernel key-control-block pointers back into full registry key paths.
/// </summary>
/// <remarks>
/// <para>
/// This is the registry counterpart of <see cref="FileObjectResolver"/>, and it is the
/// step most naive ETW registry monitors skip — which is why they report
/// <c>SetValue</c> on <c>0xFFFFA80C…</c> and are useless. Kernel registry events carry a
/// KCB pointer plus a name that is <em>relative to that KCB</em>. The full path only
/// exists if you have been tracking <c>KCBCreate</c> and the rundown events that
/// enumerate every key open at session start.
/// </para>
/// <para>
/// Two independent failure modes are worth understanding, because both show up as
/// "the tool missed things":
/// </para>
/// <list type="bullet">
///   <item><description>
///     A <c>KCBCreate</c> lost to a buffer overrun means every later operation under that
///     key is unresolvable. This is why buffer sizing and the lost-event counter are
///     part of the session's quality record rather than a debug detail.
///   </description></item>
///   <item><description>
///     The provider reports that a value was set but never what it was set <em>to</em>.
///     Recovering the data is a separate job — see
///     <c>CaYaTrace.Collectors.Registry.RegistryValueCapture</c>.
///   </description></item>
/// </list>
/// </remarks>
public sealed class RegistryKeyResolver
{
    private readonly HandleNameMap _kcb;
    private readonly string? _userSidOverride;

    public RegistryKeyResolver(int capacity = 262_144, string? userSidOverride = null)
    {
        _kcb = new HandleNameMap(capacity);
        _userSidOverride = userSidOverride;
    }

    private long _absolute;
    private long _partial;

    public HandleNameMap Kcbs => _kcb;

    /// <summary>
    /// Fraction of operations resolved to a full hive-rooted key path.
    /// </summary>
    /// <remarks>
    /// A relative fragment such as <c>Software\Example</c> counts against this even though
    /// <see cref="Resolve"/> returns it: the fragment is worth showing next to its
    /// operation, but it cannot be searched, compared across machines, or acted on by a
    /// removal plan, so treating it as a success would overstate what the session holds.
    /// </remarks>
    /// <remarks>
    /// <para>
    /// Reads are excluded, and that is the point of the split. A read that could not be
    /// named says something looked at something; a <em>change</em> that could not be named is
    /// evidence of what a program did, gone. Counting them together produced a session
    /// banner reading "59.7% of registry operations unresolved" on a recording where
    /// every change had in fact been named — alarming, and about the wrong thing.
    /// </para>
    /// <para>
    /// A relative fragment such as <c>Software\Example</c> still counts against this even
    /// though <see cref="Resolve"/> returns it: the fragment is worth showing next to its
    /// operation, but it cannot be searched, compared across machines, or acted on by a
    /// removal plan.
    /// </para>
    /// </remarks>
    public double HitRate
    {
        get
        {
            long absolute = Interlocked.Read(ref _absolute);
            long partial = Interlocked.Read(ref _partial);
            return absolute + partial == 0 ? 1.0 : (double)absolute / (absolute + partial);
        }
    }

    /// <summary>The same measure over read operations, reported separately.</summary>
    public double ReadHitRate
    {
        get
        {
            long absolute = Interlocked.Read(ref _readAbsolute);
            long partial = Interlocked.Read(ref _readPartial);
            return absolute + partial == 0 ? 1.0 : (double)absolute / (absolute + partial);
        }
    }

    private long _readAbsolute;
    private long _readPartial;

    /// <summary>Records a resolved read, which is counted apart from changes.</summary>
    public void NoteReadResolved() => Interlocked.Increment(ref _readAbsolute);

    /// <summary>Records a read that never resolved to a full path.</summary>
    public void NoteReadPartial() => Interlocked.Increment(ref _readPartial);

    /// <summary>Operations that resolved only to a relative fragment.</summary>
    public long PartiallyResolved => Interlocked.Read(ref _partial);

    /// <summary>
    /// Records the full path announced by <c>KCBCreate</c> or by a rundown event.
    /// </summary>
    public void NoteKcb(ulong keyHandle, string? fullKeyName)
    {
        if (keyHandle == 0 || string.IsNullOrEmpty(fullKeyName)) return;
        string normalized = RegistryPath.Normalize(fullKeyName, _userSidOverride);
        if (normalized.Length != 0) _kcb.Set(keyHandle, normalized);
    }

    /// <summary>Drops a mapping when the kernel tears the control block down.</summary>
    public void NoteKcbDelete(ulong keyHandle)
    {
        if (keyHandle != 0) _kcb.Remove(keyHandle);
    }

    /// <summary>
    /// Resolves an operation to a full key path.
    /// </summary>
    /// <param name="keyHandle">KCB pointer from the event.</param>
    /// <param name="relativeName">
    /// Name carried by the event. May be empty (operation on the KCB itself), relative
    /// to the KCB (the common case), or already absolute on newer builds.
    /// </param>
    /// <returns>Normalized path, or empty when the KCB could not be resolved.</returns>
    public string Resolve(ulong keyHandle, string? relativeName)
    {
        // Some builds hand out an absolute name; take it and skip the KCB entirely.
        if (!string.IsNullOrEmpty(relativeName) && IsAbsolute(relativeName))
        {
            Interlocked.Increment(ref _absolute);
            return RegistryPath.Normalize(relativeName, _userSidOverride);
        }

        if (keyHandle != 0 && _kcb.TryGet(keyHandle, out string basePath))
        {
            Interlocked.Increment(ref _absolute);
            if (string.IsNullOrEmpty(relativeName)) return basePath;
            string tail = relativeName.Trim('\\');
            return tail.Length == 0 ? basePath : $"{basePath}\\{tail}";
        }

        // Better to return a fragment than nothing — it still tells the analyst which
        // value moved — but it is counted as partial, not as a resolution.
        Interlocked.Increment(ref _partial);
        return string.IsNullOrEmpty(relativeName)
            ? string.Empty
            : RegistryPath.Normalize(relativeName, _userSidOverride);
    }

    /// <summary>
    /// Resolves without recording a measurement, for callers that will retry once the
    /// key control block has been announced.
    /// </summary>
    public bool TryResolve(ulong keyHandle, string? relativeName, out string full)
    {
        full = string.Empty;
        if (!string.IsNullOrEmpty(relativeName) && IsAbsolute(relativeName))
        {
            full = RegistryPath.Normalize(relativeName, _userSidOverride);
            return true;
        }

        if (keyHandle == 0 || !_kcb.TryGet(keyHandle, out string basePath)) return false;

        string tail = relativeName?.Trim('\\') ?? string.Empty;
        full = tail.Length == 0 ? basePath : $"{basePath}\\{tail}";
        return true;
    }

    /// <summary>Records that an operation resolved, for callers using <see cref="TryResolve"/>.</summary>
    public void NoteResolved() => Interlocked.Increment(ref _absolute);

    /// <summary>Records that an operation never resolved to a full path.</summary>
    public void NotePartial() => Interlocked.Increment(ref _partial);

    /// <summary>
    /// Applies a key rename so operations under the old KCB report the new path.
    /// </summary>
    public string ApplyRename(ulong keyHandle, string newName)
    {
        string oldPath = Resolve(keyHandle, null);
        if (keyHandle == 0) return oldPath;

        string normalized = IsAbsolute(newName)
            ? RegistryPath.Normalize(newName, _userSidOverride)
            : RebaseSibling(oldPath, newName);

        if (normalized.Length != 0) _kcb.Set(keyHandle, normalized);
        return oldPath;
    }

    public void Clear() => _kcb.Clear();

    /// <summary>
    /// A rename supplies only the new leaf name, so the new path is the old path's
    /// parent plus that leaf.
    /// </summary>
    private static string RebaseSibling(string oldPath, string newLeaf)
    {
        if (string.IsNullOrEmpty(oldPath)) return newLeaf;
        int slash = oldPath.LastIndexOf('\\');
        return slash < 0 ? newLeaf : $"{oldPath[..slash]}\\{newLeaf.Trim('\\')}";
    }

    private static bool IsAbsolute(string name)
        => name.StartsWith(@"\REGISTRY", StringComparison.OrdinalIgnoreCase)
           || name.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase)
           || name.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase)
           || name.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase)
           || name.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase)
           || name.StartsWith("HKCR\\", StringComparison.OrdinalIgnoreCase);
}
