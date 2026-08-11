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

    public HandleNameMap Kcbs => _kcb;

    public double HitRate => _kcb.HitRate;

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
            return RegistryPath.Normalize(relativeName, _userSidOverride);

        bool haveBase = keyHandle != 0 && _kcb.TryGet(keyHandle, out string basePath);
        if (!haveBase)
        {
            // Better to return a partial answer than nothing: a relative name still
            // tells the analyst which value moved, and the UI marks it unresolved.
            return string.IsNullOrEmpty(relativeName)
                ? string.Empty
                : RegistryPath.Normalize(relativeName, _userSidOverride);
        }

        _kcb.TryGet(keyHandle, out basePath);

        if (string.IsNullOrEmpty(relativeName))
            return basePath;

        string tail = relativeName.Trim('\\');
        return tail.Length == 0 ? basePath : $"{basePath}\\{tail}";
    }

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
