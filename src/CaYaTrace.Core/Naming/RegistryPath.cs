using System.Security.Principal;

namespace CaYaTrace.Core.Naming;

/// <summary>
/// Canonicalizes the three different ways Windows spells a registry key.
/// </summary>
/// <remarks>
/// The kernel emits native paths (<c>\REGISTRY\MACHINE\SOFTWARE\...</c>), the Win32 API
/// and <c>reg.exe</c> use hive abbreviations (<c>HKLM\SOFTWARE\...</c>), and .reg files use
/// long names (<c>HKEY_LOCAL_MACHINE\SOFTWARE\...</c>). We settle on the abbreviated form
/// everywhere internally and expand to the long form only when writing .reg files.
///
/// Per-user hives get special treatment: a key under <c>\REGISTRY\USER\S-1-5-21-…-1001</c>
/// is folded to <c>HKCU</c> when the SID is the session user, because a removal package
/// built here must apply to a different user account on the target machine.
/// </remarks>
public static class RegistryPath
{
    private const string NativeMachine = @"\REGISTRY\MACHINE";
    private const string NativeUser = @"\REGISTRY\USER";
    private const string NativeRoot = @"\REGISTRY";
    private const string NativeSilo = @"\REGISTRY\WC";

    private static readonly Lazy<string?> CurrentUserSid = new(() =>
    {
        try { return WindowsIdentity.GetCurrent().User?.Value; }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    });

    /// <summary>
    /// Reduces any spelling to the canonical abbreviated form. Returns the trimmed
    /// input when the prefix is not recognised, so unusual hives stay visible rather
    /// than being silently dropped.
    /// </summary>
    /// <param name="userSidOverride">
    /// SID to treat as "the current user" when folding <c>\REGISTRY\USER\&lt;sid&gt;</c> to
    /// <c>HKCU</c>. Supplied when normalizing evidence captured on another machine.
    /// </param>
    public static string Normalize(string? raw, string? userSidOverride = null)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;

        string path = raw.Trim().TrimEnd('\\');
        if (path.Length == 0) return string.Empty;

        // Long Win32 names first — cheapest to detect.
        foreach ((string longName, string abbrev) in LongNames)
        {
            if (path.StartsWith(longName, StringComparison.OrdinalIgnoreCase)
                && (path.Length == longName.Length || path[longName.Length] == '\\'))
            {
                return abbrev + path[longName.Length..];
            }
        }

        if (!path.StartsWith(NativeRoot, StringComparison.OrdinalIgnoreCase))
            return path;

        // Windows may present the registry through a container silo namespace:
        // \REGISTRY\WC\Silo<guid>user_sid\Software\... rather than
        // \REGISTRY\USER\<sid>\Software\... . Observed on Windows 11 26H1, where the
        // per-user hive of an isolated app arrives in this form. Left untranslated it
        // produces paths that look absolute but match nothing, so a removal plan built
        // from them would silently target keys that do not exist.
        if (path.StartsWith(NativeSilo, StringComparison.OrdinalIgnoreCase)
            && (path.Length == NativeSilo.Length || path[NativeSilo.Length] == '\\'))
        {
            string rest = path[NativeSilo.Length..].TrimStart('\\');
            if (rest.Length == 0) return "HKLM";

            int slash = rest.IndexOf('\\');
            string silo = slash < 0 ? rest : rest[..slash];
            string tail = slash < 0 ? string.Empty : rest[slash..];

            // The silo segment carries the hive it stands in for as a suffix.
            if (silo.EndsWith("user_sid", StringComparison.OrdinalIgnoreCase)) return "HKCU" + tail;
            if (silo.EndsWith("user", StringComparison.OrdinalIgnoreCase)) return "HKCU" + tail;
            if (silo.EndsWith("machine", StringComparison.OrdinalIgnoreCase)) return "HKLM" + tail;

            // An unrecognised silo is kept verbatim rather than guessed at: a wrong
            // hive is worse than an obviously unresolved one.
            return path;
        }

        if (path.StartsWith(NativeMachine, StringComparison.OrdinalIgnoreCase)
            && (path.Length == NativeMachine.Length || path[NativeMachine.Length] == '\\'))
        {
            return "HKLM" + path[NativeMachine.Length..];
        }

        if (path.StartsWith(NativeUser, StringComparison.OrdinalIgnoreCase)
            && (path.Length == NativeUser.Length || path[NativeUser.Length] == '\\'))
        {
            string rest = path[NativeUser.Length..].TrimStart('\\');
            if (rest.Length == 0) return "HKU";

            int slash = rest.IndexOf('\\');
            string sid = slash < 0 ? rest : rest[..slash];
            string tail = slash < 0 ? string.Empty : rest[slash..];

            // The _Classes companion hive is a separate SID-suffixed hive; fold it
            // to HKCU\Software\Classes so it lines up with the Win32 view.
            bool classes = sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase);
            if (classes) sid = sid[..^8];

            string? me = userSidOverride ?? CurrentUserSid.Value;
            string root = me is not null && string.Equals(sid, me, StringComparison.OrdinalIgnoreCase)
                ? "HKCU"
                : $@"HKU\{sid}";

            return classes ? $@"{root}\Software\Classes{tail}" : root + tail;
        }

        return path;
    }

    /// <summary>Expands the abbreviated form to the long form used by .reg files.</summary>
    public static string ToLongForm(string? normalized)
    {
        if (string.IsNullOrEmpty(normalized)) return string.Empty;
        foreach ((string longName, string abbrev) in LongNames)
        {
            if (normalized.StartsWith(abbrev, StringComparison.OrdinalIgnoreCase)
                && (normalized.Length == abbrev.Length || normalized[abbrev.Length] == '\\'))
            {
                return longName + normalized[abbrev.Length..];
            }
        }
        return normalized;
    }

    /// <summary>Splits a normalized path into its hive and the remainder.</summary>
    public static (string Hive, string SubKey) Split(string? normalized)
    {
        if (string.IsNullOrEmpty(normalized)) return (string.Empty, string.Empty);
        int slash = normalized.IndexOf('\\');
        return slash < 0
            ? (normalized, string.Empty)
            : (normalized[..slash], normalized[(slash + 1)..]);
    }

    /// <summary>
    /// True when the key lives under a 32-bit redirection node. Two keys that differ
    /// only by <c>WOW6432Node</c> are the same logical setting seen through different
    /// registry views, and comparison across machines should treat them as such.
    /// </summary>
    /// <summary>
    /// Rewrites a numbered control set to <c>CurrentControlSet</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Necessary because the two halves of this tool see different spellings of the same
    /// key. Kernel events report the real path — <c>HKLM\SYSTEM\ControlSet001\Services\…</c> —
    /// while every rule anyone writes, and every path a person types, says
    /// <c>CurrentControlSet</c>. A rule table written the readable way matches nothing at all
    /// against real evidence.
    /// </para>
    /// <para>
    /// This has already caused one shipped defect: the removal policy's protected-service
    /// list matched no service on the machine, because the list said
    /// <c>CurrentControlSet</c> and every observation said <c>ControlSet001</c>. It lives here
    /// rather than in either caller so there is one answer to the question.
    /// </para>
    /// </remarks>
    public static string CanonicalizeControlSet(string? normalized)
    {
        if (normalized is null) return string.Empty;

        const string prefix = @"HKLM\SYSTEM\ControlSet";
        if (!normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return normalized;

        int i = prefix.Length;
        while (i < normalized.Length && char.IsAsciiDigit(normalized[i])) i++;

        // Must be digits followed by a separator or the end, so "ControlSetFoo" is left
        // alone rather than silently rewritten.
        if (i == prefix.Length) return normalized;
        if (i < normalized.Length && normalized[i] != '\\') return normalized;

        return @"HKLM\SYSTEM\CurrentControlSet" + normalized[i..];
    }

    public static bool IsWow64Redirected(string? normalized)
        => normalized is not null
           && normalized.Contains(@"\WOW6432Node", StringComparison.OrdinalIgnoreCase);

    /// <summary>Strips WOW6432Node so 32-bit and 64-bit views of a key unify.</summary>
    public static string StripWow64(string? normalized)
        => string.IsNullOrEmpty(normalized)
            ? string.Empty
            : normalized
                .Replace(@"\WOW6432Node\", @"\", StringComparison.OrdinalIgnoreCase)
                .TrimEnd('\\')
                .Replace(@"\WOW6432Node", string.Empty, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Joins a key path and a value name into the single string used as an
    /// observation target. The separator is <c>::</c> because a value name may legally
    /// contain a backslash.
    /// </summary>
    public static string JoinValue(string keyPath, string? valueName)
        => string.IsNullOrEmpty(valueName) ? keyPath : $"{keyPath}::{valueName}";

    public static (string Key, string? Value) SplitValue(string target)
    {
        int idx = target.IndexOf("::", StringComparison.Ordinal);
        return idx < 0 ? (target, null) : (target[..idx], target[(idx + 2)..]);
    }

    private static readonly (string LongName, string Abbrev)[] LongNames =
    {
        ("HKEY_LOCAL_MACHINE", "HKLM"),
        ("HKEY_CURRENT_USER", "HKCU"),
        ("HKEY_CLASSES_ROOT", "HKCR"),
        ("HKEY_USERS", "HKU"),
        ("HKEY_CURRENT_CONFIG", "HKCC"),
        ("HKEY_PERFORMANCE_DATA", "HKPD"),
    };
}
