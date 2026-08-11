using System.Diagnostics;
using System.Globalization;
using System.Text;
using CaYaTrace.Core.Naming;
using Microsoft.Win32;

namespace CaYaTrace.Collectors.Etw;

/// <summary>
/// Recovers the data behind a registry write, which ETW does not report.
/// </summary>
/// <remarks>
/// <para>
/// <c>Microsoft-Windows-Kernel-Registry</c> and the classic kernel registry provider both
/// report <em>that</em> a value was set — the key, the value name, the status — and never
/// what it was set to. Answering "it changed the value from 0 to 1", which is the
/// question an analyst actually has, requires reading the value back.
/// </para>
/// <para><b>What "before" really means here.</b> By the time the event reaches us the
/// write has already happened, so the previous data cannot be read; it is gone. "Before"
/// therefore comes from one of two places, in order of preference:</para>
/// <list type="number">
///   <item><description>
///     A value this class already observed earlier in the session — exact, because we
///     recorded it ourselves.
///   </description></item>
///   <item><description>
///     The pre-session baseline snapshot, for keys that were captured up front.
///   </description></item>
/// </list>
/// <para>
/// When neither exists, <c>OldValue</c> is null and the UI shows the write as an
/// establishment rather than a transition. Inventing a "before" would be worse than
/// admitting there isn't one.
/// </para>
/// <para><b>Why this is rate-limited.</b> It runs on the ETW callback thread, where any
/// stall causes the kernel to drop events across every provider at once. A read budget
/// bounds that exposure: past the budget, capture is skipped and counted rather than
/// allowed to slow the pipeline.</para>
/// </remarks>
public sealed class RegistryValueCapture
{
    /// <summary>
    /// Reads permitted per second. Sized to comfortably cover the write rate of an
    /// installer while capping worst-case time spent inside the callback.
    /// </summary>
    private const int ReadsPerSecondBudget = 4_000;

    /// <summary>Longest string retained. Some values hold megabytes of binary data.</summary>
    private const int MaxValueLength = 4096;

    private readonly Dictionary<string, string?> _lastKnown = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private readonly Stopwatch _window = Stopwatch.StartNew();

    private int _readsThisWindow;
    private long _skipped;
    private long _captured;
    private long _seeded;

    public long Captured => Interlocked.Read(ref _captured);

    /// <summary>Writes whose data could not be captured because the budget was spent.</summary>
    public long Skipped => Interlocked.Read(ref _skipped);

    /// <summary>Values pre-loaded from the baseline so their first write reads as a transition.</summary>
    public long Seeded => Interlocked.Read(ref _seeded);

    /// <summary>
    /// Seeds a known value so a later write to it is reported as a transition.
    /// </summary>
    /// <remarks>
    /// Without seeding, the <em>first</em> write to any value in a session has no
    /// "before" — and for an installer that is most writes, which would make the
    /// "changed from 0 to 1" reporting mostly absent exactly where it matters. The
    /// baseline snapshot already reads the high-value keys, so feeding those rows in
    /// here costs nothing and closes the gap.
    /// </remarks>
    public void Seed(string keyPath, string? valueName, string? data)
    {
        lock (_gate) _lastKnown[RegistryPath.JoinValue(keyPath, valueName)] = data;
        Interlocked.Increment(ref _seeded);
    }

    /// <summary>
    /// Returns the value before and after a write. <c>Before</c> is null when this value
    /// has not been seen previously in the session.
    /// </summary>
    public (string? Before, string? After) Capture(string keyPath, string? valueName)
    {
        string slot = RegistryPath.JoinValue(keyPath, valueName);

        string? before;
        lock (_gate) _lastKnown.TryGetValue(slot, out before);

        if (!TryConsumeBudget())
        {
            Interlocked.Increment(ref _skipped);
            return (before, null);
        }

        string? after = ReadValue(keyPath, valueName);
        lock (_gate) _lastKnown[slot] = after;
        Interlocked.Increment(ref _captured);

        // A write that did not change anything is noise; report it as such by
        // collapsing the transition rather than showing "1 -> 1".
        return before is not null && before == after ? (null, after) : (before, after);
    }

    /// <summary>Reads a value without recording a transition. Used for deletes.</summary>
    public string? ReadCurrent(string keyPath, string? valueName)
    {
        lock (_gate)
        {
            if (_lastKnown.TryGetValue(RegistryPath.JoinValue(keyPath, valueName), out string? cached))
                return cached;
        }
        return TryConsumeBudget() ? ReadValue(keyPath, valueName) : null;
    }

    private bool TryConsumeBudget()
    {
        lock (_gate)
        {
            if (_window.ElapsedMilliseconds >= 1000)
            {
                _window.Restart();
                _readsThisWindow = 0;
            }

            if (_readsThisWindow >= ReadsPerSecondBudget) return false;
            _readsThisWindow++;
            return true;
        }
    }

    private string? ReadValue(string keyPath, string? valueName)
    {
        (string hive, string subKey) = RegistryPath.Split(keyPath);
        RegistryHive? mapped = MapHive(hive);
        if (mapped is null) return null;

        try
        {
            // 64-bit view: the redirected 32-bit view has its own path spelling
            // (WOW6432Node) that arrives as a distinct key, so opening the native
            // view here is correct rather than a limitation.
            using RegistryKey root = RegistryKey.OpenBaseKey(mapped.Value, RegistryView.Registry64);
            using RegistryKey? key = root.OpenSubKey(subKey, writable: false);
            if (key is null) return null;

            object? raw = key.GetValue(
                string.IsNullOrEmpty(valueName) ? null : valueName,
                defaultValue: null,
                RegistryValueOptions.DoNotExpandEnvironmentNames);

            return raw is null ? null : Format(raw, key.GetValueKind(string.IsNullOrEmpty(valueName) ? null : valueName));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException
                                       or IOException or ObjectDisposedException or ArgumentException)
        {
            // Protected keys (SAM, parts of SECURITY) and keys deleted between the
            // event and the read both land here. Neither is worth a fault report.
            return null;
        }
    }

    private static string Format(object raw, RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.Binary when raw is byte[] bytes => FormatBinary(bytes),
        RegistryValueKind.MultiString when raw is string[] items => string.Join(" | ", items).Truncate(MaxValueLength),
        RegistryValueKind.DWord => Convert.ToInt64(raw, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
        RegistryValueKind.QWord => Convert.ToInt64(raw, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
        _ => (raw as string ?? raw.ToString() ?? string.Empty).Truncate(MaxValueLength),
    };

    private static string FormatBinary(byte[] bytes)
    {
        int shown = Math.Min(bytes.Length, 256);
        var sb = new StringBuilder(shown * 2 + 32);
        for (int i = 0; i < shown; i++) sb.Append(bytes[i].ToString("x2", CultureInfo.InvariantCulture));
        if (bytes.Length > shown)
            sb.Append(CultureInfo.InvariantCulture, $"… ({bytes.Length} bytes total)");
        return sb.ToString();
    }

    private static RegistryHive? MapHive(string hive) => hive.ToUpperInvariant() switch
    {
        "HKLM" => RegistryHive.LocalMachine,
        "HKCU" => RegistryHive.CurrentUser,
        "HKCR" => RegistryHive.ClassesRoot,
        "HKU" => RegistryHive.Users,
        "HKCC" => RegistryHive.CurrentConfig,
        _ => null,
    };

    /// <summary>Short status line for the session's data-quality record.</summary>
    public string? Summarize()
        => Skipped == 0
            ? null
            : $"{Skipped} registry writes recorded without their data because the read budget was exhausted";
}

internal static class StringTruncateExtensions
{
    public static string Truncate(this string value, int max)
        => value.Length <= max ? value : value[..max] + "…";
}
