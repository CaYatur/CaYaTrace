using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace CaYaTrace.Core.Model;

/// <summary>
/// Stable identity for a single process instance.
/// </summary>
/// <remarks>
/// Raw PIDs are unusable as identity: Windows recycles them aggressively, and a
/// busy installer run can burn through the same PID several times in one session.
/// Keying a causal tree on a raw PID silently merges unrelated subtrees, which is
/// the single most common way a monitor of this kind produces confident nonsense.
///
/// The preferred discriminator is the kernel's process start key
/// (<c>ProcessSequenceNumber</c> on Microsoft-Windows-Kernel-Process, Win10 1809+),
/// which is monotonic and never reused for the life of a boot. When it is not
/// available — older builds, synthesized events, snapshot-derived processes — we
/// fall back to (PID, creation time), which is unique in practice because PID
/// reuse within the same 100ns tick does not happen.
/// </remarks>
public readonly struct ProcessKey : IEquatable<ProcessKey>, IComparable<ProcessKey>
{
    /// <summary>Sentinel for "no process" / kernel / unresolved actor.</summary>
    public static readonly ProcessKey None = default;

    /// <summary>OS process id. Informational once <see cref="StartKey"/> is present.</summary>
    public uint Pid { get; }

    /// <summary>Kernel process start key. Zero when the OS did not supply one.</summary>
    public ulong StartKey { get; }

    /// <summary>Process creation time in UTC ticks. Fallback discriminator.</summary>
    public long CreateTimeTicks { get; }

    public ProcessKey(uint pid, ulong startKey, long createTimeTicks)
    {
        Pid = pid;
        StartKey = startKey;
        CreateTimeTicks = createTimeTicks;
    }

    public static ProcessKey FromStartKey(uint pid, ulong startKey, DateTimeOffset createTime)
        => new(pid, startKey, createTime.UtcTicks);

    public static ProcessKey FromCreateTime(uint pid, DateTimeOffset createTime)
        => new(pid, 0, createTime.UtcTicks);

    public bool IsNone => Pid == 0 && StartKey == 0 && CreateTimeTicks == 0;

    /// <summary>True when this key carries a kernel-supplied start key.</summary>
    public bool IsStrong => StartKey != 0;

    /// <summary>
    /// Two keys are the same process when both carry start keys and those match.
    /// Otherwise we compare the (PID, creation time) pair. A strong key and a weak
    /// key are compared on the weak fields so that a snapshot-derived process can
    /// still unify with the ETW-derived one for the same PID.
    /// </summary>
    public bool Equals(ProcessKey other)
    {
        if (StartKey != 0 && other.StartKey != 0)
            return StartKey == other.StartKey;

        if (Pid != other.Pid)
            return false;

        // One side has no creation time (e.g. an event seen before the rundown
        // completed). PID alone is the best available answer.
        if (CreateTimeTicks == 0 || other.CreateTimeTicks == 0)
            return true;

        return CreateTimeTicks == other.CreateTimeTicks;
    }

    public override bool Equals([NotNullWhen(true)] object? obj) => obj is ProcessKey k && Equals(k);

    /// <summary>
    /// Hashing deliberately uses only <see cref="Pid"/>. <see cref="Equals"/> can
    /// unify keys that differ in <see cref="StartKey"/> or <see cref="CreateTimeTicks"/>,
    /// so those fields must not contribute to the hash or equal keys could land in
    /// different buckets. PID is the one field every equal pair shares.
    /// </summary>
    public override int GetHashCode() => Pid.GetHashCode();

    public int CompareTo(ProcessKey other)
    {
        if (StartKey != 0 && other.StartKey != 0)
            return StartKey.CompareTo(other.StartKey);
        int c = Pid.CompareTo(other.Pid);
        return c != 0 ? c : CreateTimeTicks.CompareTo(other.CreateTimeTicks);
    }

    public static bool operator ==(ProcessKey a, ProcessKey b) => a.Equals(b);
    public static bool operator !=(ProcessKey a, ProcessKey b) => !a.Equals(b);

    /// <summary>
    /// Round-trippable identity string used in storage, exports, and removal packages.
    /// Strong keys serialize as <c>k:&lt;hex&gt;:&lt;pid&gt;</c>; weak keys as
    /// <c>p:&lt;pid&gt;:&lt;ticks&gt;</c>.
    /// </summary>
    public override string ToString()
        => IsNone
            ? "-"
            : StartKey != 0
                ? string.Create(CultureInfo.InvariantCulture, $"k:{StartKey:x}:{Pid}")
                : string.Create(CultureInfo.InvariantCulture, $"p:{Pid}:{CreateTimeTicks}");

    public static bool TryParse(string? text, out ProcessKey key)
    {
        key = None;
        if (string.IsNullOrEmpty(text) || text == "-")
            return text == "-";

        string[] parts = text.Split(':');
        if (parts.Length != 3)
            return false;

        switch (parts[0])
        {
            case "k":
                if (ulong.TryParse(parts[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong sk)
                    && uint.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out uint kpid))
                {
                    key = new ProcessKey(kpid, sk, 0);
                    return true;
                }
                return false;

            case "p":
                if (uint.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out uint ppid)
                    && long.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out long ticks))
                {
                    key = new ProcessKey(ppid, 0, ticks);
                    return true;
                }
                return false;

            default:
                return false;
        }
    }
}
