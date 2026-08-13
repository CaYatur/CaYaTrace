using System.Runtime.InteropServices;

namespace CaYaTrace.Collectors.Network;

/// <summary>
/// Answers "which process owns this local TCP port, right now".
/// </summary>
/// <remarks>
/// <para>
/// The intercepting proxy sees nothing but a loopback socket, so the client's ephemeral
/// port is its only link back to the program that made the request. The flow table can
/// usually supply that from kernel events, but only for ports it happened to observe —
/// and a connection that opened before the trace, or between two polls, is not one of
/// them.
/// </para>
/// <para>
/// This asks Windows instead. While the proxy is handling a connection that connection is
/// established, so the connection table has an authoritative answer.
/// </para>
/// <para>
/// It matters beyond attribution. With interception on, the system proxy routes <em>every</em>
/// program's traffic through the proxy, and a session recorded to watch one program must
/// not keep the operator's browser and mail. Deciding that needs the owner, and "unknown"
/// meant "keep it" — measured, and it captured traffic that had nothing to do with the
/// subject.
/// </para>
/// </remarks>
internal static class LocalPortOwner
{
    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;

    /// <summary>
    /// How long a lookup is reused.
    /// </summary>
    /// <remarks>
    /// The table costs a syscall and a few hundred rows to walk, and a busy page can open
    /// dozens of connections a second. A second is short enough that a recycled ephemeral
    /// port cannot plausibly change hands within it, and long enough to stop the lookup
    /// being the expensive part of proxying.
    /// </remarks>
    private static readonly TimeSpan Freshness = TimeSpan.FromSeconds(1);

    private static readonly object Gate = new();
    private static Dictionary<int, uint> _ports = new();
    private static DateTimeOffset _taken = DateTimeOffset.MinValue;

    /// <summary>
    /// The reading at which a forced refresh already happened.
    /// </summary>
    /// <remarks>
    /// Stops a port that genuinely has no owner — a connection already closed — from
    /// forcing a table read on every lookup for as long as it keeps being asked about.
    /// </remarks>
    private static DateTimeOffset _lastForced = DateTimeOffset.MinValue;

    private static void Refresh()
    {
        _ports = Read();
        _taken = DateTimeOffset.UtcNow;
    }

    /// <summary>The process id owning <paramref name="port"/>, or zero if not known.</summary>
    public static uint Resolve(ushort port)
    {
        if (port == 0) return 0;

        lock (Gate)
        {
            if (DateTimeOffset.UtcNow - _taken > Freshness) Refresh();

            uint owner = _ports.GetValueOrDefault(port);
            if (owner != 0) return owner;

            // A miss on a cached table is usually a connection newer than the table, not
            // a connection with no owner — so look once more before answering "unknown".
            // Measured: with the cache alone, a request that arrived just after a refresh
            // was attributed to nobody, and an unattributed exchange is one a scoped
            // session keeps rather than excludes.
            if (_taken == _lastForced) return 0;

            Refresh();
            _lastForced = _taken;
            return _ports.GetValueOrDefault(port);
        }
    }

    private static Dictionary<int, uint> Read()
    {
        var result = new Dictionary<int, uint>();

        int size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        if (size <= 0) return result;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0) != 0) return result;

            int rows = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<TcpRowOwnerPid>();

            for (int i = 0; i < rows; i++)
            {
                var row = Marshal.PtrToStructure<TcpRowOwnerPid>(buffer + 4 + (i * rowSize));

                // The port sits in network order in the low half of a DWORD.
                int port = (int)(((row.LocalPort & 0xFF) << 8) | ((row.LocalPort >> 8) & 0xFF));
                if (port > 0) result[port] = row.OwningPid;
            }
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr table, ref int size, bool order, int addressFamily, int tableClass, int reserved);
}
