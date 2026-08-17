using System.Runtime.InteropServices;
using System.Text;

namespace CaYaTrace.Collectors.Network;

/// <summary>
/// Captures what programs on this machine say to each other over loopback.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why anything extra is needed at all.</b> An established TCP connection over
/// 127.0.0.1 is handled inside the stack by a fastpath that never produces a packet on any
/// adapter, so no ordinary capture sees it. Measured twice with the packet monitor Windows
/// ships, told to capture every component: 5,276 events and not one of them loopback. A
/// program talking to a second copy of itself, or to the local service it had just
/// installed, produced byte counts and no contents — which is exactly the arrangement
/// worth reading.
/// </para>
/// <para>
/// <b>What sees it.</b> Npcap's loopback adapter, which hooks the Windows Filtering
/// Platform rather than the adapter stack and therefore sits above the decision that
/// makes loopback a fastpath. It is the same mechanism Wireshark uses for
/// "Adapter for loopback traffic capture", it is a signed driver maintained by somebody
/// else, and using it is strictly better than shipping a kernel driver of our own.
/// </para>
/// <para>
/// <b>Why the library and not the tool.</b> Npcap installs <c>wpcap.dll</c>; the capture
/// programs that drive it come with Wireshark, which an analysis machine usually does not
/// have. The four functions used here are libpcap's, unchanged for twenty years, and
/// calling them directly means the feature works with Npcap alone.
/// </para>
/// <para>
/// The output is pcapng, because everything that turns bytes into a readable conversation
/// — reassembly, direction, protocol, contents — already exists behind that format.
/// </para>
/// </remarks>
public sealed class LoopbackCapture : IDisposable
{
    private readonly string _path;
    private readonly int _snapLength;

    private IntPtr _handle;
    private Thread? _pump;
    private volatile bool _running;
    private PcapngWriter? _writer;

    private long _packets;
    private long _bytes;
    private string? _fault;

    /// <param name="path">Where to write the pcapng.</param>
    /// <param name="snapLengthBytes">
    /// How much of each packet to keep. The default keeps whole packets, which is the
    /// whole point — a truncated capture of a local conversation is a byte count again.
    /// </param>
    /// <param name="maxFileSizeMB">
    /// Where to stop writing. Local inter-process traffic is not a trickle — a database
    /// connection, a development server, a chatty local service move tens of megabytes a
    /// second over loopback — and an unbounded capture on a machine like that fills the
    /// disk during a session nobody is watching. Reaching the cap stops the writing and
    /// says so, rather than truncating quietly.
    /// </param>
    public LoopbackCapture(string path, int snapLengthBytes = 262144, int maxFileSizeMB = 512)
    {
        _path = path;
        _snapLength = snapLengthBytes;
        _maxBytes = Math.Max(1, maxFileSizeMB) * 1024L * 1024L;
    }

    private readonly long _maxBytes;

    /// <summary>True when the capture stopped early because it reached its size cap.</summary>
    public bool ReachedSizeLimit { get; private set; }

    /// <summary>Packets written so far.</summary>
    public long PacketCount => Interlocked.Read(ref _packets);

    /// <summary>Captured bytes written so far.</summary>
    public long ByteCount => Interlocked.Read(ref _bytes);

    /// <summary>What went wrong during the capture, if anything did.</summary>
    public string? Fault => _fault;

    /// <summary>
    /// Whether this machine can capture loopback at all, and why not when it cannot.
    /// </summary>
    /// <remarks>
    /// Answerable before anything is started, and always with a reason. A capture that
    /// quietly produces an empty file is indistinguishable from a program that never
    /// talked to anything, and an analyst reading the second when the first is true draws
    /// the opposite conclusion from the right one.
    /// </remarks>
    public static bool IsAvailable(out string reason)
    {
        if (!OperatingSystem.IsWindows())
        {
            reason = "loopback capture is a Windows feature";
            return false;
        }

        if (!TryLoadLibrary(out string libraryProblem))
        {
            reason = libraryProblem;
            return false;
        }

        string? device = FindLoopbackDevice(out string lookupProblem);
        if (device is null)
        {
            reason = lookupProblem;
            return false;
        }

        reason = $"available through {device}";
        return true;
    }

    /// <summary>Opens the loopback adapter and begins writing.</summary>
    public bool Start(out string error)
    {
        error = string.Empty;

        if (!TryLoadLibrary(out error)) return false;

        string? device = FindLoopbackDevice(out error);
        if (device is null) return false;

        var message = new byte[PcapErrorBufferSize];

        // Promiscuous is meaningless on loopback and the timeout is the read timeout in
        // milliseconds: too long and the capture lags behind the conversation, too short
        // and the pump spins. A tenth of a second is what capture tools use.
        _handle = pcap_open_live(device, _snapLength, 0, 100, message);

        if (_handle == IntPtr.Zero)
        {
            error = $"the loopback adapter would not open: {Describe(message)}";
            return false;
        }

        try
        {
            string? directory = Path.GetDirectoryName(_path);
            if (directory is { Length: > 0 }) Directory.CreateDirectory(directory);

            _writer = new PcapngWriter(_path, LinkTypeNull, _snapLength, device);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            pcap_close(_handle);
            _handle = IntPtr.Zero;
            error = $"the capture file could not be opened: {ex.Message}";
            return false;
        }

        _running = true;
        _pump = new Thread(Pump)
        {
            IsBackground = true,
            Name = "cayatrace-loopback",
        };
        _pump.Start();

        return true;
    }

    /// <summary>Stops the capture and closes the file.</summary>
    public void Stop()
    {
        if (!_running && _handle == IntPtr.Zero) return;

        _running = false;

        // Unblocks the read the pump is sitting in. Without it the thread waits out the
        // read timeout, which is survivable but leaves a stop looking like a hang.
        if (_handle != IntPtr.Zero)
        {
            try { pcap_breakloop(_handle); }
            catch (EntryPointNotFoundException) { }
        }

        _pump?.Join(TimeSpan.FromSeconds(5));
        _pump = null;

        if (_handle != IntPtr.Zero)
        {
            pcap_close(_handle);
            _handle = IntPtr.Zero;
        }

        _writer?.Dispose();
        _writer = null;
    }

    /// <summary>
    /// Reads packets until told to stop.
    /// </summary>
    /// <remarks>
    /// On its own thread rather than through libpcap's own loop callback, because a
    /// managed delegate invoked from native code across a long-running capture is a
    /// lifetime problem nobody needs: the delegate must outlive the call, and a collected
    /// one takes the process with it.
    /// </remarks>
    private void Pump()
    {
        try
        {
            while (_running)
            {
                int result = pcap_next_ex(_handle, out IntPtr headerPointer, out IntPtr dataPointer);

                // 0 is the read timeout expiring with nothing to report, which is the
                // normal state of a quiet machine.
                if (result == 0) continue;

                if (result < 0)
                {
                    // -2 is the break; anything else is the adapter going away.
                    if (result != -2) _fault = "the capture ended early";
                    return;
                }

                // Read field by field rather than through a struct.
                //
                // libpcap's header is a timeval followed by two lengths, and how wide a
                // timeval is on Windows is not something to take on trust: this build
                // announces itself as "64-bit time_t" and then lays the header out with
                // four 32-bit fields. Getting that wrong does not fail — it reads the
                // capture length out of the next field along, which is a pointer, so every
                // packet looks impossibly large and the capture silently writes nothing.
                // That is precisely what happened, and the bytes on the wire settled it.
                int seconds = Marshal.ReadInt32(headerPointer, 0);
                int microseconds = Marshal.ReadInt32(headerPointer, 4);
                int captured = Marshal.ReadInt32(headerPointer, 8);
                int onTheWire = Marshal.ReadInt32(headerPointer, 12);

                if (captured <= 0 || captured > _snapLength) continue;

                var buffer = new byte[captured];
                Marshal.Copy(dataPointer, buffer, 0, captured);

                if (Interlocked.Read(ref _bytes) + captured > _maxBytes)
                {
                    ReachedSizeLimit = true;
                    _fault = $"the capture reached its {_maxBytes / (1024 * 1024)} MB limit and stopped; "
                             + "what was captured before that point is complete";
                    return;
                }

                _writer?.Write(seconds, microseconds, buffer, onTheWire);

                Interlocked.Increment(ref _packets);
                Interlocked.Add(ref _bytes, captured);
            }
        }
        catch (Exception ex) when (ex is IOException or SEHException or AccessViolationException)
        {
            _fault = ex.Message;
        }
    }

    public void Dispose() => Stop();

    // ------------------------------------------------------------------ devices

    /// <summary>
    /// Finds the adapter that carries loopback, by what it is rather than by its name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The name is <c>\Device\NPF_Loopback</c> on current Npcap and was
    /// <c>\Device\NPF_{GUID}</c> for an installed loopback adapter on older ones, so the
    /// description is checked as well — and, failing both, any device carrying an address
    /// in 127.0.0.0/8. Three ways of asking the same question, because a capture that
    /// silently picks the wrong adapter records a machine's real network traffic while
    /// claiming to record its local conversations.
    /// </para>
    /// </remarks>
    internal static string? FindLoopbackDevice(out string problem)
    {
        problem = string.Empty;

        var message = new byte[PcapErrorBufferSize];

        if (pcap_findalldevs(out IntPtr list, message) != 0 || list == IntPtr.Zero)
        {
            problem = $"the capture driver would not list its adapters: {Describe(message)}";
            return null;
        }

        try
        {
            string? byName = null;
            string? byDescription = null;
            string? byAddress = null;

            for (IntPtr current = list; current != IntPtr.Zero;)
            {
                PcapInterface device = Marshal.PtrToStructure<PcapInterface>(current);

                string name = Utf8(device.Name) ?? string.Empty;
                string description = Utf8(device.Description) ?? string.Empty;

                if (name.EndsWith("NPF_Loopback", StringComparison.OrdinalIgnoreCase))
                    byName ??= name;

                if (description.Contains("loopback", StringComparison.OrdinalIgnoreCase))
                    byDescription ??= name;

                if (byAddress is null && HasLoopbackAddress(device.Addresses))
                    byAddress = name;

                current = device.Next;
            }

            string? found = byName ?? byDescription ?? byAddress;

            if (found is null)
            {
                problem =
                    "no loopback adapter is present. Npcap installs one when its "
                    + "\"Support loopback traffic\" option is selected, which is the default; "
                    + "reinstalling Npcap with that option adds it.";
            }

            return found;
        }
        finally
        {
            pcap_freealldevs(list);
        }
    }

    private static bool HasLoopbackAddress(IntPtr addresses)
    {
        for (IntPtr current = addresses; current != IntPtr.Zero;)
        {
            PcapAddress entry = Marshal.PtrToStructure<PcapAddress>(current);

            if (entry.Address != IntPtr.Zero)
            {
                // sockaddr: family in the first two bytes, then the port, then the
                // address for AF_INET (2).
                short family = Marshal.ReadInt16(entry.Address);
                if (family == 2)
                {
                    byte first = Marshal.ReadByte(entry.Address, 4);
                    if (first == 127) return true;
                }
            }

            current = entry.Next;
        }

        return false;
    }

    // ------------------------------------------------------------------ loading

    private static bool _loaded;
    private static string _loadProblem = string.Empty;

    /// <summary>
    /// Makes sure <c>wpcap.dll</c> can be found, from where Npcap actually puts it.
    /// </summary>
    /// <remarks>
    /// Npcap installs into <c>System32\Npcap</c> rather than <c>System32</c>, deliberately,
    /// so that it does not shadow a WinPcap install. That directory is not on the search
    /// path of a process that did not ask for it, so a plain P/Invoke fails to find a
    /// library that is sitting right there.
    /// </remarks>
    private static bool TryLoadLibrary(out string problem)
    {
        // A success is cached; a failure is not.
        //
        // Npcap can be installed while this process is running — which is exactly what an
        // operator does after being told it is missing — and remembering the refusal would
        // make them restart the tool for no reason. That is the same stale-state shape as
        // a disabled checkbox that never re-enables.
        if (_loaded)
        {
            problem = string.Empty;
            return true;
        }

        string system = Environment.GetFolderPath(Environment.SpecialFolder.System);

        foreach (string candidate in new[]
                 {
                     Path.Combine(system, "Npcap", "wpcap.dll"),
                     Path.Combine(system, "wpcap.dll"),
                     "wpcap.dll",
                 })
        {
            if (NativeLibrary.TryLoad(candidate, out IntPtr _))
            {
                _loaded = true;
                _loadProblem = string.Empty;
                problem = string.Empty;
                return true;
            }
        }

        _loadProblem =
            "Npcap is not installed. It is the packet driver Wireshark uses, it is free, "
            + "and it is the only thing on Windows that can see a program talking to another "
            + "program on the same machine: https://npcap.com";

        problem = _loadProblem;
        return false;
    }

    private static string? Utf8(IntPtr pointer) => pointer == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(pointer);

    private static string Describe(byte[] message)
    {
        int end = Array.IndexOf(message, (byte)0);
        string text = Encoding.UTF8.GetString(message, 0, end < 0 ? message.Length : end).Trim();
        return text.Length == 0 ? "no reason given" : text;
    }

    // ------------------------------------------------------------------ interop

    private const int PcapErrorBufferSize = 256;

    /// <summary>DLT_NULL: four bytes of address family, then the IP header.</summary>
    internal const int LinkTypeNull = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapInterface
    {
        public IntPtr Next;
        public IntPtr Name;
        public IntPtr Description;
        public IntPtr Addresses;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapAddress
    {
        public IntPtr Next;
        public IntPtr Address;
        public IntPtr Netmask;
        public IntPtr Broadcast;
        public IntPtr Destination;
    }

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr pcap_open_live(string device, int snapLength, int promiscuous, int timeoutMs, byte[] error);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int pcap_next_ex(IntPtr handle, out IntPtr header, out IntPtr data);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_breakloop(IntPtr handle);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_close(IntPtr handle);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int pcap_findalldevs(out IntPtr devices, byte[] error);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_freealldevs(IntPtr devices);
}
