using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace CaYaTrace.Collectors.Proxy;

/// <summary>
/// What the machine's proxy configuration was before a session touched it, written down
/// somewhere the next launch can find it.
/// </summary>
/// <remarks>
/// <para>
/// Pointing the machine at a local proxy is the one change this tool makes that does not
/// expire. A trusted root stops being usable after twelve hours; a proxy setting pointing
/// at a port nobody is listening on stays broken forever, and it breaks <em>everything</em>
/// — every browser, every updater, every installer — with an error that says nothing about
/// CaYaTrace. The operator would be left searching a registry key they have no reason to
/// suspect.
/// </para>
/// <para>
/// Keeping the old values in a field is enough for a clean stop and useless for anything
/// else, and "anything else" is the case that matters: this tool is pointed at malware, on
/// purpose, and a subject that kills the console takes the restore with it. So the previous
/// configuration is written to disk <b>before</b> the change is made, and swept on every
/// launch whether or not interception is used again.
/// </para>
/// <para>
/// Ordering is the point. Written-then-applied means a crash in the gap leaves a restore
/// point describing values that are still current, and putting back what is already there
/// costs nothing. Applied-then-written would leave a machine changed with no record of what
/// it was.
/// </para>
/// </remarks>
public sealed class ProxyRestorePoint
{
    /// <summary>The loopback port the machine was pointed at.</summary>
    /// <remarks>
    /// Also the fingerprint. A restore point only entitles us to undo <em>our own</em>
    /// change: if the current setting no longer names this port, someone configured a
    /// proxy after we died, and overwriting their setting with a pre-crash value would be
    /// its own bug. In that case the record is dropped without being applied.
    /// </remarks>
    [JsonPropertyName("port")] public int Port { get; init; }

    [JsonPropertyName("processId")] public int ProcessId { get; init; }

    [JsonPropertyName("writtenUtc")] public DateTimeOffset WrittenUtc { get; init; }

    /// <summary>Null where the value did not exist, which is not the same as zero.</summary>
    /// <remarks>
    /// Restoring a value that was absent by writing 0 leaves behind a change nobody made.
    /// The distinction survives the round trip because null means absent.
    /// </remarks>
    [JsonPropertyName("proxyEnable")] public int? ProxyEnable { get; init; }

    [JsonPropertyName("proxyServer")] public string? ProxyServer { get; init; }

    [JsonPropertyName("proxyOverride")] public string? ProxyOverride { get; init; }

    /// <summary>Whether the machine-wide WinHTTP configuration was changed too.</summary>
    [JsonPropertyName("winHttpApplied")] public bool WinHttpApplied { get; init; }

    /// <summary>Null where WinHTTP's configuration could not be read.</summary>
    [JsonPropertyName("winHttpAccessType")] public int? WinHttpAccessType { get; init; }

    [JsonPropertyName("winHttpProxy")] public string? WinHttpProxy { get; init; }

    [JsonPropertyName("winHttpBypass")] public string? WinHttpBypass { get; init; }

    private const string InternetSettings = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private static readonly JsonSerializerOptions Format = new() { WriteIndented = true };

    /// <summary>
    /// Beside the settings file rather than beside the session.
    /// </summary>
    /// <remarks>
    /// A session directory is evidence and an operator may move, archive or delete it the
    /// moment a run ends. The record of a machine change has to outlive that.
    /// </remarks>
    public static string FilePath
    {
        get
        {
            string root = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData,
                Environment.SpecialFolderOption.Create);
            return Path.Combine(root, "CaYaDev", "CaYaTrace", "proxy-restore.json");
        }
    }

    /// <summary>Records the current configuration. Called before anything is changed.</summary>
    public static ProxyRestorePoint Capture(int port, bool winHttpWillBeApplied)
    {
        int? enable = null;
        string? server = null, over = null;

        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(InternetSettings);
            if (key is not null)
            {
                enable = key.GetValue("ProxyEnable") as int?;
                server = key.GetValue("ProxyServer") as string;
                over = key.GetValue("ProxyOverride") as string;
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
        }

        Proxy.WinHttpProxy.Backup? winHttp = winHttpWillBeApplied ? Proxy.WinHttpProxy.Read() : null;

        return new ProxyRestorePoint
        {
            Port = port,
            ProcessId = Environment.ProcessId,
            WrittenUtc = DateTimeOffset.UtcNow,
            ProxyEnable = enable,
            ProxyServer = server,
            ProxyOverride = over,
            WinHttpApplied = winHttpWillBeApplied,
            WinHttpAccessType = winHttp?.AccessType,
            WinHttpProxy = winHttp?.Proxy,
            WinHttpBypass = winHttp?.Bypass,
        };
    }

    public bool Save()
    {
        try
        {
            string path = FilePath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(this, Format));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static ProxyRestorePoint? Read()
    {
        try
        {
            string path = FilePath;
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<ProxyRestorePoint>(File.ReadAllText(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public static void Discard()
    {
        try { File.Delete(FilePath); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>What a sweep found and what it managed to do about it.</summary>
    public sealed record SweepResult(
        bool FoundRestorePoint,
        bool RestoredWinINet,
        bool RestoredWinHttp,
        bool WinHttpNeedsElevation,
        int StaleAuthorities,
        int RemovedAuthorities)
    {
        public bool DidAnything => RestoredWinINet || RestoredWinHttp || RemovedAuthorities > 0;

        /// <summary>
        /// Something is still wrong that the operator has to be told about, in front of
        /// whatever they launched the tool to do.
        /// </summary>
        public bool NeedsAttention =>
            WinHttpNeedsElevation || StaleAuthorities > RemovedAuthorities;

        /// <summary>
        /// The message keys this result should be reported under, in order.
        /// </summary>
        /// <remarks>
        /// Keys rather than sentences. The tool speaks two languages and the text lives in
        /// one place for both; a collector has no business holding a second copy of it in
        /// English only.
        /// </remarks>
        public IEnumerable<string> MessageKeys()
        {
            if (RestoredWinINet) yield return "proxy.sweep.wininet_restored";
            if (RestoredWinHttp) yield return "proxy.sweep.winhttp_restored";
            if (WinHttpNeedsElevation) yield return "proxy.sweep.winhttp_needs_admin";
            if (RemovedAuthorities > 0) yield return "proxy.sweep.ca_removed";
            if (StaleAuthorities > RemovedAuthorities) yield return "proxy.sweep.ca_needs_admin";
        }
    }

    /// <summary>
    /// Undoes anything an earlier run left behind. Safe to call on every launch.
    /// </summary>
    /// <remarks>
    /// Unconditional by design. The old sweep ran inside the proxy collector, which meant
    /// the promise in the consent text — removed again on the next launch — was only kept
    /// for an operator who happened to enable interception a second time. The run that
    /// failed to clean up is the run that is not around to notice, and the launch that has
    /// to notice is the next one, whatever it was asked to do.
    /// </remarks>
    public static SweepResult Sweep()
    {
        ProxyRestorePoint? point = Read();

        bool restoredWinINet = false;
        bool restoredWinHttp = false;
        bool winHttpNeedsElevation = false;

        if (point is not null)
        {
            restoredWinINet = point.RestoreWinINetIfStillOurs();

            if (point.WinHttpApplied && point.WinHttpIsStillOurs())
            {
                restoredWinHttp = Proxy.WinHttpProxy.Restore(point.AsWinHttpBackup());

                // WinHTTP's configuration is machine-wide, so putting it back is an
                // administrator's job. A user-level launch can see the damage and not
                // repair it, which is worth saying out loud rather than swallowing.
                if (!restoredWinHttp) winHttpNeedsElevation = true;
            }

            // Kept only while something still needs doing, so a machine that is already
            // clean stops carrying a record of a session that ended days ago.
            if (!winHttpNeedsElevation) Discard();
        }

        List<string> stale = SessionCertificateAuthority.FindStale();
        int removed = 0;
        if (stale.Count > 0) removed = SessionCertificateAuthority.RemoveAllStale(out _);

        return new SweepResult(
            point is not null, restoredWinINet, restoredWinHttp, winHttpNeedsElevation,
            stale.Count, removed);
    }

    private Proxy.WinHttpProxy.Backup AsWinHttpBackup() =>
        new(WinHttpAccessType ?? 1, WinHttpProxy, WinHttpBypass);

    /// <summary>True when the machine still points at the port this record describes.</summary>
    private bool WinHttpIsStillOurs()
    {
        Proxy.WinHttpProxy.Backup? current = Proxy.WinHttpProxy.Read();
        return current?.Proxy is { } proxy
            && proxy.Contains($"127.0.0.1:{Port}", StringComparison.Ordinal);
    }

    private bool RestoreWinINetIfStillOurs()
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(InternetSettings, writable: true);
            if (key is null) return false;

            // Only undo our own change. If the current value names a different proxy the
            // operator configured one after we died, and restoring a pre-crash value over
            // the top of a deliberate setting would be a bug of our own making.
            if (key.GetValue("ProxyServer") as string is not { } current
                || !current.Contains($"127.0.0.1:{Port}", StringComparison.Ordinal))
            {
                return false;
            }

            Put(key, "ProxyEnable", ProxyEnable, RegistryValueKind.DWord);
            Put(key, "ProxyServer", ProxyServer, RegistryValueKind.String);
            Put(key, "ProxyOverride", ProxyOverride, RegistryValueKind.String);

            NotifyProxyChanged();
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return false;
        }

        static void Put(RegistryKey key, string name, object? value, RegistryValueKind kind)
        {
            if (value is null) key.DeleteValue(name, throwOnMissingValue: false);
            else key.SetValue(name, value, kind);
        }
    }

    /// <summary>Tells WinINet to re-read its proxy configuration.</summary>
    /// <remarks>
    /// Same reason as when the setting is applied: the registry is where the value lives,
    /// not where it is read from. Without this the machine is repaired on disk and still
    /// broken in every process already running.
    /// </remarks>
    internal static void NotifyProxyChanged()
    {
        const int InternetOptionSettingsChanged = 39;
        const int InternetOptionRefresh = 37;

        try
        {
            InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
        }
    }

    [System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr session, int option, IntPtr buffer, int bufferLength);
}
