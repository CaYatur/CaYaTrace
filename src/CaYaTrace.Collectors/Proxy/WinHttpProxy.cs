using System.Runtime.InteropServices;

namespace CaYaTrace.Collectors.Proxy;

/// <summary>
/// The machine-wide proxy that WinHTTP uses, which is not the one the control panel sets.
/// </summary>
/// <remarks>
/// <para>
/// Windows has two independent HTTP client stacks with two independent proxy
/// configurations. WinINet's is per-user and is what a browser and .NET Framework read;
/// WinHTTP's is per-machine and is what services, most installers and updaters, and
/// anything running before a user logs on read.
/// </para>
/// <para>
/// Setting only the first is why a subject can be recorded with interception switched on
/// and produce no exchanges at all — measured. The two are set together, and both are put
/// back afterwards.
/// </para>
/// <para>
/// Configured through the API rather than by running <c>netsh</c>, because the session is
/// recording at the time: spawning a process to change the machine puts that process, its
/// image loads and its registry writes into the evidence the operator is about to read.
/// </para>
/// </remarks>
internal static class WinHttpProxy
{
    private const int AccessTypeNoProxy = 1;
    private const int AccessTypeNamedProxy = 3;

    /// <summary>The configuration that was in place, so it can be put back exactly.</summary>
    internal sealed record Backup(int AccessType, string? Proxy, string? Bypass);

    /// <summary>Reads the current machine-wide configuration.</summary>
    public static Backup? Read()
    {
        var info = new WINHTTP_PROXY_INFO();

        try
        {
            if (!WinHttpGetDefaultProxyConfiguration(ref info)) return null;

            return new Backup(
                (int)info.dwAccessType,
                Marshal.PtrToStringUni(info.lpszProxy),
                Marshal.PtrToStringUni(info.lpszProxyBypass));
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
        finally
        {
            if (info.lpszProxy != IntPtr.Zero) Marshal.FreeHGlobal(info.lpszProxy);
            if (info.lpszProxyBypass != IntPtr.Zero) Marshal.FreeHGlobal(info.lpszProxyBypass);
        }
    }

    /// <summary>Points WinHTTP at the local proxy. Returns false if it could not be set.</summary>
    public static bool Apply(int port)
    {
        IntPtr proxy = Marshal.StringToHGlobalUni($"127.0.0.1:{port}");

        // Loopback stays direct: the proxy's own upstream connections and any local
        // service must not be routed back into it.
        IntPtr bypass = Marshal.StringToHGlobalUni("<local>");

        try
        {
            var info = new WINHTTP_PROXY_INFO
            {
                dwAccessType = AccessTypeNamedProxy,
                lpszProxy = proxy,
                lpszProxyBypass = bypass,
            };

            return WinHttpSetDefaultProxyConfiguration(ref info);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(proxy);
            Marshal.FreeHGlobal(bypass);
        }
    }

    /// <summary>Puts back what was there, exactly.</summary>
    public static bool Restore(Backup? backup)
    {
        IntPtr proxy = IntPtr.Zero;
        IntPtr bypass = IntPtr.Zero;

        try
        {
            // No backup means the configuration could not be read, and the safe assumption
            // is the default: no proxy. Leaving 127.0.0.1 in place would break every
            // service on the machine once the session ended.
            var info = new WINHTTP_PROXY_INFO
            {
                dwAccessType = (uint)(backup?.AccessType ?? AccessTypeNoProxy),
            };

            if (backup?.Proxy is { Length: > 0 } p) info.lpszProxy = proxy = Marshal.StringToHGlobalUni(p);
            if (backup?.Bypass is { Length: > 0 } b) info.lpszProxyBypass = bypass = Marshal.StringToHGlobalUni(b);

            return WinHttpSetDefaultProxyConfiguration(ref info);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
        finally
        {
            if (proxy != IntPtr.Zero) Marshal.FreeHGlobal(proxy);
            if (bypass != IntPtr.Zero) Marshal.FreeHGlobal(bypass);
        }
    }

    public static string Describe(Backup? backup) => backup is null
        ? "unknown"
        : backup.AccessType == AccessTypeNamedProxy
            ? $"{backup.Proxy} (bypass {backup.Bypass})"
            : "direct";

    [StructLayout(LayoutKind.Sequential)]
    private struct WINHTTP_PROXY_INFO
    {
        public uint dwAccessType;
        public IntPtr lpszProxy;
        public IntPtr lpszProxyBypass;
    }

    [DllImport("winhttp.dll", SetLastError = true)]
    private static extern bool WinHttpGetDefaultProxyConfiguration(ref WINHTTP_PROXY_INFO info);

    [DllImport("winhttp.dll", SetLastError = true)]
    private static extern bool WinHttpSetDefaultProxyConfiguration(ref WINHTTP_PROXY_INFO info);
}
