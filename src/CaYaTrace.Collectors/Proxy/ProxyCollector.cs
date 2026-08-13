using CaYaTrace.Core.Model;
using Microsoft.Win32;

namespace CaYaTrace.Collectors.Proxy;

/// <summary>
/// Everything the operator is agreeing to when they enable interception.
/// </summary>
public sealed record InterceptionConsentRequest(
    string CertificateThumbprint,
    string CertificateSubject,
    int ProxyPort)
{
    /// <summary>
    /// The text an operator must read. Written to be understood rather than clicked
    /// through: it names the concrete change, its blast radius, and its duration.
    /// </summary>
    public string Describe() =>
        $"""
        CaYaTrace is about to intercept HTTPS traffic on this machine.

        To do that it will:
          · install a temporary certificate authority into the machine's trusted roots
              {CertificateSubject}
              thumbprint {CertificateThumbprint}
          · route HTTP and HTTPS through a local proxy on 127.0.0.1:{ProxyPort}

        While that certificate is trusted, any program running as you can present a
        certificate for any website and this machine will believe it. The certificate
        expires in 12 hours, is removed when the session stops, and is removed again on
        the next launch if this run does not finish.

        The proxy setting does not expire, so it is written down before it is changed and
        put back on the next launch even if this run is killed outright — which is the
        expected outcome when the thing being recorded fights back.

        Do this on a machine you can afford to have in this state — ideally a disposable
        VM, not the computer you bank on.

        Traffic recorded this way includes request and response bodies: passwords,
        session cookies, and uploaded files.
        """;
}

public sealed class ProxyCollectorOptions
{
    public ProxyOptions Proxy { get; init; } = ProxyOptions.Default;

    /// <summary>
    /// Point the machine's WinINet proxy settings at us. Without it, only applications
    /// explicitly configured to use the proxy are visible.
    /// </summary>
    public bool ConfigureSystemProxy { get; init; } = true;

    public static ProxyCollectorOptions Default { get; } = new();
}

/// <summary>
/// Runs the intercepting proxy for the length of a session, and guarantees the machine
/// is put back afterwards.
/// </summary>
/// <remarks>
/// <para>
/// The collector's real job is not proxying — it is making sure two system changes,
/// a trusted root and the system proxy configuration, are always reverted. Both are
/// reverted on stop, on dispose, and on the next launch, because the run that fails to
/// clean up is the one that is not around to notice.
/// </para>
/// <para>
/// Consent is a callback rather than a flag. There is no way to enable this by passing
/// an option: something has to affirmatively answer the question, and the CLI and the
/// workbench each ask it in their own way.
/// </para>
/// </remarks>
public sealed class ProxyCollector : ICollector
{
    private const string InternetSettings = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private readonly ProxyCollectorOptions _options;
    private readonly Func<InterceptionConsentRequest, bool> _consent;

    private CollectorContext? _ctx;
    private SessionCertificateAuthority? _authority;
    private InterceptingProxy? _proxy;
    private ProxySettingsBackup? _backup;

    /// <summary>The machine-wide WinHTTP configuration as it was before this session.</summary>
    private WinHttpProxy.Backup? _winHttpBackup;
    private bool _winHttpApplied;

    public ProxyCollector(Func<InterceptionConsentRequest, bool> consent, ProxyCollectorOptions? options = null)
    {
        _consent = consent;
        _options = options ?? ProxyCollectorOptions.Default;
    }

    public string Name => "https-proxy";

    public bool RequiresElevation => true;

    private sealed record ProxySettingsBackup(object? Enable, object? Server, object? Override);

    public Task<bool> StartAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        _ctx = context;

        // Always, before anything else. A previous run that crashed with the CA
        // installed left the machine trusting an interception root, and that is not
        // something to leave until someone thinks to check.
        int stale = SessionCertificateAuthority.RemoveAllStale(out List<string> removed);
        if (stale > 0)
        {
            context.Store.LogQuality(Name, "warning",
                $"removed {stale} certificate authority(ies) left behind by an earlier run: {string.Join(", ", removed)}");
        }

        if (!IsElevated())
        {
            context.ReportSkipped(Name, "installing a certificate authority requires an elevated process");
            return Task.FromResult(false);
        }

        _authority = SessionCertificateAuthority.Create(context.Session.SessionId);
        _proxy = new InterceptingProxy(context, _authority, _options.Proxy);
        _proxy.Start();

        var request = new InterceptionConsentRequest(
            _authority.Thumbprint,
            $"CN={SessionCertificateAuthority.SubjectMarker}",
            _proxy.Port);

        if (!_consent(request))
        {
            context.ReportSkipped(Name, "the operator declined HTTPS interception");
            Cleanup();
            return Task.FromResult(false);
        }

        if (!_authority.Install(out string? installError))
        {
            context.ReportFault(Name, $"could not install the certificate authority: {installError}");
            Cleanup();
            return Task.FromResult(false);
        }

        context.Session.ProxyEnabled = true;
        context.Session.ProxyCaThumbprint = _authority.Thumbprint;

        string exported = _authority.ExportPublicCertificate(
            Path.Combine(context.SessionDirectory, "proxy"));

        if (_options.ConfigureSystemProxy)
        {
            // On disk before anything is touched. A subject that kills this process takes
            // the in-memory backup with it, and the machine is left pointing at a port
            // nobody is listening on — which breaks every HTTP client on it, with an error
            // that names no cause. Written first so a crash in the gap leaves a record of
            // values that are still current, which is a harmless thing to put back.
            if (!ProxyRestorePoint.Capture(_proxy.Port, winHttpWillBeApplied: true).Save())
            {
                context.Store.LogQuality(Name, "warning",
                    "could not write the proxy restore point, so an abnormal exit would leave "
                    + "the machine's proxy settings pointing at this session");
            }

            _backup = ApplySystemProxy(_proxy.Port);

            // The other half. WinHTTP has its own machine-wide configuration, separate
            // from the per-user one above, and it is the one services, installers and
            // updaters read — which is most of what this tool is pointed at.
            _winHttpBackup = WinHttpProxy.Read();
            _winHttpApplied = WinHttpProxy.Apply(_proxy.Port);
            if (!_winHttpApplied)
            {
                context.Store.LogQuality(Name, "warning",
                    "the machine-wide WinHTTP proxy could not be set, so services and "
                    + "installers that use it will not be intercepted");
            }
            else
            {
                context.Store.LogQuality(Name, "info",
                    $"WinHTTP proxy pointed at 127.0.0.1:{_proxy.Port}, "
                    + $"previously {WinHttpProxy.Describe(_winHttpBackup)}");
            }
        }

        context.Emit(new Observation
        {
            Timestamp = DateTimeOffset.UtcNow,
            Category = EventCategory.Security,
            Action = EventAction.ValueSet,
            Target = "machine trusted root store",
            Target2 = _authority.Thumbprint,
            NewValue = $"CN={SessionCertificateAuthority.SubjectMarker}",
            Source = EvidenceSource.Analyst,
            Status = EventStatus.Success,
            Details = $"installed by CaYaTrace with the operator's consent; public certificate at {exported}",
        });

        context.Session.EnabledCollectors.Add(Name);
        return Task.FromResult(true);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_ctx is null) return;

        if (_proxy is not null)
        {
            _ctx.Store.LogQuality(Name, "info",
                $"{_proxy.Exchanges:N0} HTTP exchanges recorded, " +
                $"{_proxy.OpaqueConnections:N0} connections stayed encrypted (pinning or a private trust store)");

            // Said out loud. The proxy is machine-wide while the session is not, so the
            // difference between what it saw and what it kept is a real number and the
            // operator should know it exists rather than wonder why a busy machine
            // produced a short list.
            if (_proxy.OtherProcessExchanges > 0)
            {
                _ctx.Store.LogQuality(Name, "info",
                    $"{_proxy.OtherProcessExchanges:N0} exchanges belonged to other programs on this "
                    + "machine and were not recorded. Record system-wide to keep them.");
            }
        }

        if (_backup is not null) RestoreSystemProxy(_backup);

        // Put WinHTTP back whether or not reading it succeeded. Leaving the machine
        // pointed at a proxy that no longer exists breaks every service that uses it,
        // and that failure would appear long after the session ended.
        bool winHttpRestored = !_winHttpApplied || WinHttpProxy.Restore(_winHttpBackup);
        if (!winHttpRestored)
        {
            _ctx.ReportFault(Name,
                "could not restore the machine-wide WinHTTP proxy. Run "
                + "'netsh winhttp reset proxy' from an elevated prompt.");
        }

        // Only once the machine really is back. Dropping the record while something is
        // still pointing at this session would delete the one thing the next launch needs
        // in order to finish the job.
        if (_backup is not null && winHttpRestored) ProxyRestorePoint.Discard();

        if (_authority is { IsInstalled: true })
        {
            bool removed = _authority.Remove(out string? error);
            _ctx.Session.ProxyCaRemoved = removed;

            if (!removed)
            {
                // Loud, and repeated in the session's quality record. A trusted
                // interception root left on a machine is the worst outcome this tool
                // can produce, and it must never be a silent one.
                _ctx.ReportFault(Name,
                    $"THE TEMPORARY CERTIFICATE AUTHORITY COULD NOT BE REMOVED ({error}). " +
                    $"Remove thumbprint {_authority.Thumbprint} from the machine's Trusted Root " +
                    "Certification Authorities store by hand, or run CaYaTrace again to retry.");
            }
            else
            {
                _ctx.Emit(new Observation
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Category = EventCategory.Security,
                    Action = EventAction.ValueDelete,
                    Target = "machine trusted root store",
                    Target2 = _authority.Thumbprint,
                    Source = EvidenceSource.Analyst,
                    Status = EventStatus.Success,
                    Details = "removal verified by re-reading the store",
                });
            }
        }

        if (_proxy is not null) await _proxy.DisposeAsync().ConfigureAwait(false);
        _proxy = null;
    }

    /// <summary>
    /// Points WinINet at the local proxy, keeping the previous values.
    /// </summary>
    /// <remarks>
    /// Per-user rather than machine-wide, and loopback is excluded so the tool's own
    /// traffic and local services are not routed through it.
    /// </remarks>
    private ProxySettingsBackup? ApplySystemProxy(int port)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(InternetSettings, writable: true);
            if (key is null) return null;

            var backup = new ProxySettingsBackup(
                key.GetValue("ProxyEnable"),
                key.GetValue("ProxyServer"),
                key.GetValue("ProxyOverride"));

            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            key.SetValue("ProxyServer", $"127.0.0.1:{port}", RegistryValueKind.String);
            key.SetValue("ProxyOverride", "<local>", RegistryValueKind.String);

            // Writing the registry is not enough on its own, and this is where the whole
            // feature was silently failing: WinINet caches proxy configuration and only
            // re-reads it when told to. Measured — a subject launched with interception
            // enabled made six TLS handshakes straight past the proxy and the session
            // recorded zero exchanges.
            NotifyProxyChanged();

            return backup;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            _ctx?.ReportFault(Name, $"could not configure the system proxy: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Tells WinINet its proxy configuration changed.
    /// </summary>
    /// <remarks>
    /// Without this the registry values are correct and nothing reads them: WinINet holds
    /// its proxy configuration in memory and refreshes on notification, not on a timer.
    /// Both options are sent because the pair is what the control panel itself sends, and
    /// sending only one leaves some callers on the stale configuration.
    /// </remarks>
    private static void NotifyProxyChanged()
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

    private void RestoreSystemProxy(ProxySettingsBackup backup)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(InternetSettings, writable: true);
            if (key is null) return;

            Restore(key, "ProxyEnable", backup.Enable, RegistryValueKind.DWord);
            Restore(key, "ProxyServer", backup.Server, RegistryValueKind.String);
            Restore(key, "ProxyOverride", backup.Override, RegistryValueKind.String);

            NotifyProxyChanged();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            _ctx?.ReportFault(Name,
                $"could not restore the system proxy settings ({ex.Message}). " +
                "Check Settings > Network > Proxy: it may still point at 127.0.0.1.");
        }

        static void Restore(RegistryKey key, string name, object? value, RegistryValueKind kind)
        {
            // A value that did not exist before must be deleted, not set to zero:
            // leaving ProxyEnable=0 behind is a change we made and did not undo.
            if (value is null) key.DeleteValue(name, throwOnMissingValue: false);
            else key.SetValue(name, value, kind);
        }
    }

    private void Cleanup()
    {
        _proxy?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _proxy = null;
        _authority?.Dispose();
        _authority = null;
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        // Dispose is the last line of defence for the two system changes. Even an
        // abnormal shutdown path must not leave a trusted interception root behind.
        try { await StopAsync(CancellationToken.None).ConfigureAwait(false); }
        catch (Exception) { }

        if (_authority is { IsInstalled: true })
            SessionCertificateAuthority.RemoveAllStale(out _);

        _authority?.Dispose();
        _authority = null;
    }
}
