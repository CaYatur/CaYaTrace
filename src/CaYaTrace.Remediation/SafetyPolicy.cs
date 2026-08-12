using CaYaTrace.Core.Naming;

namespace CaYaTrace.Remediation;

public enum SafetyVerdict
{
    /// <summary>The item may be acted on, subject to fingerprint verification.</summary>
    Allowed = 0,

    /// <summary>Permitted, but the analyst must confirm it individually.</summary>
    RequiresConfirmation = 1,

    /// <summary>Refused unconditionally. No flag overrides this.</summary>
    Forbidden = 2,
}

public readonly record struct SafetyDecision(SafetyVerdict Verdict, string Reason)
{
    public static SafetyDecision Allow() => new(SafetyVerdict.Allowed, string.Empty);
    public static SafetyDecision Confirm(string reason) => new(SafetyVerdict.RequiresConfirmation, reason);
    public static SafetyDecision Forbid(string reason) => new(SafetyVerdict.Forbidden, reason);
}

/// <summary>
/// The rules that stand between a removal plan and an unbootable machine.
/// </summary>
/// <remarks>
/// <para>
/// A removal package is data recorded on one machine and applied to another. Every
/// assumption it carries — that a path means the same thing, that a service is the
/// one we saw, that a registry key belongs to the subject — may be false on the
/// target. This class encodes the cases where being wrong is unrecoverable.
/// </para>
/// <para>
/// The deny list is not configurable and there is no override flag. That is a
/// deliberate design choice: an uninstaller that can be talked into deleting
/// <c>System32</c> is a wiper with extra steps, and the legitimate need to remove
/// something Windows-owned is rare enough to be worth doing by hand, with the
/// operator's full attention on it.
/// </para>
/// </remarks>
public sealed class SafetyPolicy
{
    private readonly PathNormalizer _paths;

    /// <summary>
    /// Path prefixes that may never be removed. Expressed as tokens so the rule holds
    /// regardless of where Windows is installed on the target.
    /// </summary>
    private static readonly string[] ForbiddenPathTokens =
    {
        "%WINDIR%",
        "%SYSTEM32%",
        "%SYSWOW64%",
        "%SYSTEMDRIVE%\\$Recycle.Bin",
        "%SYSTEMDRIVE%\\System Volume Information",
        "%SYSTEMDRIVE%\\Recovery",
        "%SYSTEMDRIVE%\\EFI",
        "%SYSTEMDRIVE%\\Boot",
    };

    /// <summary>
    /// Directories that must never be removed as a unit, though items inside them can
    /// be. Deleting the container takes every unrelated program with it.
    /// </summary>
    private static readonly string[] ForbiddenExactPaths =
    {
        "%SYSTEMDRIVE%\\",
        "%PROGRAMFILES%",
        "%PROGRAMFILES(X86)%",
        "%PROGRAMDATA%",
        "%USERPROFILE%",
        "%USERSROOT%",
        "%APPDATA%",
        "%LOCALAPPDATA%",
        "%TEMP%",
        "%DESKTOP%",
        "%PUBLIC%",
        "%STARTMENU%",
    };

    /// <summary>Registry subtrees whose removal breaks boot or logon.</summary>
    private static readonly string[] ForbiddenRegistryPrefixes =
    {
        @"HKLM\SYSTEM\CurrentControlSet\Control",
        @"HKLM\SYSTEM\CurrentControlSet\Enum",
        @"HKLM\SYSTEM\CurrentControlSet\Hardware Profiles",
        @"HKLM\SYSTEM\Select",
        @"HKLM\SYSTEM\Setup",
        @"HKLM\SAM",
        @"HKLM\SECURITY",
        @"HKLM\BCD00000000",
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        @"HKLM\SOFTWARE\Microsoft\Cryptography",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup",
    };

    /// <summary>
    /// Places Windows records that a program ran, rather than places a program installs
    /// itself into.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This list exists because of a measured failure. A plan built from a 30-second
    /// recording of an installer proposed deleting values under the Background Activity
    /// Moderator, the user's Internet Settings zone map, and the shared INetCache — none
    /// of which the subject installed. It had merely <em>run</em>, and Windows wrote those
    /// entries about it.
    /// </para>
    /// <para>
    /// The distinction the planner cannot make on its own is between "the subject
    /// created this" and "Windows recorded that the subject existed". Undoing the second
    /// is not uninstalling anything; it is damaging shared state that other programs
    /// depend on, and doing it under the banner of a clean removal is worse than leaving
    /// residue behind.
    /// </para>
    /// </remarks>
    private static readonly string[] ActivityRecordRegistryPrefixes =
    {
        // Background Activity Moderator and the desktop activity moderator: Windows'
        // own record of which executables ran and when.
        @"HKLM\SYSTEM\CurrentControlSet\Services\bam",
        @"HKLM\SYSTEM\CurrentControlSet\Services\dam",

        // Shell and compatibility caches, written for anything that is launched.
        @"HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        @"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags",
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage",

        // The user's own network and browser configuration. A program that made one
        // HTTP request touches these; none of it is that program's to remove.
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager",

        // Group policy. Machine administration, never an application's to undo.
        @"HKLM\SOFTWARE\Policies",
        @"HKCU\SOFTWARE\Policies",
    };

    /// <summary>
    /// Path segments that make a key shared machine trust configuration wherever it
    /// appears.
    /// </summary>
    /// <remarks>
    /// A segment rule rather than more prefixes, because these stores exist under at
    /// least six roots — per-user, per-machine, enterprise, and group-policy variants of
    /// each — and the observed plan named a different one every few lines. They are
    /// created on demand by the crypto API, so <em>any</em> program that validates a signature
    /// or makes an HTTPS request appears to have "created" them. Removing one breaks
    /// certificate validation for the whole machine.
    /// </remarks>
    private static readonly string[] TrustStoreSegments =
    {
        "SystemCertificates",
        "EnterpriseCertificates",
        "Trust Providers",
        "CertificateTransparency",

        // The store layout itself. The crypto API creates a key with these three
        // children wherever a component asks for its own store, so the parent name
        // varies without limit while the shape does not — measured, after a plan
        // proposed deleting six of them under two parents nobody would have predicted:
        // a background-transfer task's class id, and the package state repository.
        "Certificates",
        "CRLs",
        "CTLs",
    };

    /// <summary>
    /// The state that decides how the shell shows a user their own folders.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Added after an operator reported that Desktop and Documents disappeared from File
    /// Explorer's navigation pane following a removal. The specific value was not
    /// identified — the plan that ran is gone and the operator was not certain the
    /// removal was the cause — so this refuses the whole class rather than the one key,
    /// which is the right shape of fix either way.
    /// </para>
    /// <para>
    /// The reason this class is reachable at all is the same one behind the activity
    /// records and the trust stores: a program does not have to intend anything for
    /// Windows to write here on its behalf. Opening a file dialog writes to
    /// <c>ComDlg32</c>; showing a window writes shell bags; being installed writes
    /// <c>FileExts</c>. All of it then looks like something the subject created.
    /// </para>
    /// <para>
    /// The damage is also asymmetric in a way that matters. Leaving one of these behind
    /// costs the operator a stale entry they can delete by hand; removing one wrongly
    /// costs them a shell that no longer shows them their documents, with no indication
    /// of what happened or how to undo it.
    /// </para>
    /// </remarks>
    private static readonly string[] ShellPresentationSegments =
    {
        "User Shell Folders",
        "Shell Folders",
        "FolderDescriptions",
        "NameSpace",
        "MyComputer",
        "HideDesktopIcons",
        "FileExts",
        "TypedPaths",
        "StreamMRU",
        "Streams",
        "Shell Icons",
        "BagMRU",
        "Bags",
    };

    /// <summary>
    /// Folders the shell reads to build what the user sees, rather than program state.
    /// </summary>
    /// <remarks>
    /// Same class as <see cref="ShellPresentationSegments"/> on the file system. Removing
    /// a library definition or the Quick Launch folder takes the taskbar and the
    /// navigation pane with it, and a program touching them is Windows recording its
    /// existence, not the program installing something.
    /// </remarks>
    private static readonly string[] ShellStatePathTokens =
    {
        @"%APPDATA%\Microsoft\Windows\Libraries",
        @"%APPDATA%\Microsoft\Internet Explorer\Quick Launch",
        @"%APPDATA%\Microsoft\Windows\SendTo",
        @"%APPDATA%\Microsoft\Windows\Templates",
        @"%APPDATA%\Microsoft\Windows\Network Shortcuts",
        @"%APPDATA%\Microsoft\Windows\Printer Shortcuts",
        @"%APPDATA%\Microsoft\Windows\Themes",
        @"%LOCALAPPDATA%\Microsoft\Windows\Shell",
        @"%LOCALAPPDATA%\Microsoft\Windows\Notifications",
        @"%LOCALAPPDATA%\Packages\Microsoft.Windows.Explorer",
    };

    /// <summary>
    /// Shared caches Windows maintains for every program. Same reasoning as
    /// <see cref="ActivityRecordRegistryPrefixes"/>, on the file system.
    /// </summary>
    private static readonly string[] SharedCachePathTokens =
    {
        @"%LOCALAPPDATA%\Microsoft\Windows\INetCache",
        @"%LOCALAPPDATA%\Microsoft\Windows\INetCookies",
        @"%LOCALAPPDATA%\Microsoft\Windows\WebCache",
        @"%LOCALAPPDATA%\Microsoft\Windows\Explorer",
        @"%LOCALAPPDATA%\Microsoft\Windows\Caches",
        @"%LOCALAPPDATA%\Microsoft\Windows\History",
        @"%LOCALAPPDATA%\Microsoft\CLR_v4.0",
        @"%LOCALAPPDATA%\CrashDumps",
        @"%APPDATA%\Microsoft\Windows\Recent",
        @"%PROGRAMDATA%\Microsoft\Windows\Caches",
        @"%PROGRAMDATA%\Microsoft\Windows Defender",

        // PowerShell's own startup profile cache. Written by the shell whenever it runs,
        // so anything launched through PowerShell — which is most scripted installs —
        // appears to have created it. Observed in a real plan.
        @"%LOCALAPPDATA%\Microsoft\Windows\PowerShell",
        @"%APPDATA%\Microsoft\Windows\PowerShell",
    };

    /// <summary>
    /// Registry locations that are legitimate removal targets but sit on shared
    /// surfaces, where deleting the whole key would take unrelated software with it.
    /// Only individual values under these may be removed.
    /// </summary>
    private static readonly string[] ValueOnlyRegistryPrefixes =
    {
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
    };

    /// <summary>
    /// Services whose removal makes Windows unbootable or unusable. A package that
    /// names one of these is either mistaken or hostile; either way the answer is no.
    /// </summary>
    private static readonly HashSet<string> ProtectedServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "Power", "PlugPlay",
        "BFE", "BrokerInfrastructure", "SamSs", "EventLog", "Schedule",
        "CryptSvc", "Dhcp", "Dnscache", "gpsvc", "LanmanServer", "LanmanWorkstation",
        "netprofm", "NlaSvc", "nsi", "ProfSvc", "SENS", "ShellHWDetection",
        "Themes", "TrustedInstaller", "UserManager", "Winmgmt", "WinDefend",
        "wscsvc", "WSearch", "MpsSvc", "SystemEventsBroker", "StateRepository",
        "TermService", "UsoSvc", "wuauserv", "AppInfo", "SecurityHealthService",

        // Networking and storage. A machine that loses these does not come back on the
        // network, or does not boot.
        "Tcpip", "Tcpip6", "NetBT", "afd", "netbios", "tdx", "Winsock", "WinSock2",
        "disk", "partmgr", "volmgr", "volsnap", "storahci", "stornvme", "NTFS",
        "FltMgr", "Ndis", "NdisWan", "NativeWifiP", "WlanSvc", "WwanSvc",
    };

    public SafetyPolicy(PathNormalizer paths) => _paths = paths;

    /// <summary>
    /// The verdict for a planned removal, dispatched by what kind of thing it is.
    /// </summary>
    /// <remarks>
    /// Exists so the workbench can show an item as protected <em>before</em> the operator
    /// approves a plan, rather than having the runner silently skip it afterwards. A
    /// plan that quietly does less than it displayed is a plan nobody can audit — and
    /// the answer shown must be the same one the runner will reach, which is why both
    /// go through this method rather than each mapping kinds to checks itself.
    /// </remarks>
    public SafetyDecision Evaluate(RemovalItem item) => item.Kind switch
    {
        RemovalKind.File or RemovalKind.Directory => EvaluateFile(_paths.Expand(item.Target)),

        RemovalKind.RegistryValue => EvaluateSplitValue(item),

        RemovalKind.RegistryKey => EvaluateRegistryKey(item.Target),
        RemovalKind.Service => EvaluateService(item.Target),
        RemovalKind.ScheduledTask => EvaluateScheduledTask(item.Target),

        // An autorun entry is a registry value wearing a different name; a firewall rule
        // and a certificate are neither, and are allowed through to the runner, which
        // has the kind-specific handling.
        RemovalKind.AutorunEntry => item.ValueName is not null
            ? EvaluateRegistryValue(item.Target, item.ValueName)
            : EvaluateRegistryKey(item.Target),

        _ => SafetyDecision.Allow(),
    };

    private SafetyDecision EvaluateSplitValue(RemovalItem item)
    {
        if (item.ValueName is not null) return EvaluateRegistryValue(item.Target, item.ValueName);

        (string key, string? value) = RegistryPath.SplitValue(item.Target);
        return EvaluateRegistryValue(key, value);
    }

    public SafetyDecision EvaluateFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return SafetyDecision.Forbid("empty path");

        string token = _paths.Tokenize(path);
        string expanded = _paths.Expand(token);

        // A path that escapes upward is either a bug or an attempt to break out of
        // the intended target.
        if (token.Contains("..", StringComparison.Ordinal))
            return SafetyDecision.Forbid("path contains a relative traversal segment");

        foreach (string forbidden in ForbiddenExactPaths)
        {
            string normalizedForbidden = forbidden.TrimEnd('\\');
            if (string.Equals(token.TrimEnd('\\'), normalizedForbidden, StringComparison.OrdinalIgnoreCase))
                return SafetyDecision.Forbid($"{forbidden} is a shared container and is never removed as a unit");
        }

        foreach (string forbidden in ForbiddenPathTokens)
        {
            if (token.StartsWith(forbidden, StringComparison.OrdinalIgnoreCase)
                && (token.Length == forbidden.Length || token[forbidden.Length] == '\\'))
            {
                return SafetyDecision.Forbid($"{forbidden} is Windows-owned");
            }
        }

        foreach (string cache in SharedCachePathTokens)
        {
            if (token.StartsWith(cache, StringComparison.OrdinalIgnoreCase)
                && (token.Length == cache.Length || token[cache.Length] == '\\'))
            {
                return SafetyDecision.Forbid($"{cache} is a cache Windows keeps for every program");
            }
        }

        foreach (string shell in ShellStatePathTokens)
        {
            if (token.StartsWith(shell, StringComparison.OrdinalIgnoreCase)
                && (token.Length == shell.Length || token[shell.Length] == '\\'))
            {
                return SafetyDecision.Forbid(
                    $"{shell} is how the shell decides what to show the user, not something a program installs");
            }
        }

        // A raw device or volume path is not a file. These reach a plan when a program
        // opens a volume handle, and proposing them makes a plan look reckless.
        if (token.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)
            || token.StartsWith(@"\\.\", StringComparison.Ordinal)
            || token.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            return SafetyDecision.Forbid("this is a device path, not a file");
        }

        // A drive root, with or without a trailing separator.
        if (expanded.Length <= 3 && expanded.Contains(':', StringComparison.Ordinal))
            return SafetyDecision.Forbid("refusing to act on a drive root");

        // Things outside the usual install locations are legitimate but unusual;
        // surface them for individual confirmation rather than sweeping them up.
        bool familiar =
            token.StartsWith("%PROGRAMFILES", StringComparison.OrdinalIgnoreCase) ||
            token.StartsWith("%PROGRAMDATA%", StringComparison.OrdinalIgnoreCase) ||
            token.StartsWith("%APPDATA%", StringComparison.OrdinalIgnoreCase) ||
            token.StartsWith("%LOCALAPPDATA%", StringComparison.OrdinalIgnoreCase) ||
            token.StartsWith("%TEMP%", StringComparison.OrdinalIgnoreCase) ||
            token.StartsWith("%USERPROFILE%", StringComparison.OrdinalIgnoreCase) ||
            token.StartsWith("%STARTMENU%", StringComparison.OrdinalIgnoreCase) ||
            token.StartsWith("%DESKTOP%", StringComparison.OrdinalIgnoreCase);

        return familiar
            ? SafetyDecision.Allow()
            : SafetyDecision.Confirm("outside the usual installation locations");
    }

    public SafetyDecision EvaluateRegistryKey(string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath))
            return SafetyDecision.Forbid("empty registry path");

        string normalized = CanonicalizeControlSet(RegistryPath.Normalize(keyPath));
        (string hive, string subKey) = RegistryPath.Split(normalized);

        if (subKey.Length == 0)
            return SafetyDecision.Forbid("refusing to act on a registry hive root");

        foreach (string forbidden in ForbiddenRegistryPrefixes)
        {
            if (normalized.StartsWith(forbidden, StringComparison.OrdinalIgnoreCase)
                && (normalized.Length == forbidden.Length || normalized[forbidden.Length] == '\\'))
            {
                return SafetyDecision.Forbid($"{forbidden} is required for Windows to boot or log on");
            }
        }

        foreach (string record in ActivityRecordRegistryPrefixes)
        {
            if (normalized.StartsWith(record, StringComparison.OrdinalIgnoreCase)
                && (normalized.Length == record.Length || normalized[record.Length] == '\\'))
            {
                return SafetyDecision.Forbid(
                    $"{record} is where Windows records that a program ran, not something a program installs");
            }
        }

        foreach (string segment in ShellPresentationSegments)
        {
            if (HasSegment(normalized, segment))
            {
                return SafetyDecision.Forbid(
                    $"{segment} is how the shell decides what to show the user, not something a program installs");
            }
        }

        foreach (string segment in TrustStoreSegments)
        {
            if (HasSegment(normalized, segment))
            {
                return SafetyDecision.Forbid(
                    $"{segment} is a machine-wide trust store, created on demand by anything that checks a signature");
            }
        }

        foreach (string valueOnly in ValueOnlyRegistryPrefixes)
        {
            if (string.Equals(normalized, valueOnly, StringComparison.OrdinalIgnoreCase))
                return SafetyDecision.Forbid($"{valueOnly} is shared; only individual values under it may be removed");
        }

        // The Services key itself, versus a specific service under it.
        if (string.Equals(normalized, @"HKLM\SYSTEM\CurrentControlSet\Services", StringComparison.OrdinalIgnoreCase))
            return SafetyDecision.Forbid("removing the service root would unregister every service on the machine");

        if (normalized.StartsWith(@"HKLM\SYSTEM\CurrentControlSet\Services\", StringComparison.OrdinalIgnoreCase))
        {
            string[] parts = normalized[@"HKLM\SYSTEM\CurrentControlSet\Services\".Length..].Split('\\');

            if (ProtectedServices.Contains(parts[0]))
                return SafetyDecision.Forbid($"{parts[0]} is a core Windows service");

            // A service's own subkeys are its configuration. Removing one while leaving
            // the service is never a legitimate uninstall step — if the service is being
            // removed, its key goes as a unit. Without this rule a plan proposed
            // deleting Tcpip\Parameters, which would take the machine's networking
            // configuration with it.
            if (parts.Length > 1)
            {
                return SafetyDecision.Forbid(
                    $"{parts[0]} already exists; its configuration is not the subject's to remove");
            }
        }

        _ = hive;
        return SafetyDecision.Allow();
    }

    /// <summary>
    /// Rewrites a numbered control set to the boot-selected one, so a rule written once
    /// holds however the path was observed.
    /// </summary>
    /// <remarks>
    /// Kernel events name the concrete set — <c>ControlSet001</c> — while every rule anyone
    /// would write names <c>CurrentControlSet</c>. Without this the protected-service list
    /// and the activity-record list both miss, which is how a plan came to propose
    /// deleting values under <c>ControlSet001\Services\bam</c>.
    /// </remarks>
    /// <summary>
    /// True when a backslash-delimited path contains this exact segment.
    /// </summary>
    /// <remarks>
    /// A substring test would match a key an application legitimately owns and happened
    /// to name something like <c>MySystemCertificatesCache</c>; the boundaries matter.
    /// </remarks>
    private static bool HasSegment(string path, string segment)
    {
        int index = 0;
        while ((index = path.IndexOf(segment, index, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            bool leftOk = index == 0 || path[index - 1] == '\\';
            int after = index + segment.Length;
            bool rightOk = after == path.Length || path[after] == '\\';

            if (leftOk && rightOk) return true;
            index = after;
        }
        return false;
    }

    /// <summary>
    /// Kept as a local name for readability; the one implementation lives in
    /// <see cref="RegistryPath.CanonicalizeControlSet"/> so the analyzer and this policy
    /// cannot drift into disagreeing about what a service key is called.
    /// </summary>
    private static string CanonicalizeControlSet(string normalized)
        => RegistryPath.CanonicalizeControlSet(normalized);

    public SafetyDecision EvaluateRegistryValue(string keyPath, string? valueName)
    {
        SafetyDecision keyDecision = EvaluateRegistryKey(keyPath);

        // A value under a value-only surface is exactly what those rules permit, so a
        // "shared key" refusal does not apply at value granularity.
        if (keyDecision.Verdict == SafetyVerdict.Forbidden)
        {
            string normalized = CanonicalizeControlSet(RegistryPath.Normalize(keyPath));
            bool valueOnlySurface = ValueOnlyRegistryPrefixes.Any(p =>
                string.Equals(normalized, p, StringComparison.OrdinalIgnoreCase));

            if (!valueOnlySurface) return keyDecision;
        }

        if (string.IsNullOrEmpty(valueName))
            return SafetyDecision.Confirm("removing a key's default value can change how the key behaves");

        return SafetyDecision.Allow();
    }

    public SafetyDecision EvaluateService(string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
            return SafetyDecision.Forbid("empty service name");

        return ProtectedServices.Contains(serviceName)
            ? SafetyDecision.Forbid($"{serviceName} is a core Windows service")
            : SafetyDecision.Allow();
    }

    public SafetyDecision EvaluateScheduledTask(string taskPath)
    {
        if (string.IsNullOrWhiteSpace(taskPath))
            return SafetyDecision.Forbid("empty task path");

        string normalized = taskPath.Replace('/', '\\');
        if (!normalized.StartsWith('\\')) normalized = "\\" + normalized;

        // Windows' own maintenance tasks live under \Microsoft\Windows\. Removing one
        // silently disables things like defragmentation, update, or Defender scans.
        if (normalized.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase))
            return SafetyDecision.Forbid("tasks under \\Microsoft\\Windows\\ belong to Windows itself");

        return SafetyDecision.Allow();
    }

    /// <summary>
    /// A validly signed Microsoft binary is almost never the thing being uninstalled;
    /// far more often it is a shared runtime the subject happened to touch.
    /// </summary>
    public static SafetyDecision EvaluateSigner(string? signer, Core.Model.SignatureState state)
    {
        if (signer is null) return SafetyDecision.Allow();

        bool microsoft = signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
        return microsoft && state == Core.Model.SignatureState.SignedValid
            ? SafetyDecision.Confirm($"validly signed by {signer}; likely a shared component rather than part of the subject")
            : SafetyDecision.Allow();
    }
}
