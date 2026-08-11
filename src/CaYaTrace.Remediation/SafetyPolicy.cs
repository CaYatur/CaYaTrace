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
    };

    public SafetyPolicy(PathNormalizer paths) => _paths = paths;

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

        string normalized = RegistryPath.Normalize(keyPath);
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
            string service = normalized[@"HKLM\SYSTEM\CurrentControlSet\Services\".Length..].Split('\\')[0];
            if (ProtectedServices.Contains(service))
                return SafetyDecision.Forbid($"{service} is a core Windows service");
        }

        _ = hive;
        return SafetyDecision.Allow();
    }

    public SafetyDecision EvaluateRegistryValue(string keyPath, string? valueName)
    {
        SafetyDecision keyDecision = EvaluateRegistryKey(keyPath);

        // A value under a value-only surface is exactly what those rules permit, so a
        // "shared key" refusal does not apply at value granularity.
        if (keyDecision.Verdict == SafetyVerdict.Forbidden)
        {
            string normalized = RegistryPath.Normalize(keyPath);
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
