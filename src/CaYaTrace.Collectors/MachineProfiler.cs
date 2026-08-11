using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;
using Microsoft.Win32;

namespace CaYaTrace.Collectors;

/// <summary>
/// Describes the machine a session was recorded on.
/// </summary>
/// <remarks>
/// This is what makes evidence portable. A path recorded here is only meaningful
/// elsewhere if the reader knows this machine's drive layout, folder redirections,
/// and user SID; a comparison across VMs is only sound if the reader knows the two
/// machines differed. Capturing it up front costs milliseconds and removes an entire
/// class of "why don't these match" confusion later.
/// </remarks>
public static class MachineProfiler
{
    public static MachineProfile Describe(PathNormalizer paths)
    {
        var profile = new MachineProfile
        {
            MachineName = Environment.MachineName,
            OsVersion = RuntimeInformation.OSDescription,
            OsBuild = ReadOsBuild(),
            Architecture = RuntimeInformation.OSArchitecture.ToString(),
            Locale = CultureInfo.CurrentUICulture.Name,
            TimeZone = TimeZoneInfo.Local.Id,
        };

        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            profile.UserSid = identity.User?.Value;
            profile.UserName = identity.Name;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Running as a service account with a restricted token.
        }

        (profile.IsVirtualMachine, profile.Hypervisor) = DetectVirtualization();
        profile.MachineId = ComputeMachineId(profile);

        foreach ((string device, string drive) in paths.VolumeMap)
            profile.VolumeMap[device] = drive;

        foreach ((string token, string concrete) in paths.Tokens)
            profile.KnownFolders[token] = concrete;

        return profile;
    }

    private static string ReadOsBuild()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
            if (key is null) return Environment.OSVersion.Version.ToString();

            string? build = key.GetValue("CurrentBuildNumber") as string;
            object? ubr = key.GetValue("UBR");
            string? displayVersion = key.GetValue("DisplayVersion") as string;

            var sb = new StringBuilder();
            if (displayVersion is { Length: > 0 }) sb.Append(displayVersion).Append(' ');
            sb.Append(build ?? Environment.OSVersion.Version.Build.ToString(CultureInfo.InvariantCulture));
            if (ubr is not null) sb.Append('.').Append(ubr);
            return sb.ToString();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return Environment.OSVersion.Version.ToString();
        }
    }

    /// <summary>
    /// Best-effort hypervisor detection.
    /// </summary>
    /// <remarks>
    /// Reported rather than acted on. Some software behaves differently under a
    /// hypervisor — malware especially — so an analyst comparing a VM run against a
    /// bare-metal run needs to know which was which. CaYaTrace does not attempt to
    /// hide the VM; that would be an evasion feature, not an analysis one.
    /// </remarks>
    private static (bool, string?) DetectVirtualization()
    {
        try
        {
            using RegistryKey? system = Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\BIOS", writable: false);

            string vendor = (system?.GetValue("SystemManufacturer") as string ?? string.Empty).ToLowerInvariant();
            string product = (system?.GetValue("SystemProductName") as string ?? string.Empty).ToLowerInvariant();
            string combined = vendor + " " + product;

            foreach ((string needle, string name) in new[]
                     {
                         ("vmware", "VMware"),
                         ("virtualbox", "VirtualBox"),
                         ("innotek", "VirtualBox"),
                         ("qemu", "QEMU/KVM"),
                         ("kvm", "QEMU/KVM"),
                         ("xen", "Xen"),
                         ("parallels", "Parallels"),
                         ("microsoft corporation virtual", "Hyper-V"),
                         ("virtual machine", "Hyper-V"),
                     })
            {
                if (combined.Contains(needle, StringComparison.Ordinal)) return (true, name);
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Fall through to "unknown".
        }

        return (false, null);
    }

    /// <summary>
    /// A stable, non-identifying id for this machine.
    /// </summary>
    /// <remarks>
    /// Derived by hashing machine name, user SID, and OS build rather than reading a
    /// hardware serial or the Windows MachineGuid. Two VMs cloned from one image get
    /// different ids once renamed, which is what multi-VM comparison needs — and the
    /// value does not carry anything that identifies the operator's hardware into an
    /// exported report.
    /// </remarks>
    private static string ComputeMachineId(MachineProfile profile)
    {
        string material = string.Join('|', profile.MachineName, profile.UserSid ?? "-", profile.OsBuild);
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
    }
}
