using System.Text.Json;
using CaYaTrace.Core.Naming;
using Microsoft.Win32;

namespace CaYaTrace.Collectors.Snapshots;

/// <summary>One row of a system inventory: a stable identity plus its current state.</summary>
public readonly record struct SnapshotRow(string Identity, string Payload);

/// <summary>
/// Enumerates one class of persistent system state, before and after the subject runs.
/// </summary>
/// <remarks>
/// <para>
/// Snapshots exist because live event capture has two blind spots that matter for
/// uninstall. First, some persistence is established through interfaces that produce
/// no useful kernel event — a scheduled task registered through the Task Scheduler
/// COM service, a firewall rule added through the Windows Firewall API. The registry
/// writes underneath are visible but reconstructing intent from them is guesswork.
/// Second, anything that happened while a collector was starved of buffers is simply
/// missing.
/// </para>
/// <para>
/// A before/after diff catches both, at the cost of losing attribution: it proves the
/// change happened without proving who made it. That is why diff-derived observations
/// carry <c>EvidenceSource.SnapshotDiff</c> and are attributed only when a matching
/// live event corroborates them.
/// </para>
/// </remarks>
public interface ISnapshotProvider
{
    /// <summary>Kind name; also the storage discriminator.</summary>
    string Kind { get; }

    /// <summary>True when this provider needs elevation for a complete picture.</summary>
    bool RequiresElevation { get; }

    IEnumerable<SnapshotRow> Capture();
}

internal static class SnapshotJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Write<T>(T value) => JsonSerializer.Serialize(value, Options);
}

/// <summary>
/// Windows services, read from the registry rather than the Service Control Manager.
/// </summary>
/// <remarks>
/// The registry view is strictly richer: it includes the image path, the service DLL
/// for shared-host services, the account, the start type, and dependencies — all of
/// which a removal plan needs and none of which the SCM API returns in one call. It
/// also sees services that are registered but not yet known to a running SCM.
/// </remarks>
public sealed class ServiceSnapshotProvider : ISnapshotProvider
{
    public string Kind => "service";
    public bool RequiresElevation => false;

    public IEnumerable<SnapshotRow> Capture()
    {
        using RegistryKey? services = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services", writable: false);
        if (services is null) yield break;

        foreach (string name in services.GetSubKeyNames())
        {
            SnapshotRow? row = null;
            try
            {
                using RegistryKey? key = services.OpenSubKey(name, writable: false);
                if (key is null) continue;

                using RegistryKey? parameters = key.OpenSubKey("Parameters", writable: false);

                using RegistryKey? triggers = key.OpenSubKey("TriggerInfo", writable: false);

                var record = new
                {
                    Name = name,
                    DisplayName = key.GetValue("DisplayName") as string,
                    Description = key.GetValue("Description") as string,
                    ImagePath = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                    ServiceDll = parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                    ObjectName = key.GetValue("ObjectName") as string,
                    Start = key.GetValue("Start") as int?,
                    Type = key.GetValue("Type") as int?,
                    ErrorControl = key.GetValue("ErrorControl") as int?,
                    Group = key.GetValue("Group") as string,
                    DependOnService = key.GetValue("DependOnService") as string[],
                    RequiredPrivileges = key.GetValue("RequiredPrivileges") as string[],

                    // Delayed automatic start, which is how software arranges to come up
                    // after whatever would have noticed it starting.
                    DelayedAutostart = key.GetValue("DelayedAutostart") as int?,

                    // What the service control manager does when the service stops
                    // unexpectedly. This is the mechanism behind "I stopped it and it came
                    // back", and a removal that does not disarm it does not work — so the
                    // raw value is carried through for the analyzer to decode.
                    FailureActions = key.GetValue("FailureActions") is byte[] fa
                        ? Convert.ToHexString(fa).ToLowerInvariant()
                        : null,
                    FailureCommand = key.GetValue("FailureCommand") as string,

                    // A protected service cannot be stopped even by an administrator.
                    LaunchProtected = key.GetValue("LaunchProtected") as int?,

                    // Trigger-started services do not appear to start automatically and
                    // still run whenever their trigger fires.
                    HasTriggers = triggers is not null && triggers.SubKeyCount > 0,
                };

                row = new SnapshotRow(name, SnapshotJson.Write(record));
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                // A handful of service keys are ACL'd away even from administrators.
            }

            if (row is not null) yield return row.Value;
        }
    }
}

/// <summary>
/// Scheduled tasks, read from the on-disk task store.
/// </summary>
/// <remarks>
/// Each task under <c>%WinDir%\System32\Tasks</c> is its own XML definition, so reading the
/// directory gives the full trigger/action/principal detail without COM interop and
/// without spawning <c>schtasks.exe</c> — which matters because spawning a process during
/// a monitoring session pollutes the very trace we are collecting.
/// </remarks>
public sealed class ScheduledTaskSnapshotProvider : ISnapshotProvider
{
    public string Kind => "task";
    public bool RequiresElevation => true;

    public IEnumerable<SnapshotRow> Capture()
    {
        string root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");

        if (!Directory.Exists(root)) yield break;

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            yield break;
        }

        foreach (string file in files)
        {
            SnapshotRow? row = null;
            try
            {
                string identity = "\\" + Path.GetRelativePath(root, file).Replace('/', '\\');
                string xml = File.ReadAllText(file);

                var record = new
                {
                    Path = identity,
                    Definition = xml.Length > 65536 ? xml[..65536] : xml,
                    LastWriteUtc = File.GetLastWriteTimeUtc(file),
                };

                row = new SnapshotRow(identity, SnapshotJson.Write(record));
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                // Task files are ACL'd per-principal; skipping one is expected.
            }

            if (row is not null) yield return row.Value;
        }
    }
}

/// <summary>
/// Auto-start entries across the registry Run keys and the Startup folders.
/// </summary>
/// <remarks>
/// The locations covered here are the ones an uninstall must clean up. Deliberately
/// excluded are the deeper hijack surfaces (AppInit_DLLs, IFEO debuggers, LSA
/// packages, Winsock providers) which live in <see cref="PersistenceSnapshotProvider"/>
/// — they belong to a different question: "was anything subverted?" rather than
/// "what did this program register?".
/// </remarks>
public sealed class AutorunSnapshotProvider : ISnapshotProvider
{
    public string Kind => "autorun";
    public bool RequiresElevation => false;

    private static readonly (RegistryHive Hive, string Path, RegistryView View)[] RunKeys =
    {
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry64),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RegistryView.Registry64),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry32),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RegistryView.Registry32),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry64),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RegistryView.Registry64),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", RegistryView.Registry64),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", RegistryView.Registry64),
    };

    public IEnumerable<SnapshotRow> Capture()
    {
        foreach ((RegistryHive hive, string path, RegistryView view) in RunKeys)
        {
            foreach (SnapshotRow row in ReadRunKey(hive, path, view)) yield return row;
        }

        foreach (Environment.SpecialFolder folder in new[]
                 {
                     Environment.SpecialFolder.Startup,
                     Environment.SpecialFolder.CommonStartup,
                 })
        {
            foreach (SnapshotRow row in ReadStartupFolder(folder)) yield return row;
        }
    }

    private static IEnumerable<SnapshotRow> ReadRunKey(RegistryHive hive, string path, RegistryView view)
    {
        string prefix = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
        string viewTag = view == RegistryView.Registry32 ? " (32-bit view)" : string.Empty;

        string[] names;
        RegistryKey? baseKey = null;
        RegistryKey? key = null;
        try
        {
            baseKey = RegistryKey.OpenBaseKey(hive, view);
            key = baseKey.OpenSubKey(path, writable: false);
            if (key is null) yield break;
            names = key.GetValueNames();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            baseKey?.Dispose();
            yield break;
        }

        try
        {
            foreach (string name in names)
            {
                string? data;
                try
                {
                    data = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString();
                }
                catch (Exception ex) when (ex is System.Security.SecurityException or IOException)
                {
                    continue;
                }

                string identity = $@"{prefix}\{path}::{name}{viewTag}";
                yield return new SnapshotRow(identity, SnapshotJson.Write(new
                {
                    Location = $@"{prefix}\{path}",
                    Name = name,
                    Command = data,
                    Bitness = view == RegistryView.Registry32 ? "x86" : "x64",
                }));
            }
        }
        finally
        {
            key.Dispose();
            baseKey.Dispose();
        }
    }

    private static IEnumerable<SnapshotRow> ReadStartupFolder(Environment.SpecialFolder folder)
    {
        string dir = Environment.GetFolderPath(folder);
        if (dir.Length == 0 || !Directory.Exists(dir)) yield break;

        string[] entries;
        try { entries = Directory.GetFileSystemEntries(dir); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { yield break; }

        foreach (string entry in entries)
        {
            yield return new SnapshotRow(entry, SnapshotJson.Write(new
            {
                Location = dir,
                Name = Path.GetFileName(entry),
                Kind = "startup-folder",
            }));
        }
    }
}

/// <summary>
/// Persistence and hijack surfaces beyond the ordinary Run keys.
/// </summary>
/// <remarks>
/// These locations rarely change on a healthy machine, which makes any diff here
/// worth an analyst's attention. They are also where software that does not want to
/// be uninstalled tends to live, so a removal plan that ignores them leaves the thing
/// running.
/// </remarks>
public sealed class PersistenceSnapshotProvider : ISnapshotProvider
{
    public string Kind => "persistence";
    public bool RequiresElevation => true;

    private static readonly (string Label, RegistryHive Hive, string Path)[] Locations =
    {
        ("winlogon",        RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ("appinit-dlls",    RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
        ("lsa",             RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa"),
        ("session-manager", RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager"),
        ("safeboot-minimal",RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal"),
        ("known-dlls",      RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"),
        ("shell-folders",   RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"),
        ("context-menu",    RegistryHive.ClassesRoot,  @"*\shellex\ContextMenuHandlers"),
        ("browser-helper",  RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
    };

    public IEnumerable<SnapshotRow> Capture()
    {
        foreach ((string label, RegistryHive hive, string path) in Locations)
        {
            foreach (SnapshotRow row in ReadValuesAndSubkeys(label, hive, path))
                yield return row;
        }

        // Image File Execution Options debuggers: a classic way to hijack the launch
        // of an arbitrary executable, and something an uninstall must undo.
        foreach (SnapshotRow row in ReadIfeo()) yield return row;
    }

    private static IEnumerable<SnapshotRow> ReadValuesAndSubkeys(string label, RegistryHive hive, string path)
    {
        RegistryKey? baseKey = null;
        RegistryKey? key = null;
        string[] valueNames;
        string[] subKeyNames;

        try
        {
            baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            key = baseKey.OpenSubKey(path, writable: false);
            if (key is null) yield break;
            valueNames = key.GetValueNames();
            subKeyNames = key.GetSubKeyNames();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            baseKey?.Dispose();
            yield break;
        }

        try
        {
            string prefix = HivePrefix(hive);
            foreach (string name in valueNames)
            {
                string? data = null;
                try { data = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString(); }
                catch (Exception ex) when (ex is System.Security.SecurityException or IOException) { }

                yield return new SnapshotRow($@"{prefix}\{path}::{name}", SnapshotJson.Write(new
                {
                    Surface = label,
                    Location = $@"{prefix}\{path}",
                    Name = name,
                    Value = data,
                }));
            }

            foreach (string sub in subKeyNames)
            {
                yield return new SnapshotRow($@"{prefix}\{path}\{sub}", SnapshotJson.Write(new
                {
                    Surface = label,
                    Location = $@"{prefix}\{path}",
                    SubKey = sub,
                }));
            }
        }
        finally
        {
            key.Dispose();
            baseKey.Dispose();
        }
    }

    private static IEnumerable<SnapshotRow> ReadIfeo()
    {
        const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

        RegistryKey? root = null;
        string[] images;
        try
        {
            root = Registry.LocalMachine.OpenSubKey(path, writable: false);
            if (root is null) yield break;
            images = root.GetSubKeyNames();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            root?.Dispose();
            yield break;
        }

        try
        {
            foreach (string image in images)
            {
                string? debugger = null;
                try
                {
                    using RegistryKey? sub = root.OpenSubKey(image, writable: false);
                    debugger = sub?.GetValue("Debugger") as string;
                }
                catch (Exception ex) when (ex is System.Security.SecurityException or IOException) { }

                // Only entries with a debugger set are interesting; the rest are
                // ordinary mitigation-policy entries that ship with Windows.
                if (string.IsNullOrEmpty(debugger)) continue;

                yield return new SnapshotRow($@"HKLM\{path}\{image}::Debugger", SnapshotJson.Write(new
                {
                    Surface = "ifeo-debugger",
                    Image = image,
                    Debugger = debugger,
                }));
            }
        }
        finally
        {
            root.Dispose();
        }
    }

    private static string HivePrefix(RegistryHive hive) => hive switch
    {
        RegistryHive.LocalMachine => "HKLM",
        RegistryHive.CurrentUser => "HKCU",
        RegistryHive.ClassesRoot => "HKCR",
        RegistryHive.Users => "HKU",
        _ => hive.ToString(),
    };
}

/// <summary>Programs listed in Add/Remove Programs, across both registry views.</summary>
public sealed class InstalledProgramSnapshotProvider : ISnapshotProvider
{
    public string Kind => "program";
    public bool RequiresElevation => false;

    private static readonly (RegistryHive Hive, RegistryView View)[] Roots =
    {
        (RegistryHive.LocalMachine, RegistryView.Registry64),
        (RegistryHive.LocalMachine, RegistryView.Registry32),
        (RegistryHive.CurrentUser, RegistryView.Registry64),
    };

    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public IEnumerable<SnapshotRow> Capture()
    {
        foreach ((RegistryHive hive, RegistryView view) in Roots)
        {
            RegistryKey? baseKey = null;
            RegistryKey? uninstall = null;
            string[] products;

            try
            {
                baseKey = RegistryKey.OpenBaseKey(hive, view);
                uninstall = baseKey.OpenSubKey(UninstallPath, writable: false);
                if (uninstall is null) { baseKey.Dispose(); continue; }
                products = uninstall.GetSubKeyNames();
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                baseKey?.Dispose();
                continue;
            }

            try
            {
                string prefix = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                foreach (string product in products)
                {
                    SnapshotRow? row = null;
                    try
                    {
                        using RegistryKey? key = uninstall.OpenSubKey(product, writable: false);
                        if (key is null) continue;

                        row = new SnapshotRow($@"{prefix}\{UninstallPath}\{product}", SnapshotJson.Write(new
                        {
                            Id = product,
                            DisplayName = key.GetValue("DisplayName") as string,
                            DisplayVersion = key.GetValue("DisplayVersion") as string,
                            Publisher = key.GetValue("Publisher") as string,
                            InstallLocation = key.GetValue("InstallLocation") as string,
                            UninstallString = key.GetValue("UninstallString") as string,
                            QuietUninstallString = key.GetValue("QuietUninstallString") as string,
                            InstallDate = key.GetValue("InstallDate")?.ToString(),
                            Bitness = view == RegistryView.Registry32 ? "x86" : "x64",
                        }));
                    }
                    catch (Exception ex) when (ex is System.Security.SecurityException or IOException) { }

                    if (row is not null) yield return row.Value;
                }
            }
            finally
            {
                uninstall.Dispose();
                baseKey.Dispose();
            }
        }
    }
}

/// <summary>
/// Certificates in the machine root and intermediate stores.
/// </summary>
/// <remarks>
/// Tracked for two reasons. A program installing its own trusted root is a serious
/// system-trust change and must be visible. And CaYaTrace's own optional intercepting
/// proxy adds one — snapshotting the store is how the tool proves, after the fact,
/// that its temporary CA was actually removed.
/// </remarks>
public sealed class CertificateSnapshotProvider : ISnapshotProvider
{
    public string Kind => "certificate";
    public bool RequiresElevation => false;

    public IEnumerable<SnapshotRow> Capture()
    {
        foreach (System.Security.Cryptography.X509Certificates.StoreName name in new[]
                 {
                     System.Security.Cryptography.X509Certificates.StoreName.Root,
                     System.Security.Cryptography.X509Certificates.StoreName.CertificateAuthority,
                 })
        {
            foreach (System.Security.Cryptography.X509Certificates.StoreLocation location in new[]
                     {
                         System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine,
                         System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser,
                     })
            {
                List<SnapshotRow> rows = new();
                try
                {
                    using var store = new System.Security.Cryptography.X509Certificates.X509Store(name, location);
                    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

                    foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 cert in store.Certificates)
                    {
                        rows.Add(new SnapshotRow($"{location}/{name}/{cert.Thumbprint}", SnapshotJson.Write(new
                        {
                            Store = $"{location}/{name}",
                            cert.Thumbprint,
                            cert.Subject,
                            cert.Issuer,
                            NotBefore = cert.NotBefore.ToUniversalTime(),
                            NotAfter = cert.NotAfter.ToUniversalTime(),
                        })));
                    }
                }
                catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (SnapshotRow row in rows) yield return row;
            }
        }
    }
}

/// <summary>Kernel drivers currently registered, with their image paths.</summary>
public sealed class DriverSnapshotProvider : ISnapshotProvider
{
    public string Kind => "driver";
    public bool RequiresElevation => false;

    public IEnumerable<SnapshotRow> Capture()
    {
        using RegistryKey? services = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services", writable: false);
        if (services is null) yield break;

        foreach (string name in services.GetSubKeyNames())
        {
            SnapshotRow? row = null;
            try
            {
                using RegistryKey? key = services.OpenSubKey(name, writable: false);
                if (key is null) continue;

                // Type 1 = kernel driver, 2 = file system driver. Everything else is
                // a user-mode service and belongs to the service provider.
                if (key.GetValue("Type") is not int type || (type != 1 && type != 2)) continue;

                row = new SnapshotRow(name, SnapshotJson.Write(new
                {
                    Name = name,
                    ImagePath = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                    Start = key.GetValue("Start") as int?,
                    Type = type,
                    Group = key.GetValue("Group") as string,
                }));
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }

            if (row is not null) yield return row.Value;
        }
    }
}

/// <summary>The hosts file, which malware commonly edits to redirect or block.</summary>
public sealed class HostsFileSnapshotProvider : ISnapshotProvider
{
    public string Kind => "hosts";
    public bool RequiresElevation => false;

    public IEnumerable<SnapshotRow> Capture()
    {
        string path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

        string[] lines;
        try
        {
            if (!File.Exists(path)) yield break;
            lines = File.ReadAllLines(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        int index = 0;
        foreach (string line in lines)
        {
            string trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed[0] == '#') { index++; continue; }
            yield return new SnapshotRow($"{index}:{trimmed}", SnapshotJson.Write(new { Line = trimmed }));
            index++;
        }
    }
}
