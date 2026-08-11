using System.Runtime.InteropServices;
using System.Text;

namespace CaYaTrace.Core.Naming;

/// <summary>
/// Converts the many spellings Windows uses for the same file into one canonical
/// form, and tokenizes machine-specific prefixes so paths can be compared across
/// machines.
/// </summary>
/// <remarks>
/// <para>
/// The kernel reports NT paths (<c>\Device\HarddiskVolume3\Windows\...</c>), the Win32
/// layer reports DOS paths (<c>C:\Windows\...</c>), and various APIs emit long-path
/// (<c>\\?\C:\...</c>) or object-manager (<c>\??\C:\...</c>) forms. Left alone, the same
/// file appears as four unrelated artifacts and every downstream count is wrong.
/// </para>
/// <para>
/// Tokenization exists for the cross-machine case. <c>C:\Users\cagan\AppData\Roaming\X</c>
/// on the analyst's box and <c>C:\Users\Admin\AppData\Roaming\X</c> on a VM are the same
/// artifact; both tokenize to <c>%APPDATA%\X</c>. This is what makes a removal package
/// recorded on one machine applicable on another.
/// </para>
/// </remarks>
public sealed class PathNormalizer
{
    private readonly Dictionary<string, string> _deviceToDrive;
    private readonly List<KeyValuePair<string, string>> _tokens;

    private PathNormalizer(Dictionary<string, string> deviceToDrive, List<KeyValuePair<string, string>> tokens)
    {
        _deviceToDrive = deviceToDrive;
        _tokens = tokens;
    }

    /// <summary>Device-path to drive-letter map discovered on this machine.</summary>
    public IReadOnlyDictionary<string, string> VolumeMap => _deviceToDrive;

    /// <summary>Token to concrete-path map for this machine, longest path first.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Tokens => _tokens;

    public static PathNormalizer CreateForCurrentMachine()
    {
        var devices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DriveInfo drive in SafeGetDrives())
        {
            string letter = drive.Name.TrimEnd('\\');       // "C:"
            string? target = QueryDosDeviceSafe(letter);     // "\Device\HarddiskVolume3"
            if (!string.IsNullOrEmpty(target))
                devices[target] = letter;
        }

        return new PathNormalizer(devices, BuildTokenTable());
    }

    /// <summary>
    /// Builds a normalizer for a foreign machine from a serialized map, so evidence
    /// recorded elsewhere can be re-expanded against local paths.
    /// </summary>
    public static PathNormalizer CreateForRemote(
        IDictionary<string, string> volumeMap,
        IDictionary<string, string> tokenMap)
    {
        var devices = new Dictionary<string, string>(volumeMap, StringComparer.OrdinalIgnoreCase);
        var tokens = tokenMap
            .Where(static kv => !string.IsNullOrEmpty(kv.Value))
            .OrderByDescending(static kv => kv.Value.Length)
            .ToList();
        return new PathNormalizer(devices, tokens);
    }

    /// <summary>
    /// Reduces any Windows path spelling to a plain DOS path. Returns the input
    /// unchanged when it is already canonical or cannot be resolved.
    /// </summary>
    public string Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return string.Empty;

        string path = raw.Trim();

        // Long-path and object-manager prefixes are pure noise once resolved.
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            path = @"\\" + path[8..];
        else if (path.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase))
            path = @"\\" + path[8..];
        else if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
            path = path[4..];
        else if (path.StartsWith(@"\??\", StringComparison.Ordinal))
            path = path[4..];

        // \SystemRoot\System32\drivers\x.sys — used by driver load events.
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(GetSystemRoot(), path[12..]);

        // Bare "system32\drivers\x.sys" from some driver-load paths.
        else if (path.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(GetSystemRoot(), path);

        if (path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            path = ResolveDevicePath(path);

        return path.Replace('/', '\\');
    }

    private string ResolveDevicePath(string path)
    {
        // Longest device prefix wins: \Device\HarddiskVolume1 must not shadow
        // \Device\HarddiskVolume10.
        string? bestDevice = null;
        foreach (string device in _deviceToDrive.Keys)
        {
            if (path.Length <= device.Length)
                continue;
            if (!path.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                continue;
            // Must break on a separator, not mid-segment.
            if (path[device.Length] != '\\')
                continue;
            if (bestDevice is null || device.Length > bestDevice.Length)
                bestDevice = device;
        }

        if (bestDevice is not null)
            return _deviceToDrive[bestDevice] + path[bestDevice.Length..];

        // Named pipes and mailslots are legitimate targets; keep them recognisable
        // rather than mangling them into a fake drive path.
        if (path.StartsWith(@"\Device\NamedPipe\", StringComparison.OrdinalIgnoreCase))
            return @"\\.\pipe\" + path[18..];
        if (path.StartsWith(@"\Device\Mailslot\", StringComparison.OrdinalIgnoreCase))
            return @"\\.\mailslot\" + path[17..];

        return path;
    }

    /// <summary>
    /// Replaces the machine-specific prefix of a path with a portable token.
    /// <c>C:\Users\cagan\AppData\Roaming\App</c> becomes <c>%APPDATA%\App</c>.
    /// </summary>
    public string Tokenize(string? path)
    {
        string full = Normalize(path);
        if (full.Length == 0) return full;

        foreach ((string token, string concrete) in _tokens)
        {
            if (concrete.Length == 0 || full.Length < concrete.Length)
                continue;
            if (!full.StartsWith(concrete, StringComparison.OrdinalIgnoreCase))
                continue;
            if (full.Length > concrete.Length && full[concrete.Length] != '\\')
                continue;

            return full.Length == concrete.Length ? token : token + full[concrete.Length..];
        }

        return full;
    }

    /// <summary>Expands a tokenized path against this machine's folder layout.</summary>
    public string Expand(string? tokenized)
    {
        if (string.IsNullOrEmpty(tokenized)) return string.Empty;
        if (tokenized[0] != '%') return tokenized;

        foreach ((string token, string concrete) in _tokens)
        {
            if (concrete.Length == 0) continue;
            if (!tokenized.StartsWith(token, StringComparison.OrdinalIgnoreCase)) continue;
            if (tokenized.Length > token.Length && tokenized[token.Length] != '\\') continue;

            return tokenized.Length == token.Length ? concrete : concrete + tokenized[token.Length..];
        }

        return tokenized;
    }

    /// <summary>True when the path resolves under a Windows-owned directory.</summary>
    public bool IsSystemPath(string? path)
    {
        string token = Tokenize(path);
        return token.StartsWith("%WINDIR%", StringComparison.OrdinalIgnoreCase)
            || token.StartsWith("%SYSTEM32%", StringComparison.OrdinalIgnoreCase)
            || token.StartsWith("%SYSWOW64%", StringComparison.OrdinalIgnoreCase);
    }

    private static List<KeyValuePair<string, string>> BuildTokenTable()
    {
        // Order matters at build time only for readability; the list is sorted by
        // descending concrete length so the most specific prefix always matches first
        // (%LOCALAPPDATA% must beat %USERPROFILE%).
        var raw = new List<KeyValuePair<string, string>>
        {
            new("%SYSTEM32%",       Environment.GetFolderPath(Environment.SpecialFolder.System)),
            new("%SYSWOW64%",       Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)),
            new("%WINDIR%",         GetSystemRoot()),
            new("%PROGRAMFILES(X86)%", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)),
            new("%PROGRAMFILES%",   Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)),
            new("%PROGRAMDATA%",    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)),
            new("%LOCALAPPDATA%",   Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)),
            new("%APPDATA%",        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
            new("%TEMP%",           Path.TrimEndingDirectorySeparator(Path.GetTempPath())),
            new("%STARTMENU%",      Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu)),
            new("%DESKTOP%",        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)),
            new("%PUBLIC%",         Environment.GetEnvironmentVariable("PUBLIC") ?? string.Empty),
            new("%USERPROFILE%",    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
            new("%USERSROOT%",      GetUsersRoot()),
            new("%SYSTEMDRIVE%",    Environment.GetEnvironmentVariable("SystemDrive") ?? "C:"),
        };

        return raw
            .Where(static kv => !string.IsNullOrEmpty(kv.Value))
            .Select(static kv => new KeyValuePair<string, string>(
                kv.Key, Path.TrimEndingDirectorySeparator(kv.Value)))
            .GroupBy(static kv => kv.Value, StringComparer.OrdinalIgnoreCase)
            .Select(static g => g.First())
            .OrderByDescending(static kv => kv.Value.Length)
            .ToList();
    }

    private static string GetUsersRoot()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string? parent = Path.GetDirectoryName(profile);
        return parent ?? string.Empty;
    }

    private static string GetSystemRoot()
        => Environment.GetEnvironmentVariable("SystemRoot")
           ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private static DriveInfo[] SafeGetDrives()
    {
        try { return DriveInfo.GetDrives(); }
        catch (IOException) { return Array.Empty<DriveInfo>(); }
        catch (UnauthorizedAccessException) { return Array.Empty<DriveInfo>(); }
    }

    private static string? QueryDosDeviceSafe(string deviceName)
    {
        try
        {
            var buffer = new StringBuilder(512);
            uint length = QueryDosDeviceW(deviceName, buffer, (uint)buffer.Capacity);
            return length == 0 ? null : buffer.ToString();
        }
        catch (DllNotFoundException) { return null; }
        catch (EntryPointNotFoundException) { return null; }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);
}
