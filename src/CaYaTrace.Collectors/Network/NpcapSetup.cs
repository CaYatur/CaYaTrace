using System.Diagnostics;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Collectors.Network;

/// <summary>What the machine has, and what would fix it.</summary>
public enum NpcapState
{
    /// <summary>Everything needed for a loopback capture is present.</summary>
    Ready = 0,

    /// <summary>No packet driver at all.</summary>
    Missing = 1,

    /// <summary>
    /// The driver is there but has no loopback adapter, which is a different fix: the
    /// installer's "Support loopback traffic" option was cleared during setup.
    /// </summary>
    NoLoopbackAdapter = 2,

    /// <summary>Not Windows, so the question does not arise.</summary>
    Unsupported = 3,
}

/// <summary>
/// What the machine has, an installer it could use, and where to get one.
/// </summary>
/// <param name="Installer">
/// An installer already sitting on this machine, verified as the real one. Null when none
/// was found — which is the normal case, and not a problem to solve by fetching one.
/// </param>
public sealed record NpcapPresence(
    NpcapState State,
    string Detail,
    string? Device,
    string? Installer,
    string? InstallerSigner,
    string? InstallerVersion);

/// <summary>
/// Helps an operator get the packet driver the loopback capture needs.
/// </summary>
/// <remarks>
/// <para>
/// A fresh analysis virtual machine has nothing on it, which is the point of one — so the
/// most likely state of the most useful capture in this tool is "unavailable", and leaving
/// that as a sentence in a log is not good enough.
/// </para>
/// <para>
/// <b>What this deliberately does not do.</b> It does not ship the installer and it does not
/// install anything unattended. Npcap's free licence covers neither: redistributing it
/// inside another product and running it silently are both reserved for their paid OEM
/// licence, and a tool that quietly did either would be putting its user in breach of a
/// licence they never read. So this finds, verifies, and offers — the operator downloads it
/// and clicks through it, which is also the only way they see the terms they are agreeing to.
/// </para>
/// <para>
/// <b>Why launching a found installer is still worth doing.</b> Getting a file into an
/// isolated virtual machine is the awkward part of this workflow, and once it is in there,
/// finding it again in Explorer is busywork. The one real risk is launching something that
/// merely has the right file name, which is why nothing is offered until its Authenticode
/// signature says who published it.
/// </para>
/// </remarks>
public static class NpcapSetup
{
    /// <summary>The official download page.</summary>
    public const string DownloadPage = "https://npcap.com/#download";

    /// <summary>
    /// Names on the certificate that signs the real installer.
    /// </summary>
    /// <remarks>
    /// Matched as a substring of the signer's subject, because the exact common name has
    /// changed across releases while the organisation has not. A file that merely looks
    /// like <c>npcap-1.88.exe</c> is not offered.
    /// </remarks>
    private static readonly string[] Publishers = { "Insecure.Com", "Nmap" };

    /// <summary>Where an operator plausibly put a file they just brought into a machine.</summary>
    private static IEnumerable<string> SearchFolders()
    {
        string? beside = Path.GetDirectoryName(Environment.ProcessPath ?? string.Empty);
        if (beside is { Length: > 0 }) yield return beside;

        foreach (Environment.SpecialFolder folder in new[]
                 {
                     Environment.SpecialFolder.UserProfile,
                     Environment.SpecialFolder.DesktopDirectory,
                     Environment.SpecialFolder.CommonDesktopDirectory,
                 })
        {
            string path = Environment.GetFolderPath(folder);
            if (path.Length > 0) yield return path;
        }

        // Downloads has no SpecialFolder, and this is where a browser puts it.
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (profile.Length > 0) yield return Path.Combine(profile, "Downloads");
    }

    /// <summary>Reads the machine and reports what would fix it.</summary>
    public static NpcapPresence Inspect()
    {
        if (!OperatingSystem.IsWindows())
            return new NpcapPresence(NpcapState.Unsupported, "loopback capture is a Windows feature", null, null, null, null);

        bool available = LoopbackCapture.IsAvailable(out string reason);

        if (available)
        {
            string? device = reason.Contains('\\', StringComparison.Ordinal)
                ? reason[reason.IndexOf('\\', StringComparison.Ordinal)..]
                : null;

            return new NpcapPresence(NpcapState.Ready, reason, device, null, null, null);
        }

        (string? installer, string? signer, string? version) = FindInstaller();

        // The driver being present without a loopback adapter is a different problem with a
        // different answer — reinstalling with one checkbox ticked, rather than installing.
        NpcapState state = DriverPresent()
            ? NpcapState.NoLoopbackAdapter
            : NpcapState.Missing;

        return new NpcapPresence(state, reason, null, installer, signer, version);
    }

    /// <summary>True when the packet driver is installed, whatever adapters it has.</summary>
    private static bool DriverPresent()
    {
        string system = Environment.GetFolderPath(Environment.SpecialFolder.System);

        return File.Exists(Path.Combine(system, "Npcap", "wpcap.dll"))
               || File.Exists(Path.Combine(system, "wpcap.dll"));
    }

    /// <summary>
    /// Finds an installer already on this machine and checks who signed it.
    /// </summary>
    /// <remarks>
    /// Newest version first, by the number in the file name, because somebody who has
    /// fetched two of them wants the later one. The signature check is not decoration: a
    /// button that runs whatever is called <c>npcap-setup.exe</c> in the Downloads folder is
    /// a way to be talked into running something else entirely.
    /// </remarks>
    public static (string? Path, string? Signer, string? Version) FindInstaller()
    {
        var candidates = new List<string>();

        foreach (string folder in SearchFolders())
        {
            try
            {
                if (!Directory.Exists(folder)) continue;

                foreach (string pattern in new[] { "npcap-*.exe", "npcap.exe" })
                    candidates.AddRange(Directory.GetFiles(folder, pattern, SearchOption.TopDirectoryOnly));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        foreach (string candidate in candidates
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(VersionOf)
                     .ThenByDescending(static path => new FileInfo(path).LastWriteTimeUtc))
        {
            (SignatureState state, string? signer) = Etw.ProcessMetadata.Verify(candidate);

            if (state != SignatureState.SignedValid) continue;
            if (signer is not { Length: > 0 }) continue;
            if (!Publishers.Any(p => signer.Contains(p, StringComparison.OrdinalIgnoreCase))) continue;

            return (candidate, signer, DescribeVersion(candidate));
        }

        return (null, null, null);
    }

    private static Version VersionOf(string path)
    {
        string name = Path.GetFileNameWithoutExtension(path);
        int dash = name.IndexOf('-', StringComparison.Ordinal);

        return dash >= 0 && Version.TryParse(name[(dash + 1)..], out Version? parsed)
            ? parsed
            : new Version(0, 0);
    }

    private static string? DescribeVersion(string path)
    {
        Version parsed = VersionOf(path);
        if (parsed.Major > 0) return parsed.ToString();

        try { return FileVersionInfo.GetVersionInfo(path).ProductVersion; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// Starts an installer the operator already has, with its own interface.
    /// </summary>
    /// <remarks>
    /// <para>
    /// No arguments, deliberately. Unattended installation is an option of Npcap's paid
    /// licence rather than a flag to be discovered, and the free installer's screens are
    /// also where the operator reads the terms and chooses whether to support loopback
    /// traffic — which is the whole reason they are here.
    /// </para>
    /// <para>
    /// Elevated, because a driver install is. The path is re-verified rather than trusted
    /// from whenever it was found: between the listing and the click, the file may have been
    /// replaced.
    /// </para>
    /// </remarks>
    public static bool Launch(string installerPath, out string error)
    {
        error = string.Empty;

        if (!File.Exists(installerPath))
        {
            error = "that installer is no longer there";
            return false;
        }

        (SignatureState state, string? signer) = Etw.ProcessMetadata.Verify(installerPath);

        if (state != SignatureState.SignedValid
            || signer is not { Length: > 0 }
            || !Publishers.Any(p => signer.Contains(p, StringComparison.OrdinalIgnoreCase)))
        {
            error = "that file is not a signed Npcap installer, so it was not started";
            return false;
        }

        try
        {
            var info = new ProcessStartInfo(installerPath)
            {
                UseShellExecute = true,
                Verb = "runas",
            };

            return Process.Start(info) is not null;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            // Cancelling the elevation prompt lands here, and is a decision rather than a
            // failure.
            error = ex.NativeErrorCode == 1223
                ? "the elevation prompt was dismissed, so nothing was started"
                : ex.Message;

            return false;
        }
    }
}
