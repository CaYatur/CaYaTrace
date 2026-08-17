using CaYaTrace.Collectors.Network;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// Helping an operator get the packet driver, without becoming a way to run anything else.
/// </summary>
/// <remarks>
/// <para>
/// A fresh analysis machine is deliberately clean, so the most useful capture in this tool
/// is unavailable on exactly the machines that most need it. The answer is to name the
/// driver, point at its authors, and — when the operator has already brought the installer
/// into the machine — offer to start it, because getting a file into an isolated virtual
/// machine is the awkward part and hunting for it again afterwards is busywork.
/// </para>
/// <para>
/// The risk that comes with that offer is starting something that merely has the right file
/// name. These tests are mostly about that.
/// </para>
/// </remarks>
public sealed class NpcapSetupTests : IDisposable
{
    private readonly ITestOutputHelper _out;

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "cayatrace-npcap-" + Guid.NewGuid().ToString("n")[..8]);

    public NpcapSetupTests(ITestOutputHelper output)
    {
        _out = output;
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>
    /// The machine's state is always answerable, and always with a reason.
    /// </summary>
    /// <remarks>
    /// Whichever way it comes out here, both outcomes have to be legible: this is the text
    /// an operator reads when the option they ticked cannot do anything.
    /// </remarks>
    [Fact]
    public void TheStateOfTheMachineIsAlwaysExplained()
    {
        NpcapPresence presence = NpcapSetup.Inspect();

        _out.WriteLine($"state: {presence.State}");
        _out.WriteLine($"detail: {presence.Detail}");
        _out.WriteLine($"device: {presence.Device}");
        _out.WriteLine($"installer: {presence.Installer} ({presence.InstallerSigner})");

        Assert.False(string.IsNullOrWhiteSpace(presence.Detail));

        if (presence.State == NpcapState.Ready)
        {
            // Ready means a real adapter was found, and saying which one is what makes the
            // claim checkable.
            Assert.False(string.IsNullOrWhiteSpace(presence.Device));
        }
        else
        {
            // Not ready has to say what would fix it, and the two states have different
            // fixes: install it, or reinstall it with one box ticked.
            Assert.True(presence.State is NpcapState.Missing or NpcapState.NoLoopbackAdapter
                            or NpcapState.Unsupported);
        }
    }

    /// <summary>
    /// A file with the right name and no signature is never offered, and never started.
    /// </summary>
    /// <remarks>
    /// The whole reason the offer is safe. "Run the installer in your Downloads folder" is
    /// otherwise a way to be talked into running something chosen by whatever put a file
    /// called <c>npcap-9.99.exe</c> there — which, on a machine used to analyse malware, is
    /// not a hypothetical arrangement.
    /// </remarks>
    [Fact]
    public void AnUnsignedFileWithTheRightNameIsRefused()
    {
        string impostor = Path.Combine(_root, "npcap-9.99.exe");
        File.WriteAllBytes(impostor, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });

        bool started = NpcapSetup.Launch(impostor, out string error);

        _out.WriteLine($"started: {started}  error: {error}");

        Assert.False(started);
        Assert.False(string.IsNullOrWhiteSpace(error));
        Assert.Contains("signed", error, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A path that no longer exists is a reason, not a crash.</summary>
    /// <remarks>
    /// Reachable in practice: the panel lists an installer, the operator deletes it, and
    /// then presses the button.
    /// </remarks>
    [Fact]
    public void AMissingFileIsReportedRatherThanThrown()
    {
        bool started = NpcapSetup.Launch(Path.Combine(_root, "gone.exe"), out string error);

        Assert.False(started);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    /// <summary>
    /// A signed Windows binary is still refused, because it is not Npcap's.
    /// </summary>
    /// <remarks>
    /// Separates the two halves of the check. Valid signature is necessary and not
    /// sufficient: the publisher has to be the one whose installer this is, or the button
    /// becomes "run any signed executable" with extra steps.
    /// </remarks>
    [Fact]
    public void ASignedFileFromSomebodyElseIsAlsoRefused()
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string signed = Path.Combine(windows, "notepad.exe");

        if (!File.Exists(signed))
        {
            _out.WriteLine("no stand-in available on this machine");
            return;
        }

        bool started = NpcapSetup.Launch(signed, out string error);

        _out.WriteLine($"started: {started}  error: {error}");

        Assert.False(started);
        Assert.Contains("Npcap", error, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The download address points at the authors and nowhere else.</summary>
    /// <remarks>
    /// Asserted because the one thing this feature must never become is a tool that fetches
    /// a driver installer from somewhere convenient.
    /// </remarks>
    [Fact]
    public void TheOnlyAddressOfferedIsTheOfficialOne()
    {
        Assert.StartsWith("https://npcap.com", NpcapSetup.DownloadPage, StringComparison.Ordinal);
    }

    /// <summary>
    /// Whatever the search finds, it is signed by the right publisher.
    /// </summary>
    /// <remarks>
    /// Runs against the real machine, so it usually finds nothing — which is the correct
    /// result and not a skip. What it rules out is the search ever handing back something
    /// that would fail the check at the moment of launching.
    /// </remarks>
    [Fact]
    public void WhateverTheSearchFindsWouldSurviveTheLaunchCheck()
    {
        (string? path, string? signer, string? version) = NpcapSetup.FindInstaller();

        _out.WriteLine($"found: {path ?? "(nothing)"}  signer: {signer}  version: {version}");

        if (path is null)
        {
            Assert.Null(signer);
            return;
        }

        Assert.True(File.Exists(path));
        Assert.False(string.IsNullOrWhiteSpace(signer));
        Assert.True(
            signer!.Contains("Insecure.Com", StringComparison.OrdinalIgnoreCase)
            || signer.Contains("Nmap", StringComparison.OrdinalIgnoreCase),
            $"offered an installer signed by {signer}");
    }
}
