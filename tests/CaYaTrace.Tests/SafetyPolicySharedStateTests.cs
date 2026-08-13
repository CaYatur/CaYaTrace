using CaYaTrace.Core.Naming;
using CaYaTrace.Remediation;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// The rules that separate "the subject installed this" from "Windows recorded that
/// the subject ran".
/// </summary>
/// <remarks>
/// <para>
/// Every case here was proposed for deletion by a real plan. A 30-second recording of
/// an installer produced 141 removal items, of which 129 were shared Windows state the
/// program had merely caused to be written: the Background Activity Moderator, the
/// user's zone map, certificate stores created on demand by anything that checks a
/// signature, and the TCP/IP service's configuration.
/// </para>
/// <para>
/// Undoing those is not uninstalling anything. It is damaging state other programs
/// depend on, under the banner of a clean removal — which is worse than leaving residue
/// behind, because the operator asked for the opposite.
/// </para>
/// </remarks>
public sealed class SafetyPolicySharedStateTests
{
    /// <summary>
    /// The state that decides how the shell shows a user their own folders.
    /// </summary>
    /// <remarks>
    /// An operator reported Desktop and Documents disappearing from File Explorer's
    /// navigation pane after a removal. The exact value was never identified, so this
    /// refuses the whole class — which is the right shape of fix regardless of which one
    /// it was, because a program does not have to intend anything for Windows to write
    /// here on its behalf: opening a file dialog writes ComDlg32, showing a window writes
    /// shell bags, being installed writes FileExts.
    /// </remarks>
    [Theory]
    [InlineData(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")]
    [InlineData(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{F42EE2D3-909F-4907-8871-4C22FC0BF756}")]
    [InlineData(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt")]
    [InlineData(@"HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop")]
    [InlineData(@"HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU")]
    public void RefusesToTouchHowTheShellPresentsFolders(string key)
    {
        SafetyDecision decision = Policy.EvaluateRegistryKey(key);

        Assert.Equal(SafetyVerdict.Forbidden, decision.Verdict);
        Assert.Contains("shell", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The dialog and document histories were already refused, for a different reason.
    /// </summary>
    /// <remarks>
    /// Kept as its own case so the overlap is deliberate rather than accidental: these
    /// are records of what a user opened, which the activity-record rule covers and
    /// describes more accurately than a shell-presentation rule would.
    /// </remarks>
    [Theory]
    [InlineData(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU")]
    [InlineData(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")]
    public void DialogAndDocumentHistoriesStayRefused(string key)
        => Assert.Equal(SafetyVerdict.Forbidden, Policy.EvaluateRegistryKey(key).Verdict);

    /// <summary>The same class on the file system: libraries, taskbar pins, Send To.</summary>
    [Theory]
    [InlineData(@"%APPDATA%\Microsoft\Windows\Libraries\Documents.library-ms")]
    [InlineData(@"%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")]
    [InlineData(@"%APPDATA%\Microsoft\Windows\SendTo")]
    public void RefusesToTouchShellStateOnDisk(string path)
    {
        SafetyDecision decision = Policy.EvaluateFile(path);

        Assert.Equal(SafetyVerdict.Forbidden, decision.Verdict);
    }

    /// <summary>
    /// The refusal must not swallow the subject's own registry keys.
    /// </summary>
    /// <remarks>
    /// A rule broad enough to be safe is only useful if it still lets a real removal
    /// happen. These are the shapes a removal has to keep being able to act on.
    /// </remarks>
    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Contoso")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\bf6e56533c2749ec")]
    [InlineData(@"HKCU\SOFTWARE\SomeVendor\SomeProduct")]
    public void StillAllowsTheSubjectsOwnKeys(string key)
    {
        Assert.NotEqual(SafetyVerdict.Forbidden, Policy.EvaluateRegistryKey(key).Verdict);
    }

    private static readonly SafetyPolicy Policy = new(PathNormalizer.CreateForCurrentMachine());

    private static SafetyVerdict Key(string path) => Policy.EvaluateRegistryKey(path).Verdict;

    private static SafetyVerdict Value(string key, string? value)
        => Policy.EvaluateRegistryValue(key, value).Verdict;

    [Theory]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1-2-3-1001")]
    [InlineData(@"HKLM\SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-1-2-3-1001")]
    [InlineData(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap")]
    [InlineData(@"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store")]
    [InlineData(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\TenantRestrictions\Payload")]
    public void WindowsRecordsOfProgramActivityAreNeverRemoved(string path)
        => Assert.Equal(SafetyVerdict.Forbidden, Key(path));

    /// <summary>
    /// A numbered control set and the boot-selected one name the same keys.
    /// </summary>
    /// <remarks>
    /// Kernel events name <c>ControlSet001</c>; every rule anyone would write names
    /// <c>CurrentControlSet</c>. Without canonicalisation the protected-service list misses
    /// entirely, which is how a plan came to propose deleting the TCP/IP configuration.
    /// </remarks>
    [Fact]
    public void ANumberedControlSetIsTheSameAsTheCurrentOne()
    {
        Assert.Equal(SafetyVerdict.Forbidden, Key(@"HKLM\SYSTEM\ControlSet001\Services\RpcSs"));
        Assert.Equal(SafetyVerdict.Forbidden, Key(@"HKLM\SYSTEM\ControlSet003\Services\Dnscache"));

        // A name that merely starts with "ControlSet" is left alone rather than rewritten.
        Assert.NotEqual(SafetyVerdict.Forbidden, Key(@"HKLM\SYSTEM\ControlSetSomethingElse\Foo"));
    }

    [Theory]
    [InlineData(@"HKCU\Software\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates")]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates")]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing")]
    public void TrustStoresAreNeverRemoved(string path)
        => Assert.Equal(SafetyVerdict.Forbidden, Key(path));

    [Fact]
    public void ASegmentRuleDoesNotMatchAKeyThatMerelyContainsTheWord()
    {
        // An application's own key that happens to embed the word must stay removable.
        Assert.NotEqual(SafetyVerdict.Forbidden,
            Key(@"HKCU\Software\Example\SystemCertificatesCache"));
    }

    [Fact]
    public void AServiceMayGoAsAUnitButItsConfigurationIsNotTheSubjectsToTake()
    {
        // Removing the whole key of a service the subject installed is legitimate.
        Assert.NotEqual(SafetyVerdict.Forbidden, Key(@"HKLM\SYSTEM\CurrentControlSet\Services\ExampleAgent"));

        // Removing a subkey while leaving the service is never an uninstall step.
        Assert.Equal(SafetyVerdict.Forbidden, Key(@"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"));
        Assert.Equal(SafetyVerdict.Forbidden, Key(@"HKLM\SYSTEM\CurrentControlSet\Services\ExampleAgent\Parameters"));
    }

    [Fact]
    public void AnAutostartValueStaysRemovableEvenThoughItsKeyIsShared()
    {
        // The Run key itself is shared and must survive; the subject's value under it is
        // exactly what a removal plan exists to take away.
        Assert.Equal(SafetyVerdict.Forbidden, Key(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
        Assert.Equal(SafetyVerdict.Allowed,
            Value(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "ExampleUpdater"));
    }

    [Theory]
    [InlineData(@"%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\ABC123\index.html")]
    [InlineData(@"%LOCALAPPDATA%\Microsoft\Windows\WebCache")]
    [InlineData(@"%APPDATA%\Microsoft\Windows\Recent\example.lnk")]
    public void SharedCachesAreNeverRemoved(string token)
        => Assert.Equal(SafetyVerdict.Forbidden, Policy.EvaluateFile(token).Verdict);

    [Theory]
    [InlineData(@"\Device\HarddiskVolume3")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\??\C:")]
    public void DevicePathsAreNotFiles(string path)
        => Assert.Equal(SafetyVerdict.Forbidden, Policy.EvaluateFile(path).Verdict);

    [Fact]
    public void AnOrdinaryInstallDirectoryIsStillRemovable()
    {
        // The whole point of the tool. None of the rules above may take this away.
        Assert.Equal(SafetyVerdict.Allowed,
            Policy.EvaluateFile(@"%LOCALAPPDATA%\ExampleApp\bin\updater.exe").Verdict);
        Assert.NotEqual(SafetyVerdict.Forbidden, Key(@"HKCU\Software\ExampleApp"));
    }
}
