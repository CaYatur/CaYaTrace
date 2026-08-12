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
