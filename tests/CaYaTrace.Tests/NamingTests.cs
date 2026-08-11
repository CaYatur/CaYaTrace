using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Path and key canonicalization. Every duplicate spelling that survives here becomes
/// a duplicate artifact in the tree and a duplicate entry in a removal plan.
/// </summary>
public sealed class NamingTests
{
    private static PathNormalizer Normalizer() => PathNormalizer.CreateForCurrentMachine();

    [Theory]
    [InlineData(@"\??\C:\Windows\notepad.exe", @"C:\Windows\notepad.exe")]
    [InlineData(@"\\?\C:\Windows\notepad.exe", @"C:\Windows\notepad.exe")]
    [InlineData(@"C:\Windows\notepad.exe", @"C:\Windows\notepad.exe")]
    public void PrefixSpellingsCollapseToOnePath(string input, string expected)
        => Assert.Equal(expected, Normalizer().Normalize(input), ignoreCase: true);

    [Fact]
    public void UncLongPathsKeepTheirUncForm()
        => Assert.Equal(@"\\server\share\file.txt", Normalizer().Normalize(@"\\?\UNC\server\share\file.txt"), ignoreCase: true);

    [Fact]
    public void NamedPipesStayRecognisable()
        => Assert.Equal(@"\\.\pipe\lsass", Normalizer().Normalize(@"\Device\NamedPipe\lsass"), ignoreCase: true);

    [Fact]
    public void UserProfilePathsTokenizeSoTheyPortAcrossMachines()
    {
        PathNormalizer n = Normalizer();
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        string token = n.Tokenize(Path.Combine(appData, "Example", "config.json"));

        Assert.StartsWith("%APPDATA%", token, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(@"Example\config.json", token, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TokenizeThenExpandIsIdentityOnThisMachine()
    {
        PathNormalizer n = Normalizer();
        string original = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Vendor", "tool.exe");

        Assert.Equal(original, n.Expand(n.Tokenize(original)), ignoreCase: true);
    }

    [Fact]
    public void LocalAppDataWinsOverUserProfile()
    {
        // %USERPROFILE% is a prefix of %LOCALAPPDATA%; matching the shorter one first
        // would make every local-appdata path unportable.
        PathNormalizer n = Normalizer();
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        Assert.StartsWith("%LOCALAPPDATA%", n.Tokenize(Path.Combine(local, "x.txt")), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(@"\REGISTRY\MACHINE\SOFTWARE\Example", @"HKLM\SOFTWARE\Example")]
    [InlineData(@"HKEY_LOCAL_MACHINE\SOFTWARE\Example", @"HKLM\SOFTWARE\Example")]
    [InlineData(@"HKLM\SOFTWARE\Example", @"HKLM\SOFTWARE\Example")]
    [InlineData(@"\REGISTRY\USER\S-1-5-18\Environment", @"HKU\S-1-5-18\Environment")]
    public void RegistrySpellingsCollapse(string input, string expected)
        => Assert.Equal(expected, RegistryPath.Normalize(input, userSidOverride: "S-1-5-21-NOBODY"), ignoreCase: true);

    [Fact]
    public void CurrentUserHiveFoldsToHkcuSoPackagesPortAcrossAccounts()
    {
        const string sid = "S-1-5-21-1111-2222-3333-1001";

        string normalized = RegistryPath.Normalize($@"\REGISTRY\USER\{sid}\Software\Example", sid);

        Assert.Equal(@"HKCU\Software\Example", normalized, ignoreCase: true);
    }

    [Fact]
    public void ClassesCompanionHiveFoldsUnderHkcuSoftwareClasses()
    {
        const string sid = "S-1-5-21-1111-2222-3333-1001";

        string normalized = RegistryPath.Normalize($@"\REGISTRY\USER\{sid}_Classes\AppX", sid);

        Assert.Equal(@"HKCU\Software\Classes\AppX", normalized, ignoreCase: true);
    }

    [Fact]
    public void Wow64ViewsUnifyForCrossMachineComparison()
    {
        Assert.True(RegistryPath.IsWow64Redirected(@"HKLM\SOFTWARE\WOW6432Node\Example"));
        Assert.Equal(@"HKLM\SOFTWARE\Example",
            RegistryPath.StripWow64(@"HKLM\SOFTWARE\WOW6432Node\Example"), ignoreCase: true);
    }

    [Fact]
    public void ValueNamesContainingBackslashesSurviveRoundTrip()
    {
        string joined = RegistryPath.JoinValue(@"HKLM\SOFTWARE\X", @"weird\name");

        (string key, string? value) = RegistryPath.SplitValue(joined);

        Assert.Equal(@"HKLM\SOFTWARE\X", key);
        Assert.Equal(@"weird\name", value);
    }
}

/// <summary>
/// Handle-to-name resolution. A miss here turns a real finding into
/// "wrote 4096 bytes to 0xFFFFCE0812A43B90".
/// </summary>
public sealed class HandleResolutionTests
{
    [Fact]
    public void FileObjectResolvesAfterOpenAndStopsAfterClose()
    {
        var resolver = new FileObjectResolver(PathNormalizer.CreateForCurrentMachine());

        resolver.NoteOpen(fileObject: 0xAAAA, fileKey: 0xBBBB, name: @"C:\Temp\example.exe");
        Assert.Equal(@"C:\Temp\example.exe", resolver.Resolve(0xAAAA, 0), ignoreCase: true);

        resolver.NoteClose(0xAAAA);

        // The per-handle mapping is gone, but the file-control-block mapping remains,
        // because the file still exists and other handles may reference it.
        Assert.Equal(string.Empty, resolver.Resolve(0xAAAA, 0));
        Assert.Equal(@"C:\Temp\example.exe", resolver.Resolve(0, 0xBBBB), ignoreCase: true);
    }

    [Fact]
    public void RecycledFileObjectDoesNotInheritThePreviousFilesName()
    {
        var resolver = new FileObjectResolver(PathNormalizer.CreateForCurrentMachine());

        resolver.NoteOpen(0xAAAA, 0x1111, @"C:\Temp\first.txt");
        resolver.NoteClose(0xAAAA);
        resolver.NoteOpen(0xAAAA, 0x2222, @"C:\Temp\second.txt");

        Assert.Equal(@"C:\Temp\second.txt", resolver.Resolve(0xAAAA, 0), ignoreCase: true);
    }

    [Fact]
    public void RenameUpdatesFuturelookupsAndReturnsTheOldPath()
    {
        var resolver = new FileObjectResolver(PathNormalizer.CreateForCurrentMachine());
        resolver.NoteOpen(0xAAAA, 0xBBBB, @"C:\Temp\old.tmp");

        string old = resolver.ApplyRename(0xAAAA, 0xBBBB, @"C:\Program Files\App\app.exe");

        Assert.Equal(@"C:\Temp\old.tmp", old, ignoreCase: true);
        Assert.Equal(@"C:\Program Files\App\app.exe", resolver.Resolve(0xAAAA, 0xBBBB), ignoreCase: true);
    }

    [Fact]
    public void RegistryOperationsResolveThroughTheKeyControlBlock()
    {
        var resolver = new RegistryKeyResolver(userSidOverride: "S-1-5-21-NOBODY");
        resolver.NoteKcb(0xC0DE, @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion");

        string full = resolver.Resolve(0xC0DE, "Run");

        Assert.Equal(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", full, ignoreCase: true);
    }

    [Fact]
    public void UnresolvedKcbStillReportsTheRelativeNameRatherThanNothing()
    {
        var resolver = new RegistryKeyResolver();

        // The KCB announcement was lost — typically to a buffer overrun. A partial
        // answer still tells the analyst which value moved.
        string result = resolver.Resolve(0xDEAD, "Run");

        Assert.Equal("Run", result);
    }

    [Fact]
    public void EvictionIsCountedSoDegradedSessionsAreVisible()
    {
        var map = new HandleNameMap(capacity: 4);
        for (ulong i = 1; i <= 10; i++) map.Set(i, $@"C:\file{i}.txt");

        Assert.True(map.Evictions >= 6);
        Assert.False(map.TryGet(1, out _));
        Assert.True(map.TryGet(10, out _));
        Assert.True(map.HitRate < 1.0);
    }
}

/// <summary>
/// Regressions found by running the engine elevated against a live system, rather
/// than by reasoning about it.
/// </summary>
public sealed class LiveCaptureRegressionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 11, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ContainerSiloHivesResolveToTheUserHive()
    {
        // Windows 11 26H1 presented the per-user hive through a container silo
        // namespace. Untranslated it yielded paths that look absolute but match
        // nothing, so a removal plan built from them would target keys that do not
        // exist. Observed verbatim during an elevated capture.
        const string native =
            @"\REGISTRY\WC\Silo8472eec8-2de1-6d7a-38ae-641b5e3bc5fcuser_sid\Software\CaYaTraceProbe";

        Assert.Equal(@"HKCU\Software\CaYaTraceProbe", RegistryPath.Normalize(native), ignoreCase: true);
    }

    [Fact]
    public void UnrecognisedSiloIsLeftVerbatimRatherThanGuessed()
    {
        const string native = @"\REGISTRY\WC\SiloSomethingElse\Software\X";

        // A wrong hive is worse than an obviously unresolved one.
        Assert.Equal(native, RegistryPath.Normalize(native));
    }

    [Fact]
    public void PlaceholderProcessIsUpgradedToTheKernelIdentity()
    {
        // A process launched suspended is seeded before the kernel announces it. If
        // the two records fail to unify, the scope flag stays on the placeholder while
        // every real event attaches to the kernel-keyed node — the tree silently
        // empties. This happened, and cost a full capture to notice.
        var table = new ProcessTable();

        var placeholder = new ProcessNode
        {
            Key = new ProcessKey(4812, 0, 0),
            ImagePath = @"C:\Windows\System32\reg.exe",
            StartTime = T0,
            InScope = true,
            ScopeReason = "root",
        };
        table.AddOrUpdate(placeholder);

        var fromKernel = new ProcessNode
        {
            Key = ProcessKey.FromStartKey(4812, 0xFFFF808D6CDD20C0, T0.AddMilliseconds(3)),
            ImagePath = "reg.exe",
            StartTime = T0.AddMilliseconds(3),
        };
        ProcessNode merged = table.AddOrUpdate(fromKernel);

        Assert.Single(table.Snapshot());
        Assert.True(merged.Key.IsStrong);
        Assert.Equal(0xFFFF808D6CDD20C0UL, merged.Key.StartKey);
        Assert.True(merged.InScope);
        Assert.Equal("root", merged.ScopeReason);
        Assert.Equal(@"C:\Windows\System32\reg.exe", merged.ImagePath);
        Assert.Equal(merged.Key, table.Resolve(4812, T0.AddSeconds(1)));
    }

    [Fact]
    public void UpgradingAKeyRepointsTheParentsChildList()
    {
        var table = new ProcessTable();
        var parent = new ProcessNode { Key = ProcessKey.FromStartKey(100, 0xA, T0), StartTime = T0 };
        table.AddOrUpdate(parent);

        var placeholder = new ProcessNode
        {
            Key = new ProcessKey(200, 0, 0),
            ParentPid = 100,
            StartTime = T0.AddSeconds(1),
        };
        table.AddOrUpdate(placeholder);
        Assert.Contains(new ProcessKey(200, 0, 0), parent.Children);

        var fromKernel = new ProcessNode
        {
            Key = ProcessKey.FromStartKey(200, 0xB, T0.AddSeconds(1)),
            StartTime = T0.AddSeconds(1),
        };
        ProcessNode merged = table.AddOrUpdate(fromKernel);

        Assert.Single(parent.Children);
        Assert.Equal(merged.Key, parent.Children[0]);
    }

    [Fact]
    public void DeferredResolutionRecoversNamesAnnouncedLater()
    {
        // The kernel emits its file-name rundown when the session stops, not when it
        // starts, so an operation on a pre-existing handle is unresolvable at the
        // moment it happens and resolvable a few seconds later.
        var resolver = new FileObjectResolver(PathNormalizer.CreateForCurrentMachine());

        Assert.False(resolver.TryResolve(0xAAAA, 0xBBBB, null, out _));

        resolver.NoteName(0xBBBB, @"C:\Program Files\Example\app.exe");

        Assert.True(resolver.TryResolve(0xAAAA, 0xBBBB, null, out string path));
        Assert.Equal(@"C:\Program Files\Example\app.exe", path, ignoreCase: true);
    }

    [Fact]
    public void TryResolveDoesNotDisturbTheQualityMetric()
    {
        // Counting a failure both when parking an operation and again when retrying it
        // reported every deferred operation as two failures, which drove the reported
        // rate to 99.9% unresolved while the stored evidence was fully resolved.
        var resolver = new FileObjectResolver(PathNormalizer.CreateForCurrentMachine());

        for (int i = 0; i < 10; i++) resolver.TryResolve(0xAAAA, 0xBBBB, null, out _);

        Assert.Equal(0, resolver.Unresolved);
        Assert.Equal(1.0, resolver.HitRate);
    }
}
