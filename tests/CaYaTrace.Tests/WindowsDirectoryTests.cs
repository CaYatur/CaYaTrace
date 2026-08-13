using CaYaTrace.Core.Model;
using CaYaTrace.Remediation;
using CaYaTrace.Storage;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// A program that installs itself into a Windows directory.
/// </summary>
/// <remarks>
/// <para>
/// Refusing everything under <c>System32</c> is right for Windows' own files and wrong for
/// a program that put its own there — and programs do, deliberately, because it is the one
/// place an uninstaller is guaranteed not to look. Measured on a real recording of an
/// installer: forty-five files written into <c>SysWOW64</c>, a service binary among them,
/// every one refused as Windows-owned, and a plan to remove the program that listed six
/// items, none of which was the program.
/// </para>
/// <para>
/// What replaces the folder test is a provenance test — the recording watched the subject
/// create the file — backed by a list of stores Windows keeps on other programs' behalf,
/// which stay refused no matter who is recorded creating something in them.
/// </para>
/// </remarks>
public sealed class WindowsDirectoryTests : IDisposable
{
    private readonly ITestOutputHelper _out;

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "cayatrace-win-" + Guid.NewGuid().ToString("n")[..8]);

    public WindowsDirectoryTests(ITestOutputHelper output)
    {
        _out = output;
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private SessionStore Store()
    {
        string directory = Path.Combine(_root, "session");
        Directory.CreateDirectory(directory);
        return SessionStore.Create(Path.Combine(directory, "session.ctdb"));
    }

    private static SafetyPolicy Policy =>
        new(CaYaTrace.Core.Naming.PathNormalizer.CreateForCurrentMachine());

    private static readonly ProcessKey Subject =
        ProcessKey.TryParse("k:ffff000011112222:2148", out ProcessKey parsed) ? parsed : ProcessKey.None;

    private static Observation Created(long seq, string path) => new()
    {
        Seq = seq,
        Actor = Subject,
        Timestamp = DateTimeOffset.UtcNow,
        Category = EventCategory.File,
        Action = EventAction.FileCreate,
        Target = path,
        Source = EvidenceSource.KernelEtw,
        Status = EventStatus.Success,
    };

    // ------------------------------------------------------------------ policy

    /// <summary>A file nobody was seen creating stays Windows'.</summary>
    /// <remarks>
    /// The default, and the answer for every library that was on the machine before the
    /// recording started. Nothing about the new rule reaches these.
    /// </remarks>
    [Theory]
    [InlineData(@"%SYSTEM32%\ntdll.dll")]
    [InlineData(@"%SYSWOW64%\kernel32.dll")]
    [InlineData(@"%WINDIR%\explorer.exe")]
    public void AFileTheRecordingNeverSawCreatedIsRefused(string path)
    {
        SafetyDecision decision = Policy.EvaluateFile(path, created: false);

        Assert.Equal(SafetyVerdict.Forbidden, decision.Verdict);
    }

    /// <summary>A file the subject created there may be removed, deliberately.</summary>
    [Theory]
    [InlineData(@"%SYSWOW64%\vendordelay.exe")]
    [InlineData(@"%SYSWOW64%\a8f3c1\agent.exe")]
    [InlineData(@"%SYSTEM32%\vendorsvc.dll")]
    [InlineData(@"%WINDIR%\winsetup.dll.man")]
    public void AFileTheSubjectCreatedThereIsOfferedForConfirmation(string path)
    {
        SafetyDecision decision = Policy.EvaluateFile(path, created: true);

        _out.WriteLine($"{path} -> {decision.Verdict}: {decision.Reason}");

        Assert.Equal(SafetyVerdict.RequiresConfirmation, decision.Verdict);
        Assert.NotEmpty(decision.Reason);
    }

    /// <summary>The directories themselves, on any evidence whatsoever.</summary>
    /// <remarks>
    /// The line that cannot move. An uninstaller that can be talked into removing
    /// <c>System32</c> is a wiper with extra steps, and no amount of provenance makes the
    /// container the program's.
    /// </remarks>
    [Theory]
    [InlineData("%WINDIR%")]
    [InlineData("%SYSTEM32%")]
    [InlineData("%SYSWOW64%")]
    [InlineData(@"%SYSTEM32%\")]
    public void TheWindowsDirectoriesThemselvesAreNeverRemovable(string path)
    {
        Assert.Equal(SafetyVerdict.Forbidden, Policy.EvaluateFile(path, created: true).Verdict);
        Assert.Equal(SafetyVerdict.Forbidden, Policy.EvaluateFile(path, created: false).Verdict);
    }

    /// <summary>
    /// The stores Windows keeps on every program's behalf, whoever is recorded writing to them.
    /// </summary>
    /// <remarks>
    /// This is what actually holds the line, rather than the provenance test. A recording
    /// of an installer produced two creations under the signature catalog store attributed
    /// to a <c>powershell.exe</c> inside the subject's own process tree — genuinely
    /// created, genuinely in scope, and absolutely not the installer's. The catalog store
    /// is how Windows knows whether anything on the machine is signed.
    /// </remarks>
    [Theory]
    [InlineData(@"%SYSTEM32%\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\authroot.cat")]
    [InlineData(@"%SYSTEM32%\catroot2\edb.log")]
    [InlineData(@"%SYSTEM32%\config\SOFTWARE.LOG1")]
    [InlineData(@"%WINDIR%\WinSxS\amd64_something\file.dll")]
    [InlineData(@"%WINDIR%\Prefetch\SETUP.EXE-1234ABCD.pf")]
    [InlineData(@"%WINDIR%\Installer\1a2b3c.msi")]
    [InlineData(@"%SYSTEM32%\DriverStore\FileRepository\x.inf")]
    [InlineData(@"%SYSTEM32%\Tasks\VendorUpdate")]
    [InlineData(@"%WINDIR%\Fonts\vendor.ttf")]
    public void WindowsOwnStoresStayRefusedEvenWhenCreated(string path)
    {
        SafetyDecision decision = Policy.EvaluateFile(path, created: true);

        _out.WriteLine($"{path} -> {decision.Verdict}: {decision.Reason}");

        Assert.Equal(SafetyVerdict.Forbidden, decision.Verdict);
    }

    /// <summary>A near-match on a name is not a match.</summary>
    /// <remarks>
    /// <c>%WINDIR%\Fonts</c> must not also claim <c>%WINDIR%\FontsBackup</c> — the kind of
    /// prefix collision that makes a deny list quietly cover more than it says, and in the
    /// other direction would let a real one through.
    /// </remarks>
    [Fact]
    public void ANearMatchOnAProtectedNameIsNotAMatch()
    {
        Assert.Equal(
            SafetyVerdict.RequiresConfirmation,
            Policy.EvaluateFile(@"%WINDIR%\FontsBackup\vendor.ttf", created: true).Verdict);
    }

    // ------------------------------------------------------------------- plan

    /// <summary>
    /// End to end: an installer that drops itself into SysWOW64 produces a plan containing it.
    /// </summary>
    /// <remarks>
    /// Shaped after a real recording. The subject writes a folder of its own beside
    /// Windows' libraries, two DLLs directly into the directory, and a service binary; a
    /// PowerShell it launched touches the catalog store on the way past.
    /// </remarks>
    [Fact]
    public void AnInstallerThatHidesInSysWow64IsStillRemovable()
    {
        using SessionStore store = Store();

        var session = new SessionInfo
        {
            SessionId = "t",
            Name = "Vendor Setup.exe",
            RootProcess = Subject,
            TargetPath = @"C:\Users\Analyst\Desktop\Vendor 1.0\Vendor Setup.exe",
        };
        store.SaveSessionInfo(session);
        store.UpsertProcesses(new[]
        {
            new ProcessNode { Key = Subject, ImagePath = "Vendor Setup.exe", InScope = true },
        });

        long seq = 1;
        store.ImportObservations(new List<Observation>
        {
            Created(seq++, @"%SYSWOW64%\a8f3c1"),
            Created(seq++, @"%SYSWOW64%\a8f3c1\agent.exe"),
            Created(seq++, @"%SYSWOW64%\a8f3c1\Data"),
            Created(seq++, @"%SYSWOW64%\a8f3c1\Data\0"),
            Created(seq++, @"%SYSWOW64%\vendorsvc.dll"),
            Created(seq++, @"%SYSWOW64%\vendorcomp.dll.rtu"),
            Created(seq++, @"%WINDIR%\winsetup.dll.man"),

            // Windows' own, on the way past.
            Created(seq++, @"%SYSTEM32%\catroot2\edb.log"),
        });

        var planner = new RemovalPlanner(store);
        List<RemovalItem> plan = planner.Build(session);

        foreach (RemovalItem item in plan) _out.WriteLine($"{item.Kind,-10} {item.Target}");

        foreach (string expected in new[]
                 {
                     @"%SYSWOW64%\a8f3c1\agent.exe", @"%SYSWOW64%\a8f3c1\Data\0",
                     @"%SYSWOW64%\vendorsvc.dll", @"%SYSWOW64%\vendorcomp.dll.rtu",
                     @"%WINDIR%\winsetup.dll.man",
                 })
        {
            Assert.Contains(plan, i => i.Target.Equals(expected, StringComparison.OrdinalIgnoreCase));
        }

        // The catalog store is not the installer's, however the event was attributed.
        Assert.DoesNotContain(plan, i => i.Target.Contains("catroot", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(planner.Excluded, e => e.Target.Contains("catroot", StringComparison.OrdinalIgnoreCase));

        // Neither directory is ever a candidate as itself.
        Assert.DoesNotContain(plan, i => i.Target.TrimEnd('\\')
            .Equals("%SYSWOW64%", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(plan, i => i.Target.TrimEnd('\\')
            .Equals("%WINDIR%", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// A folder the program made is a folder, not a file, whatever the kernel called it.
    /// </summary>
    /// <remarks>
    /// A directory is a file with a flag set, so creating one produces an ordinary file
    /// create and the plan listed it as a file. That reads wrong and orders wrong: files go
    /// before folders precisely so a folder is empty when its turn comes, and a folder
    /// disguised as a file loses that. Which entries are folders is read off the evidence —
    /// anything other recorded paths sit inside — so the answer holds on a machine where
    /// the folder no longer exists.
    /// </remarks>
    [Fact]
    public void AFolderTheProgramMadeIsListedAsAFolder()
    {
        using SessionStore store = Store();

        var session = new SessionInfo
        {
            SessionId = "t", Name = "Vendor Setup.exe", RootProcess = Subject,
            TargetPath = @"C:\Users\Analyst\Desktop\Vendor 1.0\Vendor Setup.exe",
        };
        store.SaveSessionInfo(session);
        store.UpsertProcesses(new[]
        {
            new ProcessNode { Key = Subject, ImagePath = "Vendor Setup.exe", InScope = true },
        });

        store.ImportObservations(new List<Observation>
        {
            Created(1, @"%SYSWOW64%\a8f3c1"),
            Created(2, @"%SYSWOW64%\a8f3c1\Data"),
            Created(3, @"%SYSWOW64%\a8f3c1\Data\0"),
            Created(4, @"%SYSWOW64%\a8f3c1\agent.exe"),
            Created(5, @"%SYSWOW64%\a8f3c1\eklibs"),
        });

        List<RemovalItem> plan = new RemovalPlanner(store).Build(session);
        foreach (RemovalItem item in plan) _out.WriteLine($"{item.Kind,-10} {item.Target}");

        Assert.Contains(plan, i => i.Kind == RemovalKind.Directory
                                   && i.Target.Equals(@"%SYSWOW64%\a8f3c1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(plan, i => i.Kind == RemovalKind.Directory
                                   && i.Target.Equals(@"%SYSWOW64%\a8f3c1\Data", StringComparison.OrdinalIgnoreCase));

        // Nothing sits inside these in the recording, so nothing says they are folders.
        // Being wrong here costs nothing: the runner looks at the disk before it moves.
        Assert.Contains(plan, i => i.Kind == RemovalKind.File
                                   && i.Target.EndsWith("eklibs", StringComparison.OrdinalIgnoreCase));

        // Folders go last, so they are empty by the time their turn comes.
        Assert.All(plan.Where(static i => i.Kind == RemovalKind.Directory),
            d => Assert.True(plan.Where(f => f.Kind == RemovalKind.File).All(f => f.Order < d.Order)));
    }
}
