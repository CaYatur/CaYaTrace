using CaYaTrace.Core.Model;
using CaYaTrace.Remediation;
using CaYaTrace.Storage;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// The program itself, as opposed to what it created while being watched.
/// </summary>
/// <remarks>
/// A subject is normally downloaded, unpacked and then recorded, so its own executable and
/// the folder it unpacked into already existed when the recording started — no event names
/// them as created, and a plan built only from the recording removes the program's registry
/// footprint and leaves the program on disk. Measured on a real session: two registry
/// values, and not one of the executables that had done all the work.
/// </remarks>
public sealed class SubjectFootprintTests : IDisposable
{
    private readonly ITestOutputHelper _out;

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "cayatrace-foot-" + Guid.NewGuid().ToString("n")[..8]);

    public SubjectFootprintTests(ITestOutputHelper output)
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

    private static readonly ProcessKey Subject =
        ProcessKey.TryParse("k:ffff000011112222:4772", out ProcessKey parsed) ? parsed : ProcessKey.None;

    private static Observation Event(long seq, EventCategory category, EventAction action, string target) => new()
    {
        Seq = seq,
        Actor = Subject,
        Timestamp = DateTimeOffset.UtcNow,
        Category = category,
        Action = action,
        Target = target,
        Source = EvidenceSource.KernelEtw,
        Status = EventStatus.Success,
    };

    /// <summary>
    /// The program's parts come out of the recording, not off the disk.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Reproduces what a real recording contained. Its subject was a batch file that ran an
    /// executable which loaded one library beside it and read one data file; the loader,
    /// resolving imports, also <em>opened</em> a dozen paths inside that directory for DLLs
    /// that live in System32 — the application directory comes first in the search order, so
    /// every one of them produces an open for a file that does not exist.
    /// </para>
    /// <para>
    /// A plan built from opened paths therefore lists twelve Windows DLL names inside the
    /// program's folder, one of which is <c>cmd.exe</c>. A plan built from used paths lists
    /// the four files that were really there. The difference is a read: the loader's probes
    /// have opens and nothing else, and every real file has a load, a read or a write.
    /// </para>
    /// <para>
    /// Nothing in this test exists on disk, which is the point — the recording alone has to
    /// carry it, because by the time an operator builds the plan an antivirus may already
    /// have taken the files away. That is what happened on the session this is drawn from.
    /// </para>
    /// </remarks>
    [Fact]
    public void ComponentsComeFromWhatTheRecordingSawUsed()
    {
        using SessionStore store = Store();

        var session = new SessionInfo
        {
            SessionId = "t",
            Name = "Application.bat",
            RootProcess = Subject,
            TargetPath = @"C:\Users\Analyst\Downloads\widget-2.3\Application.bat",
        };
        store.SaveSessionInfo(session);

        store.UpsertProcesses(new[]
        {
            new ProcessNode { Key = Subject, ImagePath = "helper64.exe", InScope = true },
        });

        const string home = @"%USERPROFILE%\Downloads\widget-2.3";
        long seq = 1;
        var batch = new List<Observation>
        {
            // Used: loaded, read, written.
            Event(seq++, EventCategory.Module, EventAction.ImageLoad, $@"{home}\helper64.exe"),
            Event(seq++, EventCategory.Module, EventAction.ImageLoad, $@"{home}\runtime.dll"),
            Event(seq++, EventCategory.File, EventAction.FileRead, $@"{home}\config.txt"),
            Event(seq++, EventCategory.File, EventAction.FileRead, $@"{home}\Application.bat"),

            // Windows' own, loaded from where Windows keeps them.
            Event(seq++, EventCategory.Module, EventAction.ImageLoad, @"%SYSTEM32%\ntdll.dll"),
            Event(seq++, EventCategory.Module, EventAction.ImageLoad, @"%SYSTEM32%\cmd.exe"),

            // An alternate data stream is metadata on a file, not a file.
            Event(seq++, EventCategory.File, EventAction.FileRead, $@"{home}\helper64.exe:Zone.Identifier"),

            // The directory itself, which the collector reports both ways.
            Event(seq++, EventCategory.File, EventAction.FileOpen, home),
            Event(seq++, EventCategory.File, EventAction.FileOpen, home + "\\"),
        };

        // The loader's search probes: opened, never there.
        foreach (string probe in new[]
                 {
                     "cmd.exe", "bcrypt.dll", "ncrypt.dll", "wininet.dll", "CRYPTBASE.DLL",
                     "DPAPI.DLL", "MSASN1.dll", "NTASN1.dll", "netutils.dll", "profapi.dll",
                     "srvcli.dll", "winbrand.dll", "helper64.exe.Config",
                 })
        {
            batch.Add(Event(seq++, EventCategory.File, EventAction.FileOpen, $@"{home}\{probe}"));
        }

        store.ImportObservations(batch);

        var planner = new RemovalPlanner(store);
        List<RemovalItem> plan = planner.Build(session);

        foreach (RemovalItem item in plan) _out.WriteLine($"{item.Kind,-10} {item.Target}   [{item.Rationale}]");
        _out.WriteLine($"probes rejected: {planner.Footprint.SearchProbes.Count}");

        foreach (string kept in new[] { "helper64.exe", "runtime.dll", "config.txt", "Application.bat" })
        {
            Assert.Contains(plan, i => i.Kind == RemovalKind.File
                                       && i.Target.Equals($@"{home}\{kept}", StringComparison.OrdinalIgnoreCase));
        }

        // Not one probe, and above all not this one: a bare Windows binary name wearing a
        // path under the operator's profile passes every check written to recognise a
        // system location.
        Assert.DoesNotContain(plan, i => i.Target.EndsWith(@"\cmd.exe", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(plan, i => i.Target.EndsWith(".Config", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(plan, i => i.Target.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(plan, i => i.Target.Contains("Zone.Identifier", StringComparison.OrdinalIgnoreCase));

        Assert.Equal(13, planner.Footprint.SearchProbes.Count);

        // The program's own folder, and no other.
        Assert.Contains(plan, i => i.Kind == RemovalKind.Directory
                                   && i.Target.Equals(home, StringComparison.OrdinalIgnoreCase));
        Assert.Single(plan, i => i.Kind == RemovalKind.Directory);
    }

    /// <summary>
    /// A session read on a machine other than the one that recorded it gives the same answer.
    /// </summary>
    /// <remarks>
    /// The failure this replaces: the footprint was tokenized against the reading machine,
    /// so a session recorded under one profile produced <c>%USERSROOT%\PC\Downloads\…</c>
    /// while every observation in it said <c>%USERPROFILE%\Downloads\…</c>. The two never
    /// met, and the program's own files were absent from the plan to remove it.
    /// </remarks>
    [Fact]
    public void AForeignProfileDoesNotBreakTheMatch()
    {
        using SessionStore store = Store();

        var session = new SessionInfo
        {
            SessionId = "t",
            Name = "setup.exe",
            RootProcess = Subject,

            // A profile that does not exist on the machine reading this.
            TargetPath = @"C:\Users\SomebodyElse\Downloads\widget-1.0\setup.exe",
        };
        store.SaveSessionInfo(session);

        store.UpsertProcesses(new[]
        {
            new ProcessNode { Key = Subject, ImagePath = "setup.exe", InScope = true },
        });

        const string home = @"%USERPROFILE%\Downloads\widget-1.0";
        store.ImportObservations(new List<Observation>
        {
            Event(1, EventCategory.Module, EventAction.ImageLoad, $@"{home}\setup.exe"),
            Event(2, EventCategory.File, EventAction.FileRead, $@"{home}\payload.dat"),
        });

        List<RemovalItem> plan = new RemovalPlanner(store).Build(session);
        foreach (RemovalItem item in plan) _out.WriteLine($"{item.Kind,-10} {item.Target}");

        Assert.Contains(plan, i => i.Target.Equals($@"{home}\setup.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(plan, i => i.Target.Equals($@"{home}\payload.dat", StringComparison.OrdinalIgnoreCase));

        // The reading machine's own profile is never spoken of.
        Assert.DoesNotContain(plan, i => i.Target.Contains("%USERSROOT%", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// A module loaded from somewhere else is still the program's.
    /// </summary>
    /// <remarks>
    /// The case the directory sweep cannot reach. A library side-loaded out of the profile
    /// is neither beside the executable nor created while anything watched, and the only
    /// statement the recording makes about it is that the program loaded it — which is the
    /// strongest statement there is that a program needs a file.
    /// </remarks>
    [Fact]
    public void ASideLoadedLibraryIsACandidateWhereverItSits()
    {
        using SessionStore store = Store();

        var session = new SessionInfo
        {
            SessionId = "t", Name = "setup.exe", RootProcess = Subject,
            TargetPath = @"C:\Users\Analyst\Downloads\widget\setup.exe",
        };
        store.SaveSessionInfo(session);
        store.UpsertProcesses(new[]
        {
            new ProcessNode { Key = Subject, ImagePath = "setup.exe", InScope = true },
        });

        store.ImportObservations(new List<Observation>
        {
            Event(1, EventCategory.Module, EventAction.ImageLoad, @"%LOCALAPPDATA%\a8f3c1\helper.dll"),
            Event(2, EventCategory.Module, EventAction.ImageLoad, @"%SYSTEM32%\kernel32.dll"),
        });

        List<RemovalItem> plan = new RemovalPlanner(store).Build(session);

        Assert.Contains(plan, i => i.Target.Equals(
            @"%LOCALAPPDATA%\a8f3c1\helper.dll", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(plan, i => i.Target.Contains("kernel32", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// A program run out of somebody else's folder takes nothing but itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Somebody who runs a sample straight out of a downloads folder must not lose the
    /// folder, and must not be offered their own photographs to delete either. Both used
    /// to happen: the folder was read at plan time and everything in it was listed and
    /// ticked, which then emptied the folder and let the folder itself go too.
    /// </para>
    /// <para>
    /// What decides it is how much of the folder the program accounts for. Here it is one
    /// file in six, so the folder is somebody else's and only the one file is listed.
    /// </para>
    /// </remarks>
    [Fact]
    public void AProgramRunFromSomebodyElsesFolderTakesNothingElse()
    {
        string downloads = Path.Combine(_root, "Downloads");
        Directory.CreateDirectory(downloads);

        string launcher = Path.Combine(downloads, "sample.exe");
        File.WriteAllText(launcher, "MZ");

        for (int i = 0; i < 5; i++)
            File.WriteAllText(Path.Combine(downloads, $"holiday-{i}.jpg"), "jpeg");

        using SessionStore store = Store();
        var session = new SessionInfo
        {
            SessionId = "t", Name = "sample.exe", RootProcess = Subject, TargetPath = launcher,
        };
        store.SaveSessionInfo(session);
        store.UpsertProcesses(new[]
        {
            new ProcessNode { Key = Subject, ImagePath = "sample.exe", InScope = true },
        });

        // The recording names the one file, the way a real one would.
        store.ImportObservations(new List<Observation>
        {
            Event(1, EventCategory.Module, EventAction.ImageLoad, launcher),
        });

        var planner = new RemovalPlanner(store);
        List<RemovalItem> plan = planner.Build(session);
        foreach (RemovalItem item in plan) _out.WriteLine($"{item.Kind,-10} {item.Target}");

        Assert.Contains(plan, i => i.Kind == RemovalKind.File
                                   && i.Target.EndsWith("sample.exe", StringComparison.OrdinalIgnoreCase));

        // Not one of the operator's files, and not the folder that holds them.
        Assert.DoesNotContain(plan, i => i.Target.Contains("holiday-", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(plan, i => i.Kind == RemovalKind.Directory);
        Assert.True(planner.Footprint.DirectoryIsShared);
    }

    /// <summary>
    /// A folder that is mostly the program's is the program's, including what it never touched.
    /// </summary>
    /// <remarks>
    /// The other side of the same rule, and the reason it is a proportion rather than a
    /// refusal. A licence file or an unused plugin is never opened, so no recording can
    /// name it — and leaving it behind is the residue an uninstaller exists to prevent.
    /// </remarks>
    [Fact]
    public void AFolderThatIsMostlyTheProgramsIsTakenWhole()
    {
        string install = Path.Combine(_root, "widget-2.3");
        Directory.CreateDirectory(install);

        string launcher = Path.Combine(install, "widget.exe");
        File.WriteAllText(launcher, "MZ");
        File.WriteAllText(Path.Combine(install, "runtime.dll"), "MZ");
        File.WriteAllText(Path.Combine(install, "LICENCE.txt"), "never opened");

        using SessionStore store = Store();
        var session = new SessionInfo
        {
            SessionId = "t", Name = "widget.exe", RootProcess = Subject, TargetPath = launcher,
        };
        store.SaveSessionInfo(session);
        store.UpsertProcesses(new[]
        {
            new ProcessNode { Key = Subject, ImagePath = "widget.exe", InScope = true },
        });

        store.ImportObservations(new List<Observation>
        {
            Event(1, EventCategory.Module, EventAction.ImageLoad, launcher),
            Event(2, EventCategory.Module, EventAction.ImageLoad, Path.Combine(install, "runtime.dll")),
        });

        var planner = new RemovalPlanner(store);
        List<RemovalItem> plan = planner.Build(session);
        foreach (RemovalItem item in plan) _out.WriteLine($"{item.Kind,-10} {item.Target}   [{item.Rationale}]");

        Assert.False(planner.Footprint.DirectoryIsShared);

        foreach (string expected in new[] { "widget.exe", "runtime.dll", "LICENCE.txt" })
        {
            Assert.Contains(plan, i => i.Kind == RemovalKind.File
                                       && i.Target.EndsWith(expected, StringComparison.OrdinalIgnoreCase));
        }

        Assert.Contains(plan, i => i.Kind == RemovalKind.Directory
                                   && i.Target.EndsWith("widget-2.3", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Windows' own binaries are never the subject's, whatever ran them.</summary>
    /// <remarks>
    /// A batch file launches cmd.exe, and cmd.exe is inside the subject's process tree. It
    /// is still Windows'. Being in the tree does not transfer ownership of a binary, and a
    /// plan that deleted cmd.exe would cost the machine rather than the program.
    /// </remarks>
    [Fact]
    public void WindowsOwnBinariesAreNeverCandidates()
    {
        using SessionStore store = Store();

        string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var session = new SessionInfo
        {
            SessionId = "t",
            Name = "cmd.exe",
            TargetPath = Path.Combine(system, "cmd.exe"),
        };

        store.SaveSessionInfo(session);

        List<RemovalItem> plan = new RemovalPlanner(store).Build(session);

        Assert.DoesNotContain(plan, i => i.Target.EndsWith("cmd.exe", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(plan, i => i.Target.EndsWith("conhost.exe", StringComparison.OrdinalIgnoreCase));
    }
}
