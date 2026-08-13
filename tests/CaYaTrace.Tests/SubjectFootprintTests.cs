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

    private SessionStore Store(out string directory)
    {
        directory = Path.Combine(_root, "session");
        Directory.CreateDirectory(directory);
        return SessionStore.Create(Path.Combine(directory, "session.ctdb"));
    }

    /// <summary>
    /// The subject's own directory is listed file by file.
    /// </summary>
    /// <remarks>
    /// File by file because a folder is a container: the operator asked for each file to be
    /// removed individually, and for the folder itself only when nothing in it is theirs.
    /// </remarks>
    [Fact]
    public void TheProgramsOwnFilesAreListedIndividually()
    {
        string install = Path.Combine(_root, "codex-pets-2.3");
        Directory.CreateDirectory(install);

        string launcher = Path.Combine(install, "Application.bat");
        File.WriteAllText(launcher, "@echo off");
        File.WriteAllText(Path.Combine(install, "util64.exe"), "MZ");
        File.WriteAllText(Path.Combine(install, "readme.txt"), "hello");

        Directory.CreateDirectory(Path.Combine(install, "data"));
        File.WriteAllText(Path.Combine(install, "data", "payload.bin"), "xx");

        using SessionStore store = Store(out _);
        var session = new SessionInfo { SessionId = "t", Name = "Application.bat", TargetPath = launcher };
        store.SaveSessionInfo(session);

        List<RemovalItem> plan = new RemovalPlanner(store).Build(session);

        foreach (RemovalItem item in plan)
            _out.WriteLine($"{item.Kind,-10} {item.Target}   [{item.Rationale}]");

        // Every file beside the executable, each on its own.
        foreach (string expected in new[] { "Application.bat", "util64.exe", "readme.txt", "payload.bin" })
        {
            Assert.Contains(plan, i => i.Kind == RemovalKind.File
                                       && i.Target.EndsWith(expected, StringComparison.OrdinalIgnoreCase));
        }

        // And the folder, because everything in it belongs to the program.
        Assert.Contains(plan, i => i.Kind == RemovalKind.Directory
                                   && i.Target.EndsWith("codex-pets-2.3", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// A program run from a shared folder does not take the folder with it.
    /// </summary>
    /// <remarks>
    /// The case that makes the previous one safe. Somebody who runs a sample straight out
    /// of Downloads must not be offered Downloads — and the difference cannot be the name,
    /// because a folder is shared by what is in it, not by what it is called.
    /// </remarks>
    [Fact]
    public void AProgramRunFromASharedFolderDoesNotTakeTheFolder()
    {
        string downloads = Path.Combine(_root, "Downloads");
        Directory.CreateDirectory(downloads);

        string launcher = Path.Combine(downloads, "sample.exe");
        File.WriteAllText(launcher, "MZ");

        // Somebody else's files, in the same folder.
        for (int i = 0; i < 5; i++)
            File.WriteAllText(Path.Combine(downloads, $"holiday-{i}.jpg"), "jpeg");

        using SessionStore store = Store(out _);
        var session = new SessionInfo { SessionId = "t", Name = "sample.exe", TargetPath = launcher };
        store.SaveSessionInfo(session);

        List<RemovalItem> plan = new RemovalPlanner(store).Build(session);

        foreach (RemovalItem item in plan)
            _out.WriteLine($"{item.Kind,-10} {item.Target}");

        Assert.Contains(plan, i => i.Kind == RemovalKind.File
                                   && i.Target.EndsWith("sample.exe", StringComparison.OrdinalIgnoreCase));

        // The operator's photographs are listed, which is the honest outcome — the tool
        // cannot know they are not the program's — but they arrive as individual files the
        // operator can uncheck, never as a folder that takes them all at once.
        Assert.DoesNotContain(plan, i => i.Kind == RemovalKind.Directory
                                         && i.Target.EndsWith("Downloads", StringComparison.OrdinalIgnoreCase)
                                         && !i.Target.Contains("cayatrace-foot", StringComparison.OrdinalIgnoreCase));
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
        using SessionStore store = Store(out _);

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
