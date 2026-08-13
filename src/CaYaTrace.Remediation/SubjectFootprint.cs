using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;
using CaYaTrace.Storage;

namespace CaYaTrace.Remediation;

/// <summary>
/// The program's own parts, recovered from the recording rather than from the disk.
/// </summary>
/// <remarks>
/// <para>
/// A removal plan built only from what the subject was seen <em>creating</em> cannot
/// contain the subject. A program is downloaded, unpacked, and only then recorded, so its
/// executable and the files shipped beside it already existed when the recording started
/// and no event ever names them as created.
/// </para>
/// <para>
/// The previous answer to that was to enumerate the directory on disk at plan time, which
/// works exactly once: on the machine that still holds the files, before anything has
/// removed them. Measured on a real recording, it produced two rows — a batch file and a
/// text file — because Defender had quarantined the executable and the DLL beside it
/// between the recording and the plan. The two things that had done all the work were
/// missing from the plan to remove them, and the recording named both.
/// </para>
/// <para>
/// So the recording is the source, and the disk is only ever an addition to it. That also
/// makes the answer the same on every machine: a session recorded in a virtual machine and
/// read on the host produces the same list, which the disk enumeration never could.
/// </para>
/// </remarks>
public sealed class SubjectFootprint
{
    /// <summary>One part of the program, and the evidence that it is one.</summary>
    /// <param name="Path">Tokenized, as the recording stored it.</param>
    /// <param name="Why">Shown to the operator beside the item.</param>
    /// <param name="Created">
    /// The recording watched the subject write this file, as opposed to reading or
    /// loading one that was already there. The safety policy reads it: a file inside a
    /// Windows directory may only be removed when this is true.
    /// </param>
    public readonly record struct Component(string Path, string Why, long Evidence, bool Created);

    private readonly Dictionary<string, Component> _components = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The program's parts, each named once.</summary>
    public IReadOnlyCollection<Component> Components => _components.Values;

    /// <summary>
    /// The directory the program ran from, tokenized, or null when it could not be placed.
    /// </summary>
    public string? Directory { get; private set; }

    /// <summary>
    /// Paths the recording shows the loader searching for and not finding.
    /// </summary>
    /// <remarks>
    /// Kept so the rule that discards them can be checked against a real session rather
    /// than argued about. The DLL search order tries the application's own directory
    /// first, so a program that resolves <c>bcrypt.dll</c> from System32 still produces an
    /// open for <c>&lt;program directory&gt;\bcrypt.dll</c> — a file that does not exist and
    /// never did. Twelve of them on one recording, one of which was <c>cmd.exe</c>.
    /// </remarks>
    public List<string> SearchProbes { get; } = new();

    /// <summary>
    /// Reads a session and returns what the program consists of.
    /// </summary>
    public static SubjectFootprint Collect(
        SessionStore store,
        SessionInfo session,
        PathNormalizer paths,
        IReadOnlyDictionary<ProcessKey, ProcessNode> processes)
    {
        var footprint = new SubjectFootprint();

        footprint.CollectModules(store, session, paths, processes);
        footprint.CollectDirectory(store, session, paths);

        return footprint;
    }

    /// <summary>
    /// Every module the program loaded that Windows does not own.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The single most reliable statement a recording makes about what a program consists
    /// of. A DLL the program loaded is a DLL the program needs, wherever it sits — beside
    /// the executable, in a folder it unpacked, or side-loaded from somewhere it should
    /// not be. No other signal covers the last case at all.
    /// </para>
    /// <para>
    /// Measured on a real recording: the subject's process tree loaded 74 modules, 72 of
    /// them out of System32 and two out of its own directory. The path test alone
    /// separates them, and the two it keeps are the executable and the library that had
    /// done everything the recording was made to see.
    /// </para>
    /// </remarks>
    private void CollectModules(
        SessionStore store,
        SessionInfo session,
        PathNormalizer paths,
        IReadOnlyDictionary<ProcessKey, ProcessNode> processes)
    {
        var query = new ObservationQuery { Categories = new List<EventCategory> { EventCategory.Module } };

        foreach (Observation o in store.Query(query))
        {
            if (o.Action != EventAction.ImageLoad) continue;
            if (o.Target is not { Length: > 0 }) continue;
            if (!Belongs(o.Actor, session, processes)) continue;

            string token = paths.Tokenize(o.Target);
            if (paths.IsSystemPath(token)) continue;
            if (!LooksLikeAFile(token)) continue;

            Add(token, "loaded as a module by the program", o.Seq, created: false);
        }
    }

    /// <summary>
    /// Whether a change is the subject's, in either kind of recording.
    /// </summary>
    /// <remarks>
    /// A targeted recording answers with its process tree. A system-wide one has no tree,
    /// and there the question becomes who signed the binary: Windows is busy during any
    /// recording, and everything it does on its own behalf is signed by Microsoft while
    /// nothing a third party drops is.
    /// </remarks>
    private static bool Belongs(
        ProcessKey actor,
        SessionInfo session,
        IReadOnlyDictionary<ProcessKey, ProcessNode> processes)
    {
        if (!processes.TryGetValue(actor, out ProcessNode? node))
            return session.RootProcess == ProcessKey.None;

        return session.RootProcess == ProcessKey.None ? !node.IsMicrosoftSigned() : node.InScope;
    }

    /// <summary>
    /// The files sitting in the directory the program ran from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Placed through the recording rather than through the reading machine's idea of
    /// where the profile is. The observations are tokenized when they are written, so a
    /// session recorded under one profile and read under another has already resolved
    /// <c>%USERPROFILE%</c> to the <em>recording</em> machine's — and re-tokenizing the
    /// subject's path here would produce <c>%USERSROOT%\PC\…</c> against the recording's
    /// <c>%USERPROFILE%\…</c> and match nothing.
    /// </para>
    /// <para>
    /// So the directory is found by looking for the subject's own file inside the
    /// recording, matched on its last two path segments — specific enough that a common
    /// leaf name cannot collide, and free of any dependence on where either machine keeps
    /// its users.
    /// </para>
    /// </remarks>
    private void CollectDirectory(SessionStore store, SessionInfo session, PathNormalizer paths)
    {
        if (session.TargetPath is not { Length: > 0 } target) return;

        string? parent = SafeDirectory(target);
        if (parent is not { Length: > 0 }) return;

        string leaf = System.IO.Path.GetFileName(parent.TrimEnd('\\', '/'));
        string file = System.IO.Path.GetFileName(target);
        if (leaf.Length == 0 || file.Length == 0) return;

        string suffix = $@"\{leaf}\{file}";

        // Modules as well as files: a program launched by the shell is often never read
        // by anything, and then the only event naming it is the loader mapping it in.
        //
        // Filtered in SQL, because the alternative is a scan of every file operation in
        // the session and a minute of recording produces two hundred thousand of them.
        var query = new ObservationQuery
        {
            Categories = new List<EventCategory> { EventCategory.File, EventCategory.Module },
            TargetContains = leaf,
        };

        string? directory = null;
        var used = new Dictionary<string, (string Why, long Seq, bool Created)>(StringComparer.OrdinalIgnoreCase);
        var opened = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Observation o in store.Query(query))
        {
            string? path = o.Action == EventAction.FileRename && o.Target2 is { Length: > 0 }
                ? o.Target2
                : o.Target;

            if (path is not { Length: > 0 }) continue;

            directory ??= path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                ? path[..^(file.Length + 1)].TrimEnd('\\', '/')
                : null;

            if (o.Action == EventAction.FileOpen) opened.Add(path);
            else if (Uses(o.Action)) used.TryAdd(path, (Reason(o.Action), o.Seq, Makes(o.Action)));
        }

        if (directory is not { Length: > 0 })
        {
            // The recording never names the subject's own file, which happens when a
            // program is launched and reads nothing — including itself. Nothing is known
            // about the folder it sits in, so nothing is claimed about it: the executable
            // is listed and the folder is neither swept nor offered.
            Add(paths.Tokenize(target), "the program's own executable", 0, created: false);
            return;
        }

        Directory = directory;

        string prefix = directory + "\\";

        // Named first and named plainly. Whatever else the directory holds, this is the
        // thing the operator asked to be rid of.
        Add(prefix + file, "the program's own executable", 0, created: false);

        foreach ((string path, (string why, long seq, bool made)) in used)
        {
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            if (!LooksLikeAFile(path)) continue;

            Add(path, why, seq, made);
        }

        foreach (string path in opened)
        {
            if (used.ContainsKey(path)) continue;
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            if (!LooksLikeAFile(path)) continue;

            SearchProbes.Add(path);
        }

        // A folder Windows or the operator maintains is never swept and never offered,
        // whatever proportion of it the program happens to account for. A profile that
        // has been tidied recently can hold two of the operator's files and three of the
        // program's, and no arithmetic makes Documents the program's directory.
        if (RemovalPlanner.IsWellKnownFolder(directory))
        {
            DirectoryIsShared = true;
            return;
        }

        // The disk is an addition, never the source: it holds anything the program
        // shipped and never touched, which the recording cannot know about.
        AddFromDisk(paths.Expand(directory), paths);
    }

    /// <summary>
    /// True when the directory holds more than the program.
    /// </summary>
    /// <remarks>
    /// Only ever set by looking. A folder that could not be read is not declared shared,
    /// because nothing is then known about it either way — and in that case the runner's
    /// refusal to move a folder with anything left in it is what keeps it safe.
    /// </remarks>
    public bool DirectoryIsShared { get; private set; }

    /// <summary>
    /// Adds what the program shipped and never touched — but only from its own directory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The recording cannot name a file nothing ever opened, so a licence, a
    /// configuration, an unused plugin would all survive a removal built from events
    /// alone. Reading the directory finds them.
    /// </para>
    /// <para>
    /// It also finds everything else in there, which is the danger. A program run
    /// straight out of a downloads folder, or out of a folder of fifty unrelated
    /// utilities, has a "directory" that belongs to the operator; sweeping it would list
    /// their files, ticked, and then offer the folder that holds them.
    /// </para>
    /// <para>
    /// <b>So the folder has to be earned.</b> The recording named some of what is in
    /// there; the disk says how much else is. When the program's own files are most of
    /// the folder, it is the program's folder and the rest goes with it. When they are a
    /// minority, it is somebody else's folder that the program was run from, and nothing
    /// is taken but what the recording actually named.
    /// </para>
    /// <para>
    /// A majority rather than a threshold, because the number of files a program ships is
    /// not a quantity anyone can put a bound on — but "more of this folder is the
    /// program's than is not" holds whether it shipped three files or three hundred.
    /// </para>
    /// </remarks>
    private void AddFromDisk(string directory, PathNormalizer paths)
    {
        string[] files;
        try
        {
            files = System.IO.Directory.GetFiles(directory, "*", SearchOption.AllDirectories);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return;
        }

        // Reading a folder this size is itself the wrong thing to be doing, and nothing
        // it could say would make the folder the program's.
        const int PlausibleInstall = 2000;
        if (files.Length > PlausibleInstall)
        {
            DirectoryIsShared = true;
            return;
        }

        var strangers = new List<string>();
        int mine = 0;

        foreach (string file in files)
        {
            if (_components.ContainsKey(paths.Tokenize(file))) mine++;
            else strangers.Add(file);
        }

        if (strangers.Count > mine)
        {
            DirectoryIsShared = true;
            return;
        }

        foreach (string file in strangers)
            Add(paths.Tokenize(file), "sits with the program's executable", 0, created: false);
    }

    /// <summary>
    /// True when an action shows a file being used rather than looked for.
    /// </summary>
    /// <remarks>
    /// The distinction the whole set turns on. An open proves only that something asked
    /// for the path; a read, a write, or a load proves there was something there.
    /// </remarks>
    private static bool Uses(EventAction action) => action
        is EventAction.ImageLoad
        or EventAction.FileCreate
        or EventAction.FileRead
        or EventAction.FileWrite
        or EventAction.FileSetInfo
        or EventAction.FileRename
        or EventAction.HardLinkCreate;

    /// <summary>True when an action is the file coming into existence.</summary>
    /// <remarks>
    /// Narrower than <see cref="Uses"/> on purpose. Reading a file proves it was there;
    /// only a create proves it was not there before, and that is the whole difference
    /// between a program's own dropped binary and one of Windows'.
    /// </remarks>
    private static bool Makes(EventAction action) => action
        is EventAction.FileCreate
        or EventAction.FileWrite
        or EventAction.FileRename
        or EventAction.HardLinkCreate;

    private static string Reason(EventAction action) => action switch
    {
        EventAction.FileCreate or EventAction.HardLinkCreate => "created by the program",
        EventAction.FileWrite => "written by the program",
        EventAction.FileRename => "put in place by the program",
        _ => "read by the program from its own directory",
    };

    /// <summary>
    /// Rejects the things in a path column that are not files.
    /// </summary>
    /// <remarks>
    /// A directory arrives here as its own path and as a path with a trailing separator;
    /// an alternate data stream arrives as <c>file.exe:Zone.Identifier</c>, which is
    /// metadata attached to a file rather than a file of its own and disappears with it.
    /// </remarks>
    private static bool LooksLikeAFile(string path)
    {
        if (path.Length == 0) return false;
        if (path.EndsWith('\\') || path.EndsWith('/')) return false;

        string name = System.IO.Path.GetFileName(path);
        if (name.Length == 0) return false;
        if (name.Contains(':', StringComparison.Ordinal)) return false;

        return path.Contains('\\', StringComparison.Ordinal);
    }

    private void Add(string path, string why, long seq, bool created)
    {
        if (_components.ContainsKey(path)) return;
        _components[path] = new Component(path, why, seq, created);
    }

    private static string? SafeDirectory(string path)
    {
        try { return System.IO.Path.GetDirectoryName(path); }
        catch (ArgumentException) { return null; }
    }
}
