using CaYaTrace.Core.Naming;
using Microsoft.Win32;

namespace CaYaTrace.Remediation;

/// <summary>How far to sweep for traces of a program.</summary>
public enum LeftoverDepth
{
    /// <summary>Do not sweep. The plan is whatever the recording saw.</summary>
    None,

    /// <summary>
    /// Directories and registry keys named after the program, under the roots where
    /// programs install themselves.
    /// </summary>
    Safe,

    /// <summary>
    /// Also uninstall entries, services, App Paths and startup values that name it, and
    /// scheduled tasks.
    /// </summary>
    Moderate,

    /// <summary>
    /// Also registry values anywhere under the software hives whose <em>data</em> points
    /// at one of its directories. Slow, and the only depth that finds a reference written
    /// somewhere nobody would think to look.
    /// </summary>
    Advanced,
}

/// <summary>What the sweep found, and how hard it looked.</summary>
public sealed record LeftoverScan
{
    public required LeftoverDepth Depth { get; init; }

    public required IReadOnlyList<RemovalItem> Items { get; init; }

    /// <summary>The words that were matched against, so a wrong match is explainable.</summary>
    public required IReadOnlyList<string> Terms { get; init; }

    public int KeysExamined { get; init; }

    public int DirectoriesExamined { get; init; }

    /// <summary>Where the sweep stopped early, if it did.</summary>
    public string? Note { get; init; }
}

/// <summary>
/// Sweeps the machine for what a program left behind, whether or not it was recorded.
/// </summary>
/// <remarks>
/// <para>
/// The removal plan is built from the recording: every item in it is something the tool
/// watched being created. That is the right foundation and it is not enough on its own,
/// which is the complaint that produced this class — a plan that only knows what it saw
/// misses everything that was already there. A program installed before the recording
/// started, a component dropped by a nested installer that ran outside the traced scope,
/// a registry key written by an elevated helper: all invisible, all still on the machine
/// afterwards.
/// </para>
/// <para>
/// So this asks the opposite question. Instead of "what did I watch it create", it asks
/// "what on this machine is named after it", which is how a dedicated uninstaller finds
/// leftovers and why people keep one around.
/// </para>
/// <para>
/// <b>Nothing here deletes.</b> It produces candidates with the reason each one matched,
/// every one still passes the safety policy, and the operator approves the plan. A sweep
/// that matched too widely is then a list to uncheck rather than damage — which is the
/// only way an aggressive search is safe to offer at all.
/// </para>
/// </remarks>
public sealed class LeftoverScanner
{
    private readonly PathNormalizer _paths;
    private readonly SafetyPolicy _policy;

    public LeftoverScanner(PathNormalizer paths)
    {
        _paths = paths;
        _policy = new SafetyPolicy(paths);
    }

    /// <summary>
    /// Words too common to search on.
    /// </summary>
    /// <remarks>
    /// A term like "data" or "update" appears in the name of something almost every
    /// program on the machine installs. Matching on one does not widen the sweep, it
    /// destroys it: the result is a list of everybody's files with the subject's somewhere
    /// inside, which an operator cannot approve and should not be asked to.
    /// </remarks>
    private static readonly HashSet<string> TooCommon = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft", "windows", "common", "shared", "program", "programs", "files",
        "data", "cache", "temp", "tmp", "local", "roaming", "system", "system32",
        "update", "updater", "install", "installer", "setup", "uninstall", "app",
        "apps", "application", "software", "config", "settings", "user", "users",
        "default", "current", "version", "client", "server", "service", "services",
        "main", "core", "base", "test", "beta", "help", "docs", "bin", "lib",
    };

    /// <summary>
    /// Turns what is known about a program into the words worth searching for.
    /// </summary>
    /// <remarks>
    /// Deliberately conservative. Every term here becomes a substring match against
    /// thousands of names, so a bad one is not a slightly worse result — it is a plan
    /// containing somebody else's program.
    /// </remarks>
    public static IReadOnlyList<string> TermsFrom(IEnumerable<string?> candidates)
    {
        var terms = new List<string>();

        foreach (string? candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate)) continue;

            // A name whose every word is too common leaves nothing distinctive to search
            // for, and the whole phrase is no substitute: "Microsoft Update Service"
            // matches no directory on earth, so keeping it only makes the term list look
            // like the sweep had something to go on when it did not.
            //
            // Judged on the individual words. The phrase is never itself in the common
            // list — that is what makes it look distinctive when it is not.
            string leaf = Leaf(candidate);
            List<string> parts = Parts(leaf).ToList();

            if (parts.Count > 0 && parts.All(static w => w.Length < 4 || TooCommon.Contains(w))) continue;

            foreach (string word in Split(candidate))
            {
                // Four characters is where a substring stops matching by accident. Three
                // would admit "app", "svc", "net", and with them most of the machine.
                if (word.Length < 4) continue;
                if (TooCommon.Contains(word)) continue;
                if (terms.Contains(word, StringComparer.OrdinalIgnoreCase)) continue;

                terms.Add(word);
            }
        }

        return terms;
    }

    /// <summary>
    /// The last component of a path, without its extension.
    /// </summary>
    /// <remarks>
    /// A product name, a vendor, a file name or a whole path can arrive here. Only the
    /// leaf is ever worth searching for — the directories above it belong to everybody.
    /// </remarks>
    private static string Leaf(string candidate)
    {
        string leaf = candidate.Replace('/', '\\').TrimEnd('\\');
        int slash = leaf.LastIndexOf('\\');
        if (slash >= 0 && slash < leaf.Length - 1) leaf = leaf[(slash + 1)..];

        return Path.GetFileNameWithoutExtension(leaf);
    }

    private static IEnumerable<string> Parts(string leaf) =>
        leaf.Split(
            new[] { ' ', '-', '_', '.', '(', ')', '[', ']' },
            StringSplitOptions.RemoveEmptyEntries);

    private static IEnumerable<string> Split(string candidate)
    {
        string leaf = Leaf(candidate);
        if (leaf.Length == 0) yield break;

        yield return leaf;

        foreach (string part in Parts(leaf)) yield return part;
    }

    /// <summary>The directories programs install themselves into.</summary>
    private static IEnumerable<string> Roots()
    {
        foreach (Environment.SpecialFolder folder in new[]
                 {
                     Environment.SpecialFolder.ProgramFiles,
                     Environment.SpecialFolder.ProgramFilesX86,
                     Environment.SpecialFolder.CommonApplicationData,
                     Environment.SpecialFolder.ApplicationData,
                     Environment.SpecialFolder.LocalApplicationData,
                     Environment.SpecialFolder.CommonStartMenu,
                     Environment.SpecialFolder.StartMenu,
                     Environment.SpecialFolder.CommonDesktopDirectory,
                 })
        {
            string path = Environment.GetFolderPath(folder);
            if (path.Length > 0) yield return path;
        }
    }

    public LeftoverScan Scan(IReadOnlyList<string> terms, LeftoverDepth depth)
    {
        var items = new List<RemovalItem>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int keys = 0;
        int directories = 0;
        string? note = null;

        if (depth == LeftoverDepth.None || terms.Count == 0)
            return new LeftoverScan { Depth = depth, Items = items, Terms = terms };

        void Offer(RemovalKind kind, string target, string? valueName, string why)
        {
            string token = _paths.Tokenize(target);
            if (!seen.Add($"{kind}|{token}|{valueName}")) return;

            var item = new RemovalItem
            {
                Kind = kind,
                Target = token,
                ValueName = valueName,
                Rationale = why,
            };

            // Refused items are still offered, marked. The operator asked what this
            // program left behind, and "there is something here the tool will not touch"
            // is an answer they need — silently dropping it is how a plan comes to look
            // clean while the machine is not.
            SafetyDecision decision = _policy.Evaluate(item);
            if (decision.Verdict == SafetyVerdict.Forbidden)
            {
                items.Add(item with { Rationale = $"{why} — will not be removed: {decision.Reason}" });
                return;
            }

            items.Add(item);
        }

        // ---- directories named after it ------------------------------------------
        foreach (string root in Roots())
        {
            string[] children;
            try { children = Directory.GetDirectories(root); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }

            foreach (string child in children)
            {
                directories++;
                string name = Path.GetFileName(child);
                if (!Matches(name, terms)) continue;

                Offer(RemovalKind.Directory, child, null,
                    $"a directory named after the program, under {_paths.Tokenize(root)}");
            }
        }

        // ---- vendor keys ----------------------------------------------------------
        foreach ((RegistryHive hive, string path) in new[]
                 {
                     (RegistryHive.LocalMachine, @"SOFTWARE"),
                     (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node"),
                     (RegistryHive.CurrentUser, @"Software"),
                 })
        {
            foreach (string name in SubKeys(hive, path, ref keys))
            {
                if (!Matches(name, terms)) continue;
                Offer(RemovalKind.RegistryKey, $"{Prefix(hive)}\\{path}\\{name}", null,
                    "a registry key named after the program");
            }
        }

        if (depth == LeftoverDepth.Safe)
            return new LeftoverScan { Depth = depth, Items = items, Terms = terms, KeysExamined = keys, DirectoriesExamined = directories };

        // ---- uninstall entries, services, App Paths, startup ----------------------
        foreach ((RegistryHive hive, string path) in new[]
                 {
                     (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                     (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                     (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                 })
        {
            foreach (string name in SubKeys(hive, path, ref keys))
            {
                string full = $"{path}\\{name}";
                string? display = Value(hive, full, "DisplayName");
                string? publisher = Value(hive, full, "Publisher");

                // The key's own name is frequently a GUID, so the name a person would
                // recognise is inside it.
                if (!Matches(name, terms) && !Matches(display, terms) && !Matches(publisher, terms)) continue;

                Offer(RemovalKind.RegistryKey, $"{Prefix(hive)}\\{full}", null,
                    $"an uninstall entry for {display ?? name}");
            }
        }

        foreach (string name in SubKeys(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services", ref keys))
        {
            string full = $@"SYSTEM\CurrentControlSet\Services\{name}";
            string? image = Value(RegistryHive.LocalMachine, full, "ImagePath");
            string? display = Value(RegistryHive.LocalMachine, full, "DisplayName");

            if (!Matches(name, terms) && !Matches(display, terms) && !Matches(image, terms)) continue;

            Offer(RemovalKind.Service, name, null,
                $"a service{(image is null ? string.Empty : $" running {image}")}");
        }

        foreach ((RegistryHive hive, string path) in new[]
                 {
                     (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
                     (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                     (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
                     (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                 })
        {
            bool isRun = path.EndsWith("Run", StringComparison.OrdinalIgnoreCase)
                         || path.EndsWith("RunOnce", StringComparison.OrdinalIgnoreCase);

            if (isRun)
            {
                foreach ((string name, string? data) in Values(hive, path, ref keys))
                {
                    if (!Matches(name, terms) && !Matches(data, terms)) continue;
                    Offer(RemovalKind.RegistryValue, $"{Prefix(hive)}\\{path}", name,
                        "a startup entry that names the program");
                }
            }
            else
            {
                foreach (string name in SubKeys(hive, path, ref keys))
                {
                    if (!Matches(name, terms)) continue;
                    Offer(RemovalKind.RegistryKey, $"{Prefix(hive)}\\{path}\\{name}", null,
                        "an App Paths registration");
                }
            }
        }

        foreach (string task in ScheduledTasks(terms))
            Offer(RemovalKind.ScheduledTask, task, null, "a scheduled task named after the program");

        if (depth == LeftoverDepth.Moderate)
            return new LeftoverScan { Depth = depth, Items = items, Terms = terms, KeysExamined = keys, DirectoriesExamined = directories };

        // ---- anything pointing at it ----------------------------------------------
        //
        // Walks the software hives looking at value *data* rather than names. This is the
        // depth that finds a shell extension, a file association or a stale path written
        // somewhere nobody would think to look — and it is the slow one, so it is bounded
        // and says when it stopped.
        const int KeyBudget = 60_000;

        foreach ((RegistryHive hive, string path) in new[]
                 {
                     (RegistryHive.LocalMachine, @"SOFTWARE\Classes"),
                     (RegistryHive.CurrentUser, @"Software\Classes"),
                     (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion"),
                 })
        {
            if (keys >= KeyBudget) break;
            Deep(hive, path, terms, Offer, ref keys, KeyBudget, 0);
        }

        if (keys >= KeyBudget)
            note = $"the deep sweep stopped after {KeyBudget:N0} keys; there may be more references than are listed";

        return new LeftoverScan
        {
            Depth = depth,
            Items = items,
            Terms = terms,
            KeysExamined = keys,
            DirectoriesExamined = directories,
            Note = note,
        };
    }

    private void Deep(
        RegistryHive hive, string path, IReadOnlyList<string> terms,
        Action<RemovalKind, string, string?, string> offer, ref int keys, int budget, int depth)
    {
        // Six levels reaches a CLSID's InprocServer32 and stops well short of walking the
        // whole hive, which on a real machine is millions of keys.
        if (depth > 6 || keys >= budget) return;

        foreach ((string name, string? data) in Values(hive, path, ref keys))
        {
            if (!Matches(data, terms)) continue;

            offer(RemovalKind.RegistryValue, $"{Prefix(hive)}\\{path}", name.Length == 0 ? null : name,
                $"its data points at the program: {Shorten(data)}");
        }

        foreach (string child in SubKeys(hive, path, ref keys))
        {
            if (keys >= budget) return;
            Deep(hive, $"{path}\\{child}", terms, offer, ref keys, budget, depth + 1);
        }
    }

    private static string Shorten(string? text) =>
        text is null ? string.Empty : text.Length <= 120 ? text : text[..120] + "…";

    private static bool Matches(string? candidate, IReadOnlyList<string> terms) =>
        candidate is { Length: > 0 }
        && terms.Any(term => candidate.Contains(term, StringComparison.OrdinalIgnoreCase));

    private static string Prefix(RegistryHive hive) =>
        hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";

    private static RegistryKey Base(RegistryHive hive) =>
        hive == RegistryHive.LocalMachine ? Registry.LocalMachine : Registry.CurrentUser;

    private static IReadOnlyList<string> SubKeys(RegistryHive hive, string path, ref int counted)
    {
        try
        {
            using RegistryKey? key = Base(hive).OpenSubKey(path);
            if (key is null) return Array.Empty<string>();

            string[] names = key.GetSubKeyNames();
            counted += names.Length;
            return names;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return Array.Empty<string>();
        }
    }

    /// <summary>One value's text, or null. Used for the names a person would recognise.</summary>
    private static string? Value(RegistryHive hive, string path, string name)
    {
        try
        {
            using RegistryKey? key = Base(hive).OpenSubKey(path);
            return key?.GetValue(name) as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static IReadOnlyList<(string Name, string? Data)> Values(RegistryHive hive, string path, ref int counted)
    {
        try
        {
            using RegistryKey? key = Base(hive).OpenSubKey(path);
            if (key is null) return Array.Empty<(string, string?)>();

            var result = new List<(string, string?)>();
            foreach (string name in key.GetValueNames())
            {
                counted++;

                // Only text. A binary value that happens to contain the bytes of a path is
                // not a reference to it in any sense the operator could act on.
                object? value = key.GetValue(name);
                if (value is string text) result.Add((name, text));
                else if (value is string[] many) result.Add((name, string.Join(";", many)));
            }

            return result;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return Array.Empty<(string, string?)>();
        }
    }

    /// <summary>Scheduled tasks whose name matches, read from the task store on disk.</summary>
    /// <remarks>
    /// Read from the filesystem rather than by running <c>schtasks</c>, because spawning a
    /// process to enumerate is slower, harder to bound, and leaves its own traces.
    /// </remarks>
    private static IReadOnlyList<string> ScheduledTasks(IReadOnlyList<string> terms)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        var found = new List<string>();

        try
        {
            foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                string name = Path.GetFileName(file);
                if (!Matches(name, terms)) continue;

                // The scheduler names a task by its path under the store, with a leading
                // separator — which is what a delete has to be given.
                found.Add("\\" + Path.GetRelativePath(root, file).Replace('/', '\\'));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }

        return found;
    }
}
