using CaYaTrace.Remediation;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// What happens to a file that will not move, on a file that really will not move.
/// </summary>
/// <remarks>
/// Every case here holds a real lock, sets a real attribute, or asks Windows a real
/// question. A test that mocks the lock proves the code compiles.
/// </remarks>
public sealed class StubbornFileTests : IDisposable
{
    private readonly ITestOutputHelper _out;

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "cayatrace-lock-" + Guid.NewGuid().ToString("n")[..8]);

    public StubbornFileTests(ITestOutputHelper output)
    {
        _out = output;
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private string Quarantine => Path.Combine(_root, "quarantine");

    /// <summary>
    /// One run, closed afterwards.
    /// </summary>
    /// <remarks>
    /// Disposed rather than left to the finaliser because the rollback journal is a real
    /// handle on a real file, and a second run against the same quarantine folder is
    /// precisely what the retry does.
    /// </remarks>
    private List<ItemResult> Run(RemovalForce force, params RemovalItem[] items)
    {
        using var runner = new RemediationRunner(Quarantine, apply: true)
        {
            Force = force,
            ConfirmationHandler = static (_, _, _) => true,
        };

        return runner.Execute(items);
    }

    private static RemovalItem File(string path) => new()
    {
        Kind = RemovalKind.File,
        Target = path,
        Rationale = "under test",
    };

    /// <summary>
    /// A locked file names what is holding it.
    /// </summary>
    /// <remarks>
    /// The single most useful thing a failed removal can say. "In use or locked" leaves an
    /// operator with nowhere to go; the name of the process holding it is usually the whole
    /// answer, because most of the time it is a preview pane or an editor and closing it
    /// costs nothing at all.
    /// </remarks>
    [Fact]
    public void ALockedFileNamesWhatIsHoldingIt()
    {
        string path = Path.Combine(_root, "held.bin");
        System.IO.File.WriteAllBytes(path, new byte[] { 1, 2, 3 });

        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            IReadOnlyList<FileHolder> holders = StubbornFile.WhoIsHolding(path, out string detail);

            _out.WriteLine($"holders: {holders.Count}  detail: {detail}");
            foreach (FileHolder holder in holders) _out.WriteLine($"    {holder}");

            Assert.Contains(holders, h => h.Pid == (uint)Environment.ProcessId);

            List<ItemResult> results = Run(RemovalForce.Standard, File(path));

            _out.WriteLine($"outcome: {results[0].Outcome}  {results[0].Detail}");

            Assert.Equal(ItemOutcome.Failed, results[0].Outcome);
            Assert.Contains("held by", results[0].Detail, StringComparison.OrdinalIgnoreCase);

            // Still there, because a failed removal must not have half-removed anything.
            Assert.True(System.IO.File.Exists(path));
        }
    }

    /// <summary>Once the lock goes, the ordinary path works.</summary>
    [Fact]
    public void TheSameFileMovesOnceNothingHoldsIt()
    {
        string path = Path.Combine(_root, "released.bin");
        System.IO.File.WriteAllBytes(path, new byte[] { 4, 5, 6 });

        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.Equal(ItemOutcome.Failed, Run(RemovalForce.Standard, File(path))[0].Outcome);
        }

        ItemResult result = Run(RemovalForce.Standard, File(path))[0];

        _out.WriteLine($"{result.Outcome}: {result.Detail}");

        Assert.Equal(ItemOutcome.Removed, result.Outcome);
        Assert.False(System.IO.File.Exists(path));
    }

    /// <summary>
    /// Read-only is bookkeeping, not protection, and does not stop a removal.
    /// </summary>
    /// <remarks>
    /// A program that marks its own files read-only, hidden and system has not secured
    /// them. Refusing to move one on that basis is refusing the only thing that was asked.
    /// </remarks>
    [Fact]
    public void AReadOnlyHiddenSystemFileIsStillRemoved()
    {
        string path = Path.Combine(_root, "marked.bin");
        System.IO.File.WriteAllBytes(path, new byte[] { 7 });
        System.IO.File.SetAttributes(path,
            FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);

        ItemResult result = Run(RemovalForce.Standard, File(path))[0];

        _out.WriteLine($"{result.Outcome}: {result.Detail}");

        Assert.Equal(ItemOutcome.Removed, result.Outcome);
        Assert.False(System.IO.File.Exists(path));
    }

    /// <summary>
    /// A folder goes only once it is empty, and says what is still in it.
    /// </summary>
    /// <remarks>
    /// This is the guarantee that makes it safe to list a program's directory beside its
    /// files. Whatever the operator chose to keep is still in the folder and keeps the
    /// folder — they cannot lose a file by leaving the directory ticked.
    /// </remarks>
    [Fact]
    public void AFolderWithSomethingKeptInItIsNotRemoved()
    {
        string folder = Path.Combine(_root, "program");
        Directory.CreateDirectory(folder);

        string theirs = Path.Combine(folder, "notes.txt");
        string ours = Path.Combine(folder, "payload.bin");
        System.IO.File.WriteAllText(theirs, "keep me");
        System.IO.File.WriteAllBytes(ours, new byte[] { 9 });

        // The operator ticked the program's file and the folder, and left theirs alone.
        List<ItemResult> results = Run(
            RemovalForce.Standard,
            File(ours),
            new RemovalItem { Kind = RemovalKind.Directory, Target = folder, Rationale = "under test" });

        foreach (ItemResult r in results) _out.WriteLine($"{r.Item.Kind,-10} {r.Outcome}: {r.Detail}");

        Assert.Equal(ItemOutcome.Removed, results.Single(r => r.Item.Kind == RemovalKind.File).Outcome);

        ItemResult directory = results.Single(r => r.Item.Kind == RemovalKind.Directory);
        Assert.Equal(ItemOutcome.SkippedByPolicy, directory.Outcome);
        Assert.Contains("notes.txt", directory.Detail, StringComparison.Ordinal);

        Assert.True(System.IO.File.Exists(theirs));
        Assert.True(Directory.Exists(folder));
    }

    /// <summary>And it does go, once nothing of theirs is left.</summary>
    [Fact]
    public void AFolderGoesOnceEverythingInItHas()
    {
        string folder = Path.Combine(_root, "alone");
        Directory.CreateDirectory(folder);
        System.IO.File.WriteAllBytes(Path.Combine(folder, "only.bin"), new byte[] { 1 });

        List<ItemResult> results = Run(
            RemovalForce.Standard,
            File(Path.Combine(folder, "only.bin")),
            new RemovalItem { Kind = RemovalKind.Directory, Target = folder, Rationale = "under test" });

        foreach (ItemResult r in results) _out.WriteLine($"{r.Item.Kind,-10} {r.Outcome}: {r.Detail}");

        Assert.All(results, r => Assert.Equal(ItemOutcome.Removed, r.Outcome));
        Assert.False(Directory.Exists(folder));
    }

    /// <summary>
    /// Insisting stops the process that is holding the file, and then the file moves.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The rung that separates this from every removal that gives up. A real second
    /// process takes a real exclusive lock — nothing here is simulated — and the run has
    /// to find it, stop it, and finish.
    /// </para>
    /// <para>
    /// It is a child of this test so that stopping it costs nothing, which is also the
    /// shape of the case it stands for: the thing holding a program's file is nearly
    /// always the program.
    /// </para>
    /// </remarks>
    [Fact]
    public void InsistingStopsWhateverIsHoldingTheFile()
    {
        string path = Path.Combine(_root, "guarded.bin");
        System.IO.File.WriteAllBytes(path, new byte[] { 0xBA, 0xDD });

        string script =
            $"$s=[System.IO.File]::Open('{path}',3,3,0); Start-Sleep -Seconds 120; $s.Dispose()";

        using var holder = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -Command \"{script}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
        });

        if (holder is null)
        {
            _out.WriteLine("powershell would not start; nothing to test against");
            return;
        }

        try
        {
            // Wait for the lock to actually exist, rather than assuming it does.
            for (int i = 0; i < 100 && CanOpenExclusively(path); i++) Thread.Sleep(50);

            Assert.False(CanOpenExclusively(path), "the helper never took the lock");

            IReadOnlyList<FileHolder> holders = StubbornFile.WhoIsHolding(path, out _);
            foreach (FileHolder h in holders) _out.WriteLine($"holder: {h}");
            Assert.Contains(holders, h => h.Pid == (uint)holder.Id);

            // The gentle pass reports and stops.
            ItemResult gentle = Run(RemovalForce.Standard, File(path))[0];
            _out.WriteLine($"standard  -> {gentle.Outcome}: {gentle.Detail}");
            Assert.Equal(ItemOutcome.Failed, gentle.Outcome);
            Assert.True(System.IO.File.Exists(path));

            // The insistent pass does something about it.
            ItemResult insistent = Run(RemovalForce.Insistent, File(path))[0];
            _out.WriteLine($"insistent -> {insistent.Outcome}: {insistent.Detail}");

            // Stopping the holder is the rung that should carry this, and it is the only
            // one that ends with the file already gone. Reaching the restart rung instead
            // would mean the stop failed, which is the bug this exists to catch.
            Assert.Equal(ItemOutcome.Removed, insistent.Outcome);
            Assert.False(System.IO.File.Exists(path));
            Assert.True(holder.HasExited);
        }
        finally
        {
            try { if (!holder.HasExited) holder.Kill(entireProcessTree: true); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }

            ForgetAnyPendingRestart();
        }
    }

    /// <summary>
    /// Removes any restart-time move this test asked Windows for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The last rung of the ladder writes to the session manager's pending-rename list,
    /// which outlives the test, the test run, and the working folder. A test is allowed to
    /// use a machine; it is not allowed to leave something on it.
    /// </para>
    /// <para>
    /// This was not hypothetical. An earlier version of the ladder misread the Restart
    /// Manager's application type, could not stop the holder it had correctly found, fell
    /// through to this rung, and left an entry naming a temp folder that no longer existed.
    /// </para>
    /// </remarks>
    private void ForgetAnyPendingRestart()
    {
        const string Key = @"SYSTEM\CurrentControlSet\Control\Session Manager";
        const string Name = "PendingFileRenameOperations";

        try
        {
            using Microsoft.Win32.RegistryKey? manager =
                Microsoft.Win32.Registry.LocalMachine.OpenSubKey(Key, writable: true);

            if (manager?.GetValue(Name) is not string[] entries) return;

            // The list is pairs of source and destination, so a surviving entry has to
            // drop both halves or the next boot reads the list misaligned.
            var kept = new List<string>();
            for (int i = 0; i < entries.Length; i += 2)
            {
                string source = entries[i];
                string destination = i + 1 < entries.Length ? entries[i + 1] : string.Empty;

                // Matched on the working-folder prefix rather than on this run's folder,
                // so a run that left something behind before this cleanup existed is
                // tidied by the next one instead of sitting there forever.
                const string Ours = "cayatrace-lock-";

                if (source.Contains(Ours, StringComparison.OrdinalIgnoreCase)
                    || destination.Contains(Ours, StringComparison.OrdinalIgnoreCase))
                {
                    _out.WriteLine($"removed a restart-time move this test created: {source}");
                    continue;
                }

                kept.Add(source);
                kept.Add(destination);
            }

            if (kept.Count != entries.Length)
                manager.SetValue(Name, kept.ToArray(), Microsoft.Win32.RegistryValueKind.MultiString);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException
                                       or IOException)
        {
            // Not elevated, which also means the rung that writes it could not have run.
            _out.WriteLine($"could not check the pending-restart list: {ex.Message}");
        }
    }

    private static bool CanOpenExclusively(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <summary>Nothing is deleted; it is moved, and it is still there afterwards.</summary>
    [Fact]
    public void WhatWasRemovedIsStillInQuarantine()
    {
        string path = Path.Combine(_root, "evidence.bin");
        System.IO.File.WriteAllBytes(path, new byte[] { 0xC0, 0xFF, 0xEE });

        ItemResult result = Run(RemovalForce.Standard, File(path))[0];

        Assert.Equal(ItemOutcome.Removed, result.Outcome);
        Assert.NotNull(result.QuarantinePath);
        Assert.True(System.IO.File.Exists(result.QuarantinePath!));
        Assert.Equal(new byte[] { 0xC0, 0xFF, 0xEE }, System.IO.File.ReadAllBytes(result.QuarantinePath!));
    }
}
