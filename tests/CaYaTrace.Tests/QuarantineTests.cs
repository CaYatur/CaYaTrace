using System.Text.Json;
using CaYaTrace.Remediation;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Reading back what a removal moved aside.
/// </summary>
/// <remarks>
/// <para>
/// The journal these tests parse is written by <see cref="RemediationRunner"/>, and the
/// shape below is copied from a real one. That matters: the first version of the reader
/// was written against an invented schema with top-level <c>original</c> and
/// <c>quarantine</c> fields, and it silently listed nothing at all — the removal reported
/// three files moved and the operator was offered a choice about an empty list.
/// </para>
/// <para>
/// Silently, because a journal line that does not match is skipped rather than raised. So
/// the format is pinned here instead of trusted.
/// </para>
/// </remarks>
public sealed class QuarantineTests : IDisposable
{
    private readonly string _root =
        Path.Combine(Path.GetTempPath(), $"cayatrace-quarantine-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>The shape the runner actually writes, and the only one that counts.</summary>
    private void Journal(params object[] entries)
    {
        Directory.CreateDirectory(_root);
        File.WriteAllLines(
            Path.Combine(_root, "rollback-journal.jsonl"),
            entries.Select(static e => JsonSerializer.Serialize(e)));
    }

    private string Held(string relative, string content = "payload")
    {
        string path = Path.Combine(_root, "files", relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void ListsWhatTheRunnerRecordedMoving()
    {
        string held = Held("C/ProgramData/Probe/agent.exe");
        string original = Path.Combine(_root, "origin", "agent.exe");

        Journal(new
        {
            at = DateTimeOffset.UtcNow,
            kind = "filesystem",
            target = @"%PROGRAMDATA%\Probe\agent.exe",
            payload = new { original, quarantined = held, isDirectory = false },
        });

        QuarantinedItem item = Assert.Single(new Quarantine(_root).Contents());

        Assert.Equal(held, item.QuarantinePath);
        Assert.Equal(original, item.OriginalPath);
        Assert.False(item.IsDirectory);
        Assert.True(item.CanRestore);
        Assert.True(item.SizeBytes > 0);
    }

    /// <summary>
    /// A service registration is exported, not moved, so it is not sitting in quarantine.
    /// </summary>
    /// <remarks>
    /// Listing it would offer the operator a "put it back" that does not put anything
    /// back — service and registry state are restored from the <c>.reg</c> beside it, by a
    /// different route.
    /// </remarks>
    [Fact]
    public void OnlyFilesAreListedAsHeld()
    {
        string held = Held("C/ProgramData/Probe/payload.exe");

        Journal(
            new
            {
                at = DateTimeOffset.UtcNow,
                kind = "service",
                target = "ProbeSvc",
                payload = new { backup = @"C:\q\registry\ProbeSvc.reg", imagePath = @"C:\x.exe" },
            },
            new
            {
                at = DateTimeOffset.UtcNow,
                kind = "registry-value",
                target = @"HKCU\Software\…\Run",
                payload = new { keyPath = @"HKCU\Software\…\Run", valueName = "Probe", backup = @"C:\q\r.reg" },
            },
            new
            {
                at = DateTimeOffset.UtcNow,
                kind = "filesystem",
                target = @"%PROGRAMDATA%\Probe\payload.exe",
                payload = new { original = Path.Combine(_root, "origin", "payload.exe"), quarantined = held, isDirectory = false },
            });

        QuarantinedItem item = Assert.Single(new Quarantine(_root).Contents());
        Assert.Equal(held, item.QuarantinePath);
    }

    [Fact]
    public void PutsAFileBackWhereItCameFrom()
    {
        string held = Held("C/ProgramData/Probe/agent.exe", "the original bytes");
        string original = Path.Combine(_root, "origin", "agent.exe");

        Journal(new
        {
            at = DateTimeOffset.UtcNow,
            kind = "filesystem",
            target = "probe",
            payload = new { original, quarantined = held, isDirectory = false },
        });

        var quarantine = new Quarantine(_root);
        (QuarantinedItem _, bool ok, string _) = Assert.Single(quarantine.Apply(QuarantineDisposition.Restore));

        Assert.True(ok);
        Assert.True(File.Exists(original));
        Assert.Equal("the original bytes", File.ReadAllText(original));
        Assert.Empty(quarantine.Contents());
    }

    /// <summary>
    /// Something already sitting at the original location is not overwritten.
    /// </summary>
    /// <remarks>
    /// A restore that clobbers whatever is there now turns an undo into a second removal.
    /// </remarks>
    [Fact]
    public void RefusesToRestoreOverSomethingThatIsThereNow()
    {
        string held = Held("C/ProgramData/Probe/agent.exe");
        string original = Path.Combine(_root, "origin", "agent.exe");

        Directory.CreateDirectory(Path.GetDirectoryName(original)!);
        File.WriteAllText(original, "something else lives here now");

        Journal(new
        {
            at = DateTimeOffset.UtcNow,
            kind = "filesystem",
            target = "probe",
            payload = new { original, quarantined = held, isDirectory = false },
        });

        (QuarantinedItem _, bool ok, string message) =
            Assert.Single(new Quarantine(_root).Apply(QuarantineDisposition.Restore));

        Assert.False(ok);
        Assert.Contains("already exists", message);
        Assert.Equal("something else lives here now", File.ReadAllText(original));
    }

    /// <summary>
    /// A journal naming a path outside the quarantine folder does not get to delete it.
    /// </summary>
    /// <remarks>
    /// Deleting is the one irreversible operation in the tool and the path comes from a
    /// file on disk. This containment check is the only thing between an edited journal
    /// and a tool that deletes an arbitrary directory.
    /// </remarks>
    [Fact]
    public void RefusesToDeleteOutsideTheQuarantineFolder()
    {
        string outside = Path.Combine(Path.GetTempPath(), $"cayatrace-outside-{Guid.NewGuid():N}.txt");
        File.WriteAllText(outside, "not ours to delete");

        try
        {
            Journal(new
            {
                at = DateTimeOffset.UtcNow,
                kind = "filesystem",
                target = "probe",
                payload = new { original = Path.Combine(_root, "origin", "x.txt"), quarantined = outside, isDirectory = false },
            });

            (QuarantinedItem _, bool ok, string message) =
                Assert.Single(new Quarantine(_root).Apply(QuarantineDisposition.Delete));

            Assert.False(ok);
            Assert.Contains("outside the quarantine", message);
            Assert.True(File.Exists(outside));
        }
        finally
        {
            File.Delete(outside);
        }
    }

    [Fact]
    public void DeletesWhatItIsHolding()
    {
        string held = Held("C/ProgramData/Probe/agent.exe");

        Journal(new
        {
            at = DateTimeOffset.UtcNow,
            kind = "filesystem",
            target = "probe",
            payload = new { original = Path.Combine(_root, "origin", "agent.exe"), quarantined = held, isDirectory = false },
        });

        var quarantine = new Quarantine(_root);
        (QuarantinedItem _, bool ok, string _) = Assert.Single(quarantine.Apply(QuarantineDisposition.Delete));

        Assert.True(ok);
        Assert.False(File.Exists(held));
        Assert.Empty(quarantine.Contents());
    }

    [Fact]
    public void AnUnreadableJournalIsAnEmptyListRatherThanACrash()
    {
        Directory.CreateDirectory(_root);
        File.WriteAllText(Path.Combine(_root, "rollback-journal.jsonl"), "{not json\n\n{\"kind\":\"filesystem\"}\n");

        Assert.Empty(new Quarantine(_root).Contents());
    }
}
