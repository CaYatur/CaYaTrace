using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Model;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Guards the single assumption everything else rests on: that two events attributed
/// to "PID 4812" are only merged when they really came from the same process.
/// </summary>
public sealed class ProcessIdentityTests
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 11, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void StrongKeys_WithDifferentStartKeys_AreDifferentProcesses()
    {
        var a = ProcessKey.FromStartKey(4812, 0x1000, T0);
        var b = ProcessKey.FromStartKey(4812, 0x2000, T0.AddSeconds(30));

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void StrongKeys_WithSameStartKey_AreSameProcessEvenIfPidDiffers()
    {
        // A rundown may report the PID differently than the start event; the start
        // key is authoritative.
        var a = ProcessKey.FromStartKey(4812, 0x1000, T0);
        var b = ProcessKey.FromStartKey(4813, 0x1000, T0);

        Assert.Equal(a, b);
    }

    [Fact]
    public void WeakKeys_SamePidDifferentCreateTime_AreDifferentProcesses()
    {
        var a = ProcessKey.FromCreateTime(4812, T0);
        var b = ProcessKey.FromCreateTime(4812, T0.AddSeconds(30));

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void EqualKeys_ShareHashCode()
    {
        // Equals can unify a strong key with a weak one for the same PID, so the hash
        // must not include the fields that differ or dictionary lookups break.
        var strong = ProcessKey.FromStartKey(4812, 0x1000, T0);
        var weak = new ProcessKey(4812, 0, 0);

        Assert.Equal(strong, weak);
        Assert.Equal(strong.GetHashCode(), weak.GetHashCode());
    }

    [Theory]
    [InlineData(4812u, 0x1000UL, 0L)]
    [InlineData(9999u, 0UL, 638_000_000_000_000_000L)]
    public void KeysRoundTripThroughText(uint pid, ulong startKey, long ticks)
    {
        var original = new ProcessKey(pid, startKey, ticks);

        Assert.True(ProcessKey.TryParse(original.ToString(), out ProcessKey parsed));
        Assert.Equal(original.Pid, parsed.Pid);
        Assert.Equal(original.StartKey, parsed.StartKey);
    }

    [Fact]
    public void PidReuse_ResolvesToTheGenerationAliveAtEventTime()
    {
        // The failure this exists to prevent: an installer's child exits, Windows hands
        // the PID to something unrelated, and a naive monitor staples the second
        // process's activity onto the first process's subtree.
        var table = new ProcessTable();

        var first = new ProcessNode
        {
            Key = ProcessKey.FromStartKey(4812, 0x1000, T0),
            ImagePath = @"C:\Temp\setup.exe",
            StartTime = T0,
        };
        table.AddOrUpdate(first);
        table.MarkExit(first.Key, T0.AddSeconds(10), 0);

        var second = new ProcessNode
        {
            Key = ProcessKey.FromStartKey(4812, 0x2000, T0.AddSeconds(20)),
            ImagePath = @"C:\Windows\System32\notepad.exe",
            StartTime = T0.AddSeconds(20),
        };
        table.AddOrUpdate(second);

        Assert.Equal(first.Key, table.Resolve(4812, T0.AddSeconds(5)));
        Assert.Equal(second.Key, table.Resolve(4812, T0.AddSeconds(25)));
    }

    [Fact]
    public void EventBetweenGenerations_AttachesToTheGenerationThatHadStarted()
    {
        var table = new ProcessTable();
        var first = new ProcessNode { Key = ProcessKey.FromStartKey(100, 1, T0), StartTime = T0 };
        table.AddOrUpdate(first);
        table.MarkExit(first.Key, T0.AddSeconds(5), 0);
        var second = new ProcessNode { Key = ProcessKey.FromStartKey(100, 2, T0.AddSeconds(20)), StartTime = T0.AddSeconds(20) };
        table.AddOrUpdate(second);

        // 12s: first has exited, second has not started. The first is the only
        // process that could plausibly have produced a late-flushed event.
        Assert.Equal(first.Key, table.Resolve(100, T0.AddSeconds(12)));
    }

    [Fact]
    public void ChildLinksToTheParentGenerationAliveAtItsStart()
    {
        var table = new ProcessTable();

        var oldParent = new ProcessNode { Key = ProcessKey.FromStartKey(500, 0xA, T0), StartTime = T0 };
        table.AddOrUpdate(oldParent);
        table.MarkExit(oldParent.Key, T0.AddSeconds(5), 0);

        var newParent = new ProcessNode { Key = ProcessKey.FromStartKey(500, 0xB, T0.AddSeconds(10)), StartTime = T0.AddSeconds(10) };
        table.AddOrUpdate(newParent);

        var child = new ProcessNode
        {
            Key = ProcessKey.FromStartKey(700, 0xC, T0.AddSeconds(15)),
            ParentPid = 500,
            StartTime = T0.AddSeconds(15),
        };
        table.AddOrUpdate(child);

        Assert.Equal(newParent.Key, child.ParentKey);
        Assert.Contains(child.Key, newParent.Children);
        Assert.DoesNotContain(child.Key, oldParent.Children);
    }

    [Fact]
    public void ScopePropagatesToDescendantsButNotToSiblings()
    {
        var table = new ProcessTable();
        var root = new ProcessNode { Key = ProcessKey.FromStartKey(10, 1, T0), StartTime = T0 };
        var child = new ProcessNode { Key = ProcessKey.FromStartKey(11, 2, T0), ParentPid = 10, StartTime = T0.AddSeconds(1) };
        var grandchild = new ProcessNode { Key = ProcessKey.FromStartKey(12, 3, T0), ParentPid = 11, StartTime = T0.AddSeconds(2) };
        var unrelated = new ProcessNode { Key = ProcessKey.FromStartKey(13, 4, T0), StartTime = T0.AddSeconds(3) };

        table.AddOrUpdate(root);
        table.AddOrUpdate(child);
        table.AddOrUpdate(grandchild);
        table.AddOrUpdate(unrelated);

        table.MarkScope(root.Key);

        Assert.True(root.InScope);
        Assert.True(child.InScope);
        Assert.True(grandchild.InScope);
        Assert.False(unrelated.InScope);
    }

    [Fact]
    public void AdoptionPullsInProcessesTheParentChainWouldMiss()
    {
        // services.exe starts the installed service, so the real parent chain points
        // at services.exe rather than at the installer. Without adoption the service
        // process — often the whole point of the install — sits outside the tree.
        var table = new ProcessTable();
        var installer = new ProcessNode { Key = ProcessKey.FromStartKey(10, 1, T0), StartTime = T0, InScope = true };
        var scm = new ProcessNode { Key = ProcessKey.FromStartKey(600, 2, T0), StartTime = T0 };
        var service = new ProcessNode { Key = ProcessKey.FromStartKey(900, 3, T0), ParentPid = 600, StartTime = T0.AddSeconds(4) };

        table.AddOrUpdate(installer);
        table.AddOrUpdate(scm);
        table.AddOrUpdate(service);

        Assert.False(service.InScope);

        Assert.True(table.Adopt(service.Key, installer.Key, "service-start"));
        Assert.True(service.InScope);
        Assert.Equal("adopted:service-start", service.ScopeReason);
        Assert.Contains(service.Key, installer.Children);
    }

    [Fact]
    public void ThreadOwnershipIsClearedWhenTheProcessExits()
    {
        var table = new ProcessTable();
        var process = new ProcessNode { Key = ProcessKey.FromStartKey(10, 1, T0), StartTime = T0 };
        table.AddOrUpdate(process);
        table.SetThreadOwner(555, process.Key);

        Assert.Equal(process.Key, table.ResolveByThread(555));

        table.MarkExit(process.Key, T0.AddSeconds(1), 0);

        Assert.Equal(ProcessKey.None, table.ResolveByThread(555));
    }
}
