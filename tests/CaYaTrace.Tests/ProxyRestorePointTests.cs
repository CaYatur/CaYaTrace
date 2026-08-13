using System.Text.Json;
using CaYaTrace.Collectors.Proxy;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// The record that lets the next launch undo what a killed session left behind.
/// </summary>
/// <remarks>
/// The registry half of this is covered by driving the shipping binary against a real
/// machine, which is the only way to prove a restore actually restores. What is worth
/// pinning here is the part that quietly gets it wrong: a value that was absent is not a
/// value that was zero, and losing that difference means "restoring" a machine into a
/// state it was never in.
/// </remarks>
public sealed class ProxyRestorePointTests
{
    [Fact]
    public void AnAbsentValueSurvivesTheRoundTripAsAbsent()
    {
        var point = new ProxyRestorePoint
        {
            Port = 51000,
            ProxyEnable = null,
            ProxyServer = null,
            ProxyOverride = null,
        };

        ProxyRestorePoint? back = JsonSerializer.Deserialize<ProxyRestorePoint>(
            JsonSerializer.Serialize(point));

        Assert.NotNull(back);

        // Not zero, and not an empty string. Writing ProxyEnable=0 where there had been no
        // value leaves behind a change nobody made, on a machine the tool promised to
        // return untouched.
        Assert.Null(back!.ProxyEnable);
        Assert.Null(back.ProxyServer);
        Assert.Null(back.ProxyOverride);
    }

    [Fact]
    public void AZeroValueSurvivesTheRoundTripAsZero()
    {
        var point = new ProxyRestorePoint { Port = 51000, ProxyEnable = 0, ProxyServer = "" };

        ProxyRestorePoint? back = JsonSerializer.Deserialize<ProxyRestorePoint>(
            JsonSerializer.Serialize(point));

        Assert.NotNull(back);
        Assert.Equal(0, back!.ProxyEnable);
        Assert.Equal("", back.ProxyServer);
    }

    [Fact]
    public void CapturingRecordsThePortSoTheChangeCanBeRecognisedLater()
    {
        ProxyRestorePoint point = ProxyRestorePoint.Capture(51000, winHttpWillBeApplied: false);

        Assert.Equal(51000, point.Port);
        Assert.Equal(Environment.ProcessId, point.ProcessId);
        Assert.False(point.WinHttpApplied);
    }

    /// <summary>A sweep that fixed everything has nothing to say.</summary>
    [Fact]
    public void AFullyRepairedSweepDoesNotAskForAttention()
    {
        var result = new ProxyRestorePoint.SweepResult(
            FoundRestorePoint: true, RestoredWinINet: true, RestoredWinHttp: true,
            WinHttpNeedsElevation: false, StaleAuthorities: 1, RemovedAuthorities: 1);

        Assert.True(result.DidAnything);
        Assert.False(result.NeedsAttention);
    }

    /// <summary>
    /// A machine that is still broken must say so, whatever else the sweep managed.
    /// </summary>
    [Fact]
    public void AMachineStillPointingAtADeadPortAsksForAttention()
    {
        var result = new ProxyRestorePoint.SweepResult(
            FoundRestorePoint: true, RestoredWinINet: true, RestoredWinHttp: false,
            WinHttpNeedsElevation: true, StaleAuthorities: 0, RemovedAuthorities: 0);

        Assert.True(result.NeedsAttention);
        Assert.Contains("proxy.sweep.winhttp_needs_admin", result.MessageKeys());
    }

    /// <summary>
    /// A certificate authority that is still trusted and could not be removed is the
    /// worst state this tool can leave a machine in, so it is never silent.
    /// </summary>
    [Fact]
    public void AnUnremovedAuthorityAsksForAttention()
    {
        var result = new ProxyRestorePoint.SweepResult(
            FoundRestorePoint: false, RestoredWinINet: false, RestoredWinHttp: false,
            WinHttpNeedsElevation: false, StaleAuthorities: 2, RemovedAuthorities: 0);

        Assert.True(result.NeedsAttention);
        Assert.Contains("proxy.sweep.ca_needs_admin", result.MessageKeys());
    }

    /// <summary>A clean launch says nothing at all.</summary>
    [Fact]
    public void ACleanMachineProducesNoMessages()
    {
        var result = new ProxyRestorePoint.SweepResult(
            FoundRestorePoint: false, RestoredWinINet: false, RestoredWinHttp: false,
            WinHttpNeedsElevation: false, StaleAuthorities: 0, RemovedAuthorities: 0);

        Assert.False(result.DidAnything);
        Assert.False(result.NeedsAttention);
        Assert.Empty(result.MessageKeys());
    }
}
