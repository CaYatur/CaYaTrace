using CaYaTrace.Analysis.Persistence;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Recognising what will undo a removal before running one.
/// </summary>
/// <remarks>
/// <para>
/// The inspection reads a service's own registry values, so the parts worth testing
/// without touching a machine are the two decisions it makes from them: whether the
/// service brings itself back after being stopped, and whether it starts again at boot.
/// Both come from the values below, and both were measured against a real service before
/// being written down.
/// </para>
/// <para>
/// This matters because the failure is silent. A removal that stops a service configured
/// to restart in sixty seconds reports success, and the machine looks clean right up
/// until somebody watches it for a minute.
/// </para>
/// </remarks>
public sealed class SelfProtectionTests
{
    /// <summary>
    /// The exact value read from a service configured with
    /// <c>sc failure … actions= restart/60000/restart/120000</c>.
    /// </summary>
    private const string RestartsTwice =
        "80510100000000000000000002000000140000000100000060ea000001000000c0d40100";

    [Fact]
    public void RecognisesAServiceThatBringsItselfBack()
    {
        ServiceRecovery? recovery = ServiceFailureActions.DecodeHex(RestartsTwice);

        Assert.NotNull(recovery);
        Assert.True(recovery!.RestartsOnFailure);
        Assert.False(recovery.RebootsMachine);
        Assert.False(recovery.RunsCommand);

        Assert.Equal(2, recovery.Actions.Count);
        Assert.Equal(60000, recovery.Actions[0].DelayMilliseconds);
        Assert.Equal(120000, recovery.Actions[1].DelayMilliseconds);

        // The wording that reaches the operator before they decide to run anything.
        Assert.Equal("restart after 60s, then restart after 120s", ServiceFailureActions.Describe(recovery));
    }

    /// <summary>
    /// A service that reboots the machine on failure is worth refusing to fight.
    /// </summary>
    /// <remarks>
    /// Rare and deliberate. Anything configured this way turns a removal attempt into an
    /// unplanned restart of somebody's computer, so it is recognised distinctly rather
    /// than lumped in with restarting.
    /// </remarks>
    [Fact]
    public void RecognisesAServiceThatRebootsTheMachine()
    {
        // reset 86400, one action: type 2 (reboot) after 60s.
        ServiceRecovery? recovery = ServiceFailureActions.DecodeHex(
            "80510100000000000000000001000000140000000200000060ea0000");

        Assert.NotNull(recovery);
        Assert.True(recovery!.RebootsMachine);
        Assert.False(recovery.RestartsOnFailure);
        Assert.Contains("reboot the machine", ServiceFailureActions.Describe(recovery));
    }

    /// <summary>A service that runs a command of its own when it fails.</summary>
    [Fact]
    public void RecognisesAServiceThatRunsSomethingWhenItFails()
    {
        // one action: type 3 (run command) after 1s.
        ServiceRecovery? recovery = ServiceFailureActions.DecodeHex(
            "8051010000000000000000000100000014000000030000000e030000");

        Assert.NotNull(recovery);
        Assert.True(recovery!.RunsCommand);
        Assert.Contains("run a command", ServiceFailureActions.Describe(recovery));
    }

    /// <summary>Recovery actions that do nothing are not something to disarm.</summary>
    [Fact]
    public void AServiceWithNoActionsHasNothingToDisarm()
    {
        ServiceRecovery? recovery = ServiceFailureActions.DecodeHex(
            "805101000000000000000000030000001400000000000000000000000000000000000000000000000000000000000000");

        Assert.NotNull(recovery);
        Assert.Empty(recovery!.Actions);
        Assert.False(recovery.RestartsOnFailure);
        Assert.Equal("no recovery actions", ServiceFailureActions.Describe(recovery));
    }

    /// <summary>
    /// Which start types run without anyone logging in.
    /// </summary>
    /// <remarks>
    /// The other half of the question. Stopping a service does nothing about the next
    /// boot, so a removal that clears the recovery actions and leaves the start type is
    /// a removal that works until the machine is restarted.
    /// </remarks>
    [Theory]
    [InlineData(0, true)]    // boot
    [InlineData(1, true)]    // system
    [InlineData(2, true)]    // automatic
    [InlineData(3, false)]   // on demand
    [InlineData(4, false)]   // disabled
    public void KnowsWhichStartTypesComeBackOnTheirOwn(int start, bool runsBeforeLogon)
        => Assert.Equal(runsBeforeLogon, ServiceStartType.RunsBeforeLogon(start));

    [Fact]
    public void DescribesStartTypesInWordsAnOperatorCanActOn()
    {
        Assert.Equal("starts automatically", ServiceStartType.Describe(2));
        Assert.Equal("starts when something asks for it", ServiceStartType.Describe(3));
        Assert.Equal("disabled", ServiceStartType.Describe(4));
        Assert.Contains("kernel", ServiceStartType.Describe(0));
    }
}
