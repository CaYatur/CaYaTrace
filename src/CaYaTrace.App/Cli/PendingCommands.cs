namespace CaYaTrace.App.Cli;

/// <summary>
/// Applies a removal package produced from a recorded session.
/// </summary>
/// <remarks>
/// Wired to the planner in <c>CaYaTrace.Remediation</c>. The safety posture is fixed and
/// not configurable away: dry-run is the default, every item is verified against the
/// fingerprint recorded at capture time before it is touched, removal moves items to
/// quarantine rather than deleting them, and a rollback journal is written first.
/// </remarks>
public static class RemediateCommand
{
    public static int Run(CommandLine cmd)
    {
        string packagePath = Path.GetFullPath(cmd.Require("package"));
        if (!File.Exists(packagePath))
        {
            Console.Error.WriteLine($"cayatrace: package not found: {packagePath}");
            return 1;
        }

        bool apply = cmd.Flag("apply");
        string quarantine = cmd.Get("quarantine")
                            ?? Path.Combine(Path.GetDirectoryName(packagePath)!, "quarantine");

        return Remediation.RemediationRunner.Run(packagePath, quarantine, apply);
    }
}

/// <summary>
/// Runs as a collection agent inside a VM, reporting to a paired host.
/// </summary>
/// <remarks>
/// Not implemented in 0.1. The transport design — pairing-code enrollment, an agent
/// that stays inert until an approved host connects, and an authenticated encrypted
/// channel that does not depend on the local network having usable TLS — is specified
/// in docs/ARCHITECTURE.md under "Fleet". It is deliberately not stubbed with
/// something weaker in the meantime: a half-built remote-collection channel on an
/// analysis network is a liability, not a feature.
/// </remarks>
public static class AgentCommand
{
    public static int Run(CommandLine cmd)
    {
        Console.Error.WriteLine(
            "cayatrace: fleet agent mode is not implemented in this build.");
        Console.Error.WriteLine(
            "           Multi-VM collection is specified in docs/ARCHITECTURE.md (Fleet).");
        Console.Error.WriteLine(
            "           Record on each VM with `CaYaTrace trace` and compare the sessions instead.");
        return 3;
    }
}
