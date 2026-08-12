using CaYaTrace.Fleet;

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
/// <para>
/// The agent connects <em>out</em> to an address the operator typed and then does nothing at
/// all until the host approves it. It opens no listening socket, so putting the agent on
/// a machine does not give that machine a remote entry point, and the pairing code is
/// the whole of the authentication — it is mixed into key derivation, so a peer that
/// does not have it cannot complete the handshake at all.
/// </para>
/// <para>
/// Two capabilities are unreachable from here by design: the agent will not capture
/// packets or intercept HTTPS on a host's instruction. Both change the machine they run
/// on, and a host that could switch them on remotely would turn a paired agent into a
/// remote administration channel.
/// </para>
/// </remarks>
public static class AgentCommand
{
    public static int Run(CommandLine cmd)
    {
        string? endpoint = cmd.Get("host");
        string? code = cmd.Get("pair");

        if (endpoint is null || code is null)
        {
            Console.Error.WriteLine("cayatrace: agent needs --host <addr:port> and --pair <code>");
            Console.Error.WriteLine("           Both are shown in the Fleet tab of the workbench on the host machine.");
            return 2;
        }

        if (!PairingCode.LooksValid(code))
        {
            // Checked before connecting rather than after: a mistyped code and a wrong
            // host produce the same handshake failure, and telling them apart afterwards
            // is guesswork.
            Console.Error.WriteLine("cayatrace: that does not look like a pairing code.");
            Console.Error.WriteLine("           Codes are 12 characters, e.g. ABCD-EFGH-JKMN.");
            return 2;
        }

        (string host, int port) = SplitEndpoint(endpoint);

        string sessionRoot = cmd.Get("out")
                             ?? Path.Combine(Environment.CurrentDirectory, "sessions");

        if (!Privilege.IsElevated())
        {
            Console.Error.WriteLine(
                "warning: not elevated — kernel tracing will be skipped on this machine and only");
            Console.Error.WriteLine(
                "         snapshot-based evidence will be collected. The host is told either way.");
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Console.Error.WriteLine("\ndisconnecting…");
            cancellation.Cancel();
        };

        try
        {
            return Modes.FleetAgentRunner
                .RunAsync(host, port, code, sessionRoot, cancellation.Token)
                .GetAwaiter().GetResult();
        }
        catch (ChannelException ex)
        {
            Console.Error.WriteLine($"cayatrace: {ex.Message}");
            Console.Error.WriteLine("           A wrong pairing code and a wrong host look the same here.");
            return 4;
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or IOException)
        {
            Console.Error.WriteLine($"cayatrace: could not reach {host}:{port} — {ex.Message}");
            return 4;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
    }

    private static (string Host, int Port) SplitEndpoint(string value)
    {
        int colon = value.LastIndexOf(':');
        if (colon > 0 && int.TryParse(value[(colon + 1)..], out int port))
            return (value[..colon], port);

        return (value, 47921);
    }
}
