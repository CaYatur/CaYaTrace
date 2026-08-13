using System.Net;
using System.Net.Sockets;
using CaYaTrace.Collectors.Network;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Asking Windows which process owns a local TCP port.
/// </summary>
/// <remarks>
/// This is the only thing standing between a machine-wide interception proxy and a session
/// full of other people's traffic, so it is tested against real sockets rather than a
/// stub. It failing silently — returning "nobody owns this" for every port — is
/// indistinguishable from it working, right up until the session contains somebody's API
/// keys.
/// </remarks>
public sealed class LocalPortOwnerTests
{
    [Fact]
    public void APortThisProcessHasOpenResolvesToThisProcess()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        try
        {
            var port = (ushort)((IPEndPoint)listener.LocalEndpoint).Port;

            uint owner = LocalPortOwner.Resolve(port);

            Assert.Equal((uint)Environment.ProcessId, owner);
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// The case the proxy actually asks about: a connection opened a moment ago.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The proxy resolves the client's ephemeral port the instant it accepts, so the
    /// lookup is always racing a connection that is seconds old at most. A cache that
    /// refuses to refresh loses exactly these, and every one it loses is an exchange that
    /// cannot be attributed — kept, in a session meant to hold one program.
    /// </para>
    /// <para>
    /// Several in a row, because the failure was not in the first lookup. It was in the
    /// second and third: a throttle meant to stop a genuinely ownerless port re-reading
    /// the table on every call also stopped every other miss in the same second from
    /// reading it even once.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task EveryFreshConnectionResolves()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        var clients = new List<TcpClient>();
        try
        {
            var resolved = new List<(ushort Port, uint Owner)>();

            // Back to back, deliberately: they all land inside one cache window.
            for (int i = 0; i < 6; i++)
            {
                var client = new TcpClient();
                clients.Add(client);
                await client.ConnectAsync(IPAddress.Loopback, serverPort);

                TcpClient accepted = await listener.AcceptTcpClientAsync();
                clients.Add(accepted);

                var clientPort = (ushort)((IPEndPoint)client.Client.LocalEndPoint!).Port;
                resolved.Add((clientPort, LocalPortOwner.Resolve(clientPort)));
            }

            List<(ushort Port, uint Owner)> missed = resolved.Where(r => r.Owner == 0).ToList();

            Assert.True(missed.Count == 0,
                $"{missed.Count} of {resolved.Count} live connections resolved to no owner "
                + $"(ports {string.Join(", ", missed.Select(m => m.Port))})");

            Assert.All(resolved, r => Assert.Equal((uint)Environment.ProcessId, r.Owner));
        }
        finally
        {
            foreach (TcpClient c in clients) c.Dispose();
            listener.Stop();
        }
    }

    [Fact]
    public void PortZeroIsNeverOwned()
    {
        Assert.Equal(0u, LocalPortOwner.Resolve(0));
    }
}
