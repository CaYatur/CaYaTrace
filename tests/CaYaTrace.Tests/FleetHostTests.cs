using System.Net.Sockets;
using CaYaTrace.Core.Model;
using CaYaTrace.Fleet;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// The host side of multi-machine collection.
/// </summary>
/// <remarks>
/// The property worth testing here is not that bytes move — <see cref="SecureChannelTests"/>
/// covers that — but that <b>nothing happens before a person says so</b>. An agent that knows
/// the pairing code has proved one thing and been granted nothing.
/// </remarks>
public sealed class FleetHostTests : IDisposable
{
    private readonly FleetHost _host = new();

    public void Dispose() => _host.Dispose();

    private static async Task<(TcpClient Client, SecureChannel Channel)> ConnectAsync(int port, string code)
    {
        var client = new TcpClient();
        await client.ConnectAsync(System.Net.IPAddress.Loopback, port);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        SecureChannel channel = await SecureChannel.ConnectAsync(client.GetStream(), code, timeout.Token);
        return (client, channel);
    }

    private static AgentHello Hello() => new()
    {
        MachineName = "VM-01",
        OsBuild = "26100",
        Architecture = "x64",
        IsVirtualMachine = true,
        Hypervisor = "Hyper-V",
        ToolVersion = "0.1.0",
        IsElevated = true,
    };

    private static async Task WaitFor(Func<bool> condition, string what)
    {
        for (int i = 0; i < 200; i++)
        {
            if (condition()) return;
            await Task.Delay(50);
        }
        Assert.Fail($"timed out waiting for {what}");
    }

    [Fact]
    public async Task AnAgentIsListedButNotApprovedUntilTheOperatorSaysSo()
    {
        _host.Start(0);
        (TcpClient client, SecureChannel channel) = await ConnectAsync(_host.Port, _host.Code);

        using (client)
        using (channel)
        {
            await FleetTransport.SendAsync(channel,
                FleetMessage.Create(FleetMessageType.Hello, null, Hello()), CancellationToken.None);

            await WaitFor(() => _host.Agents.Count == 1, "the agent to be listed");

            FleetAgentConnection agent = _host.Agents[0];
            Assert.Equal(AgentState.Pending, agent.State);
            Assert.Equal("VM-01", agent.Hello?.MachineName);

            // The decision has not been made, so the agent has been told nothing.
            Assert.Equal(0, agent.EventsReceived);
        }
    }

    [Fact]
    public async Task ApprovalIsWhatUnblocksTheAgent()
    {
        _host.Start(0);
        (TcpClient client, SecureChannel channel) = await ConnectAsync(_host.Port, _host.Code);

        using (client)
        using (channel)
        {
            await FleetTransport.SendAsync(channel,
                FleetMessage.Create(FleetMessageType.Hello, null, Hello()), CancellationToken.None);

            await WaitFor(() => _host.Agents.Count == 1, "the agent to be listed");
            _host.Decide(_host.Agents[0].Id, approve: true);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            FleetMessage? decision = await FleetTransport.ReceiveAsync(channel, timeout.Token);

            Assert.NotNull(decision);
            Assert.Equal(FleetMessageType.Approved, decision!.Type);
        }
    }

    [Fact]
    public async Task RejectionIsToldToTheAgentRatherThanLeftHanging()
    {
        _host.Start(0);
        (TcpClient client, SecureChannel channel) = await ConnectAsync(_host.Port, _host.Code);

        using (client)
        using (channel)
        {
            await FleetTransport.SendAsync(channel,
                FleetMessage.Create(FleetMessageType.Hello, null, Hello()), CancellationToken.None);

            await WaitFor(() => _host.Agents.Count == 1, "the agent to be listed");
            _host.Decide(_host.Agents[0].Id, approve: false);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            FleetMessage? decision = await FleetTransport.ReceiveAsync(channel, timeout.Token);

            Assert.NotNull(decision);
            Assert.Equal(FleetMessageType.Rejected, decision!.Type);
        }
    }

    [Fact]
    public async Task TheWrongPairingCodeNeverBecomesAnAgent()
    {
        _host.Start(0);

        // The handshake fails on both sides; what matters is that the host does not end
        // up with a connection in its list that an operator could then approve.
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            (TcpClient client, SecureChannel channel) = await ConnectAsync(_host.Port, "ZZZZ-ZZZZ-ZZZZ");
            client.Dispose();
            channel.Dispose();
        });

        await Task.Delay(300);
        Assert.Empty(_host.Agents);
    }

    [Fact]
    public async Task ObservationBatchesReachTheHost()
    {
        _host.Start(0);

        var received = new List<ObservationBatch>();
        _host.BatchReceived += (_, batch) => { lock (received) received.Add(batch); };

        (TcpClient client, SecureChannel channel) = await ConnectAsync(_host.Port, _host.Code);

        using (client)
        using (channel)
        {
            await FleetTransport.SendAsync(channel,
                FleetMessage.Create(FleetMessageType.Hello, null, Hello()), CancellationToken.None);

            await WaitFor(() => _host.Agents.Count == 1, "the agent to be listed");
            string id = _host.Agents[0].Id;
            _host.Decide(id, approve: true);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await FleetTransport.ReceiveAsync(channel, timeout.Token);

            await FleetTransport.SendAsync(channel, FleetMessage.Create(
                FleetMessageType.Observations, id, new ObservationBatch
                {
                    OriginId = id,
                    IsFinal = true,
                    Observations = new List<Observation>
                    {
                        new() { Seq = 1, Category = EventCategory.File, Action = EventAction.FileCreate, Target = @"C:\x\y.exe" },
                        new() { Seq = 2, Category = EventCategory.Registry, Action = EventAction.ValueSet, Target = @"HKCU\Software\X" },
                    },
                }), CancellationToken.None);

            await WaitFor(() => { lock (received) return received.Count == 1; }, "the batch to arrive");

            ObservationBatch batch = received[0];
            Assert.Equal(2, batch.Observations.Count);
            Assert.True(batch.IsFinal);
            Assert.Equal(@"C:\x\y.exe", batch.Observations[0].Target);

            // Enum members survive the round trip as names, not ordinals.
            Assert.Equal(EventAction.ValueSet, batch.Observations[1].Action);
        }
    }

    [Fact]
    public void ANewCodeReplacesTheOldOne()
    {
        string first = _host.Code;
        _host.NewPairingCode();

        Assert.NotEqual(first, _host.Code);
        Assert.True(PairingCode.LooksValid(_host.Code));
    }
}
