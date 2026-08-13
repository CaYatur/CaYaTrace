using System.Net;
using CaYaTrace.Collectors.Network;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// Runs the conversation recorder over a real capture and prints what it recovered.
/// </summary>
/// <remarks>
/// Set <c>CAYATRACE_LIVE_PCAP</c> to a pcapng from a session. Reassembly and handshake
/// parsing can each look right in isolation while the thing an operator reads is still a
/// bare IP address and a byte count, and the only way to see that is to run it over a
/// capture somebody actually took.
/// </remarks>
public sealed class CaptureReplayTests
{
    private readonly ITestOutputHelper _out;

    public CaptureReplayTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public void ARealCaptureIsReadBack()
    {
        string? path = Environment.GetEnvironmentVariable("CAYATRACE_LIVE_PCAP");
        if (path is null || !File.Exists(path))
        {
            _out.WriteLine("set CAYATRACE_LIVE_PCAP to a capture.pcapng to run this");
            return;
        }

        var local = new List<IPAddress> { IPAddress.Parse("10.0.2.15"), IPAddress.Loopback };

        IReadOnlyList<Conversation> conversations = ConversationRecorder.Read(path, local);

        var log = new System.Text.StringBuilder();
        void Say(string line) { _out.WriteLine(line); log.AppendLine(line); }

        Say($"conversations: {conversations.Count}");
        Say($"with a server name: {conversations.Count(static c => c.ServerName is { Length: > 0 })}");
        Say($"with any content:   {conversations.Count(static c => c.Outbound.Length + c.Inbound.Length > 0)}");
        Say(string.Empty);

        foreach (Conversation c in conversations
                     .OrderByDescending(static c => c.BytesOut + c.BytesIn)
                     .Take(20))
        {
            Say($"{c.Key.LocalAddress}:{c.Key.LocalPort} -> {c.Key.RemoteAddress}:{c.Key.RemotePort}");
            Say($"    {c.Protocol}  out={c.BytesOut:N0} in={c.BytesIn:N0}  "
                + $"kept out={c.Outbound.Length:N0} in={c.Inbound.Length:N0}  "
                + $"name={c.ServerName ?? "(none)"}  inboundConnection={c.Inbound_Connection}");

            if (c.Outbound.Length > 0)
                Say($"    first outbound bytes: {Convert.ToHexString(c.Outbound[..Math.Min(24, c.Outbound.Length)])}");
        }

        if (Environment.GetEnvironmentVariable("CAYATRACE_LIVE_OUT") is { Length: > 0 } outPath)
            File.WriteAllText(outPath, log.ToString());

        Assert.NotEmpty(conversations);
    }
}
