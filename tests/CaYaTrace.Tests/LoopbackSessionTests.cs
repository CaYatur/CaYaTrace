using System.Net;
using System.Net.Sockets;
using System.Text;
using CaYaTrace.Collectors;
using CaYaTrace.Collectors.Network;
using CaYaTrace.Core.Model;
using CaYaTrace.Export;
using CaYaTrace.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace CaYaTrace.Tests;

/// <summary>
/// A whole recording session with the loopback capture switched on.
/// </summary>
/// <remarks>
/// <para>
/// The capture is proven on its own elsewhere. What this checks is what happens when it
/// runs alongside everything else: the socket provider already reports loopback
/// connections with byte counts, so two sources now describe the same conversation and the
/// session must not end up saying it happened twice.
/// </para>
/// <para>
/// Needs administrator rights, because the kernel and socket providers do. It reports and
/// returns rather than failing when it does not have them — a test that cannot run is not
/// the same as a test that failed, and pretending otherwise means the suite goes red on
/// every machine that is not this one.
/// </para>
/// </remarks>
public sealed class LoopbackSessionTests : IDisposable
{
    private readonly ITestOutputHelper _out;

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "cayatrace-lbs-" + Guid.NewGuid().ToString("n")[..8]);

    public LoopbackSessionTests(ITestOutputHelper output)
    {
        _out = output;
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static bool Elevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    /// <summary>
    /// One local conversation appears once, with its contents, attributed to something.
    /// </summary>
    /// <remarks>
    /// Three separate claims, and the middle one is the reason this test exists. The
    /// socket provider reports the connection and its sizes; the capture reports the same
    /// connection and its bytes. If both emit a connection record the operator sees the
    /// same local exchange twice and has no way to tell which row is the real one.
    /// </remarks>
    [Fact]
    public async Task ALocalConversationIsRecordedOnceWithItsContents()
    {
        if (!Elevated())
        {
            _out.WriteLine("needs administrator rights; not run");
            return;
        }

        if (!LoopbackCapture.IsAvailable(out string why))
        {
            _out.WriteLine($"no loopback capture on this machine: {why}");
            return;
        }

        string marker = "CAYATRACE-SESSION-" + Guid.NewGuid().ToString("n")[..12];
        int port;

        var options = new SessionOptions
        {
            Mode = SessionMode.SystemWide,
            SessionRoot = _root,
            Name = "loopback-session-test",
            CaptureLoopback = true,
            CaptureSnapshots = false,
            CollectLocalSockets = true,
            CapturePackets = false,
        };

        await using var orchestrator = new SessionOrchestrator(options, NullLogger.Instance);

        SessionInfo started = await orchestrator.StartAsync();
        _out.WriteLine($"collectors: {string.Join(", ", started.EnabledCollectors)}");

        // Give the providers a moment to be listening before anything is said.
        await Task.Delay(1200);

        port = Speak(marker);

        await Task.Delay(2000);
        SessionInfo stopped = await orchestrator.StopAsync();

        string database = Path.Combine(
            Path.Combine(_root, "session_" + stopped.SessionId), "session.ctdb");

        if (!File.Exists(database))
        {
            string? found = Directory.GetFiles(_root, "session.ctdb", SearchOption.AllDirectories).FirstOrDefault();
            Assert.NotNull(found);
            database = found!;
        }

        using SessionStore store = SessionStore.Open(database);

        foreach ((DateTimeOffset _, string collector, string severity, string message) in store.ReadQualityLog())
            _out.WriteLine($"[{collector}/{severity}] {message}");

        // Every source's record is kept — provenance is the point of an evidence file —
        // so the raw stream holds all of them.
        List<Observation> raw = store
            .Query(new ObservationQuery { Categories = new List<EventCategory> { EventCategory.Network } })
            .Where(o => o.Action is EventAction.Connect or EventAction.Accept)
            .Where(o => o.Target.Contains($":{port}", StringComparison.Ordinal))
            .ToList();

        foreach (Observation o in raw)
            _out.WriteLine($"stored: {o.Action,-8} {o.Source,-14} {o.Target}  bytes={o.Bytes}");

        Assert.NotEmpty(raw);

        // What the operator reads is the projection, and there it is one conversation.
        var request = new ExportRequest { Scope = ExportScope.Full };
        string projected = SessionProjection.Build(store, stopped, request);

        using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(projected);
        System.Text.Json.JsonElement conversations = document.RootElement
            .GetProperty("network").GetProperty("conversations");

        var mine = new List<System.Text.Json.JsonElement>();
        foreach (System.Text.Json.JsonElement row in conversations.EnumerateArray())
        {
            string peer = row.GetProperty("peer").GetString() ?? string.Empty;
            long localPort = row.TryGetProperty("localPort", out System.Text.Json.JsonElement lp)
                ? lp.GetInt64()
                : 0;

            if (peer.Contains($":{port}", StringComparison.Ordinal) || localPort == port)
            {
                _out.WriteLine($"shown: {peer}  local={localPort}  via={row.GetProperty("via")}  "
                               + $"sent={row.GetProperty("sentBytes")} recv={row.GetProperty("receivedBytes")}");
                mine.Add(row);
            }
        }

        // One exchange, one row.
        Assert.Single(mine);

        // And it is the row that carries what was said, not the one that could not.
        System.Text.Json.JsonElement shown = mine[0];
        string? sentHash = shown.TryGetProperty("sentBody", out System.Text.Json.JsonElement body)
            ? body.GetString()
            : null;

        Assert.NotNull(sentHash);

        byte[]? bytes = store.ReadBlob(sentHash!);
        Assert.NotNull(bytes);
        Assert.Contains(marker, Encoding.ASCII.GetString(bytes!), StringComparison.Ordinal);
    }

    /// <summary>Says the marker over loopback and returns the port it used.</summary>
    private static int Speak(string marker)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task server = Task.Run(() =>
        {
            using TcpClient accepted = listener.AcceptTcpClient();
            using NetworkStream stream = accepted.GetStream();
            var buffer = new byte[4096];
            stream.Read(buffer, 0, buffer.Length);
            byte[] reply = Encoding.ASCII.GetBytes("ACK\n");
            stream.Write(reply, 0, reply.Length);
            stream.Flush();
        });

        using (var client = new TcpClient())
        {
            client.Connect(IPAddress.Loopback, port);
            using NetworkStream stream = client.GetStream();
            byte[] payload = Encoding.ASCII.GetBytes(marker + "\n");
            stream.Write(payload, 0, payload.Length);
            stream.Flush();
            var buffer = new byte[4096];
            stream.Read(buffer, 0, buffer.Length);
        }

        server.Wait(TimeSpan.FromSeconds(10));
        listener.Stop();

        return port;
    }
}
