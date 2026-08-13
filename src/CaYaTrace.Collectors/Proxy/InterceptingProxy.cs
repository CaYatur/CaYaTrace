using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Collectors.Proxy;

public sealed class ProxyOptions
{
    /// <summary>Loopback port to listen on. Zero picks a free one.</summary>
    public int Port { get; init; }

    /// <summary>
    /// Capture request and response bodies. The reason to run a proxy at all, and the
    /// reason a session becomes far more sensitive when one runs.
    /// </summary>
    public bool CaptureBodies { get; init; } = true;

    /// <summary>Largest body retained per message. Larger ones record their size only.</summary>
    public int MaxBodyBytes { get; init; } = 512 * 1024;

    /// <summary>
    /// Redact well-known credential-bearing headers. On by default: an analyst usually
    /// needs to know a request carried a token, not what the token was.
    /// </summary>
    public bool RedactCredentialHeaders { get; init; } = true;

    public static ProxyOptions Default { get; } = new();
}

/// <summary>
/// A local HTTP(S) proxy that records the traffic passing through it.
/// </summary>
/// <remarks>
/// <para>
/// This is the only layer that sees inside TLS, and the only one that changes the
/// machine's trust. Everything else in the network stack is passive.
/// </para>
/// <para>
/// <b>What it cannot do, deliberately.</b> Certificate pinning, ECH, and applications
/// carrying their own trust store are not defeated — that traffic stays opaque and is
/// recorded as having been unreadable rather than quietly dropped. Bypassing an
/// application's security controls is an evasion capability, not an analysis one, and
/// building it would make this tool something else.
/// </para>
/// <para>
/// Binds to loopback only. A proxy on a routable interface would let anything on the
/// network route traffic through the machine and have it decrypted and written to disk.
/// </para>
/// </remarks>
public sealed class InterceptingProxy : IAsyncDisposable
{
    private static readonly string[] SensitiveHeaders =
    {
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "x-api-key", "x-auth-token", "api-key",
    };

    private readonly ProxyOptions _options;
    private readonly SessionCertificateAuthority _authority;
    private readonly CollectorContext _ctx;
    private readonly CancellationTokenSource _shutdown = new();

    private TcpListener? _listener;
    private Task? _acceptLoop;
    private long _exchanges;
    private long _opaque;

    public InterceptingProxy(CollectorContext ctx, SessionCertificateAuthority authority, ProxyOptions? options = null)
    {
        _ctx = ctx;
        _authority = authority;
        _options = options ?? ProxyOptions.Default;
    }

    public int Port { get; private set; }

    public long Exchanges => Interlocked.Read(ref _exchanges);

    /// <summary>Connections that stayed encrypted, typically because of pinning.</summary>
    public long OpaqueConnections => Interlocked.Read(ref _opaque);

    /// <summary>Exchanges seen but not kept, because they were another program's.</summary>
    public long OtherProcessExchanges => Interlocked.Read(ref _otherProcesses);

    /// <summary>
    /// Exchanges kept although nothing on the machine could say whose they were.
    /// </summary>
    /// <remarks>
    /// Reported because these are the only ones in a scoped session that might not belong
    /// to the subject. A count of zero is the ordinary case and says the scoping was exact.
    /// </remarks>
    public long UnattributedExchanges => Interlocked.Read(ref _unattributed);

    public void Start()
    {
        _listener = new TcpListener(IPAddress.Loopback, _options.Port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;

        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_shutdown.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener!.AcceptTcpClientAsync(_shutdown.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            // Each connection is handled independently; one misbehaving client must not
            // stall the others.
            _ = Task.Run(async () =>
            {
                try { await HandleAsync(client).ConfigureAwait(false); }
                catch (Exception ex)
                {
                    // A client that hangs up early is ordinary. Anything else is the proxy
                    // failing, and swallowing it silently is how this feature came to be
                    // completely non-functional while reporting nothing at all: every
                    // HTTPS connection died here and the session showed zero exchanges,
                    // zero failures, and no explanation.
                    if (ex is not (IOException or ObjectDisposedException or OperationCanceledException))
                        NoteConnectionFault(ex);
                }
                finally { client.Dispose(); }
            });
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        // The client's ephemeral port is the only link back to the process that made
        // the request; the proxy itself sees nothing but a loopback socket.
        ushort clientPort = (ushort)((IPEndPoint)client.Client.RemoteEndPoint!).Port;
        Core.Correlation.FlowAttribution attribution =
            _ctx.Flows.AttributeProxyClient(clientPort, DateTimeOffset.UtcNow);

        // The flow table only knows ports it happened to observe. Windows knows all of
        // them, and the connection is established right now, so it has an answer — which
        // matters twice over: an unattributed exchange cannot be tied to a program, and
        // it cannot be excluded from a session recorded to watch one either.
        //
        // Asked unconditionally, and kept even when it names a process the session has
        // never heard of. That case is not a failure to attribute — it is Windows saying
        // the traffic belongs to somebody else, which is the single most useful thing it
        // can say when the proxy is machine-wide and the session is not.
        uint ownerPid = Network.LocalPortOwner.Resolve(clientPort);

        if (attribution.Owner == ProcessKey.None && ownerPid != 0)
        {
            ProcessKey owner = _ctx.Processes.Resolve(ownerPid, DateTimeOffset.UtcNow);
            if (owner != ProcessKey.None)
            {
                attribution = new Core.Correlation.FlowAttribution(
                    owner, AttributionConfidence.Probable, "local-port-table");
            }
        }

        var origin = new ClientOrigin(attribution, ownerPid);

        NetworkStream network = client.GetStream();
        var reader = new HttpMessageReader(network);

        HttpRequestLine? request = await reader.ReadRequestLineAsync(_shutdown.Token).ConfigureAwait(false);
        if (request is null) return;

        if (string.Equals(request.Method, "CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            await HandleConnectAsync(client, network, reader, request, origin).ConfigureAwait(false);
            return;
        }

        await HandlePlainAsync(network, reader, request, origin).ConfigureAwait(false);
    }

    /// <summary>
    /// Who the other end of a proxied connection is, as well as it can be established.
    /// </summary>
    /// <param name="Attribution">
    /// The process the session knows about, where one could be matched.
    /// </param>
    /// <param name="OwnerPid">
    /// What Windows says owns the client port, whether or not the session tracks it.
    /// Zero when Windows had no answer either.
    /// </param>
    /// <remarks>
    /// The two are carried separately on purpose. Collapsing them loses the difference
    /// between "nobody knows who sent this" and "Windows knows, and it was not the
    /// subject" — and that difference is the whole of the scoping decision.
    /// </remarks>
    private readonly record struct ClientOrigin(
        Core.Correlation.FlowAttribution Attribution, uint OwnerPid);

    /// <summary>Handles a plaintext HTTP request forwarded through the proxy.</summary>
    private async Task HandlePlainAsync(
        Stream clientStream, HttpMessageReader reader, HttpRequestLine request, ClientOrigin origin)
    {
        Dictionary<string, string> headers = await reader.ReadHeadersAsync(_shutdown.Token).ConfigureAwait(false);
        byte[] body = await reader.ReadBodyAsync(headers, _options.MaxBodyBytes, _shutdown.Token).ConfigureAwait(false);

        Uri? target = Uri.TryCreate(request.Target, UriKind.Absolute, out Uri? absolute)
            ? absolute
            : Uri.TryCreate($"http://{headers.GetValueOrDefault("host")}{request.Target}", UriKind.Absolute, out Uri? relative)
                ? relative
                : null;

        if (target is null) return;

        long requestSeq = Record(EventAction.HttpRequest, origin, request.Method, target.ToString(), headers, body, 0);

        using var upstream = new TcpClient();
        await upstream.ConnectAsync(target.Host, target.Port, _shutdown.Token).ConfigureAwait(false);

        await ForwardAsync(upstream.GetStream(), clientStream, request, headers, body, target, origin, requestSeq)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Handles CONNECT by terminating TLS with a minted certificate and opening a
    /// second TLS session to the real server.
    /// </summary>
    private async Task HandleConnectAsync(
        TcpClient client, NetworkStream network, HttpMessageReader reader, HttpRequestLine request,
        ClientOrigin origin)
    {
        await reader.ReadHeadersAsync(_shutdown.Token).ConfigureAwait(false);

        string host = request.Target.Split(':')[0];
        int port = request.Target.Contains(':') && int.TryParse(request.Target.Split(':')[1], out int p) ? p : 443;

        await network.WriteAsync(
            Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), _shutdown.Token)
            .ConfigureAwait(false);

        X509Certificate2 leaf = _authority.GetOrCreateLeaf(host);

        var clientTls = new SslStream(network, leaveInnerStreamOpen: false);
        try
        {
            await clientTls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leaf,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            }, _shutdown.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // The handshake did not happen, for any reason. Recorded rather than dropped:
            // "this connection could not be read" is itself a finding.
            //
            // Deliberately catching everything. This used to catch only
            // AuthenticationException and IOException, and the failure that actually
            // occurred — Schannel refusing an ephemeral server key, a Win32Exception —
            // fell straight through it. The connection died, the client reported a closed
            // socket, and the session reported zero exchanges *and* zero failures, which
            // is the worst possible combination: a feature that is off, reporting nothing
            // wrong.
            Interlocked.Increment(ref _opaque);
            RecordOpaque(host, port, origin.Attribution, $"{ex.GetType().Name}: {ex.Message}");
            clientTls.Dispose();
            return;
        }

        using (clientTls)
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(host, port, _shutdown.Token).ConfigureAwait(false);

            var serverTls = new SslStream(upstream.GetStream(), leaveInnerStreamOpen: false);
            await using (serverTls)
            {
                try
                {
                    await serverTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = host,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    }, _shutdown.Token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is AuthenticationException or IOException)
                {
                    // The upstream certificate did not validate. CaYaTrace does not
                    // suppress that check: an analysis tool that ignores a bad server
                    // certificate would hide exactly the finding worth having.
                    RecordOpaque(host, port, origin.Attribution, $"upstream TLS failed: {ex.GetType().Name}");
                    return;
                }

                RecordTlsMetadata(host, serverTls, origin.Attribution);

                var inner = new HttpMessageReader(clientTls);
                while (!_shutdown.IsCancellationRequested)
                {
                    HttpRequestLine? inner_request =
                        await inner.ReadRequestLineAsync(_shutdown.Token).ConfigureAwait(false);
                    if (inner_request is null) break;

                    Dictionary<string, string> headers =
                        await inner.ReadHeadersAsync(_shutdown.Token).ConfigureAwait(false);
                    byte[] body = await inner
                        .ReadBodyAsync(headers, _options.MaxBodyBytes, _shutdown.Token).ConfigureAwait(false);

                    string url = $"https://{host}{inner_request.Target}";
                    long seq = Record(EventAction.HttpRequest, origin, inner_request.Method, url, headers, body, 0);

                    bool keepAlive = await ForwardAsync(
                        serverTls, clientTls, inner_request, headers, body,
                        new Uri(url), origin, seq).ConfigureAwait(false);

                    if (!keepAlive) break;
                }
            }
        }
    }

    /// <summary>Replays a request upstream and streams the response back, recording it.</summary>
    private async Task<bool> ForwardAsync(
        Stream upstream, Stream downstream, HttpRequestLine request, Dictionary<string, string> headers,
        byte[] body, Uri target, ClientOrigin origin, long requestSeq)
    {
        var outbound = new StringBuilder();
        outbound.Append(request.Method).Append(' ')
                .Append(target.PathAndQuery).Append(' ')
                .Append("HTTP/1.1\r\n");

        foreach ((string name, string value) in headers)
        {
            // Connection reuse across a proxy hop is more trouble than it is worth for
            // a tool that must see message boundaries clearly.
            if (name is "proxy-connection" or "connection" or "accept-encoding") continue;
            outbound.Append(name).Append(": ").Append(value).Append("\r\n");
        }
        outbound.Append("Connection: close\r\n\r\n");

        await upstream.WriteAsync(Encoding.ASCII.GetBytes(outbound.ToString()), _shutdown.Token).ConfigureAwait(false);
        if (body.Length > 0) await upstream.WriteAsync(body, _shutdown.Token).ConfigureAwait(false);
        await upstream.FlushAsync(_shutdown.Token).ConfigureAwait(false);

        var responseReader = new HttpMessageReader(upstream);
        HttpStatusLine? status = await responseReader.ReadStatusLineAsync(_shutdown.Token).ConfigureAwait(false);
        if (status is null) return false;

        Dictionary<string, string> responseHeaders =
            await responseReader.ReadHeadersAsync(_shutdown.Token).ConfigureAwait(false);
        byte[] responseBody = await responseReader
            .ReadBodyAsync(responseHeaders, _options.MaxBodyBytes, _shutdown.Token).ConfigureAwait(false);

        Record(EventAction.HttpResponse, origin, status.Code.ToString(), target.ToString(),
            responseHeaders, responseBody, requestSeq);

        var back = new StringBuilder();
        back.Append("HTTP/1.1 ").Append(status.Code).Append(' ').Append(status.Reason).Append("\r\n");
        foreach ((string name, string value) in responseHeaders)
        {
            if (name is "transfer-encoding" or "connection" or "content-length") continue;
            back.Append(name).Append(": ").Append(value).Append("\r\n");
        }
        back.Append("Content-Length: ").Append(responseBody.Length).Append("\r\n");
        back.Append("Connection: close\r\n\r\n");

        await downstream.WriteAsync(Encoding.ASCII.GetBytes(back.ToString()), _shutdown.Token).ConfigureAwait(false);
        if (responseBody.Length > 0)
            await downstream.WriteAsync(responseBody, _shutdown.Token).ConfigureAwait(false);
        await downstream.FlushAsync(_shutdown.Token).ConfigureAwait(false);

        return false;
    }

    private long Record(
        EventAction action, ClientOrigin origin, string verbOrStatus,
        string url, Dictionary<string, string> headers, byte[] body, long causedBy)
    {
        // Traffic belonging to somebody else is not recorded when there is a subject.
        //
        // The system proxy is machine-wide by construction, so with interception on, every
        // program's requests arrive here — measured, and the first real test of this
        // feature captured the operator's own browser and editor traffic, bodies included,
        // into a file on their disk. A session recorded to watch one program should
        // contain one program.
        //
        // Counted rather than silently dropped, so the report can say the proxy saw more
        // than it kept.
        if (!IsSubjects(origin))
        {
            Interlocked.Increment(ref _otherProcesses);
            return 0;
        }

        Interlocked.Increment(ref _exchanges);

        string? bodyReference = null;
        if (_options.CaptureBodies && body.Length > 0)
        {
            string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(body)).ToLowerInvariant();
            try
            {
                _ctx.Store.WriteBlob(digest, body, headers.GetValueOrDefault("content-type"));
                bodyReference = digest;
            }
            catch (Exception) { /* a body that cannot be stored must not fail the exchange */ }
        }

        long seq = _ctx.Store.NextSequence();

        _ctx.Emit(new Observation
        {
            Seq = seq,
            Timestamp = DateTimeOffset.UtcNow,
            Category = EventCategory.Http,
            Action = action,
            Actor = origin.Attribution.Owner,
            Confidence = origin.Attribution.Confidence,
            Target = url,
            Target2 = verbOrStatus,
            Bytes = body.Length,
            CausedBySeq = causedBy,
            Source = EvidenceSource.Proxy,
            Status = EventStatus.Success,
            Details = DescribeHeaders(headers, bodyReference, body.Length),
        });

        return seq;
    }

    /// <summary>
    /// Reports a connection the proxy could not handle, once per distinct reason.
    /// </summary>
    /// <remarks>
    /// Once per reason rather than per connection: a proxy that is broken is broken for
    /// every connection, and a hundred identical lines in the data-quality log would bury
    /// the one that explains it.
    /// </remarks>
    /// <summary>
    /// True when this exchange belongs to the program under investigation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A system-wide recording has no subject, so everything is the subject and nothing is
    /// filtered. A recording of one program keeps that program's traffic and the traffic of
    /// anything it started.
    /// </para>
    /// <para>
    /// The hard case is an exchange with no matched process, and this used to keep it. That
    /// was wrong, and running the shipping build proved it: a session recording one
    /// PowerShell script came back holding the operator's desktop-app telemetry — complete
    /// with an API key in the query string — and the operating system's own connectivity
    /// checks. Both were unattributed, so both were kept. Writing a third party's
    /// credentials into someone's evidence file is a worse failure than any it prevented.
    /// </para>
    /// <para>
    /// So the question is asked of Windows instead, and there are two different answers
    /// hiding behind "unattributed":
    /// </para>
    /// <list type="bullet">
    ///   <item><description>
    ///     <b>Windows names a process the session does not track.</b> Not a failure to
    ///     attribute — the session tracks the subject and everything it started, so a
    ///     process outside that set is somebody else's, and the exchange is excluded.
    ///   </description></item>
    ///   <item><description>
    ///     <b>Windows has no answer either.</b> A connection that closed inside the lookup
    ///     window. Kept, because losing the subject's own traffic to a timing race is the
    ///     failure that has no remedy — and it is counted, so the report can say so.
    ///   </description></item>
    /// </list>
    /// </remarks>
    private bool IsSubjects(ClientOrigin origin)
    {
        if (_ctx.Session.RootProcess == ProcessKey.None) return true;

        if (origin.Attribution.Owner != ProcessKey.None)
        {
            ProcessNode? node = _ctx.Processes.Get(origin.Attribution.Owner);
            return node is null || node.InScope;
        }

        // Nobody owns it as far as Windows is concerned. Rare, and kept.
        if (origin.OwnerPid == 0)
        {
            Interlocked.Increment(ref _unattributed);
            return true;
        }

        // Windows named somebody, and the session has never seen them. That includes the
        // proxy's own upstream connections, which is as it should be: a tool has no
        // business recording itself into the evidence it is collecting.
        return false;
    }

    private long _otherProcesses;

    /// <summary>Exchanges kept although nothing could say whose they were.</summary>
    private long _unattributed;

    private void NoteConnectionFault(Exception ex)
    {
        // Keyed on the exception type, not the message: messages carry timestamps and
        // hostnames, so keying on them turns "one thing is broken" into one line per
        // connection — which is what buries the explanation it was written to surface.
        if (!_faults.TryAdd(ex.GetType().Name, 0)) { _faults[ex.GetType().Name]++; return; }

        _ctx.Store.LogQuality("https-proxy", "warning",
            $"a connection could not be handled — {ex.GetType().Name}: {ex.Message}. "
            + "Traffic on those connections was not recorded.");
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _faults = new();

    private void RecordOpaque(string host, int port, Core.Correlation.FlowAttribution attribution, string reason)
    {
        _ctx.Emit(new Observation
        {
            Timestamp = DateTimeOffset.UtcNow,
            Category = EventCategory.Tls,
            Action = EventAction.TlsAlert,
            Actor = attribution.Owner,
            Confidence = attribution.Confidence,
            Target = $"{host}:{port}",
            Target2 = "not decryptable",
            NewValue = reason,
            Source = EvidenceSource.Proxy,
            Status = EventStatus.Failed,
            Details = "the client rejected the session certificate, so this connection stayed encrypted. "
                    + "Certificate pinning or a private trust store. CaYaTrace does not attempt to bypass either.",
        });
    }

    private void RecordTlsMetadata(string host, SslStream tls, Core.Correlation.FlowAttribution attribution)
    {
        _ctx.Emit(new Observation
        {
            Timestamp = DateTimeOffset.UtcNow,
            Category = EventCategory.Tls,
            Action = EventAction.TlsHandshakeComplete,
            Actor = attribution.Owner,
            Confidence = attribution.Confidence,
            Target = host,
            Target2 = tls.SslProtocol.ToString(),
            NewValue = tls.NegotiatedCipherSuite.ToString(),
            Source = EvidenceSource.Proxy,
            Status = EventStatus.Success,
            Details = tls.RemoteCertificate is { } certificate
                ? $"{{\"subject\":{System.Text.Json.JsonSerializer.Serialize(certificate.Subject)}," +
                  $"\"issuer\":{System.Text.Json.JsonSerializer.Serialize(certificate.Issuer)}}}"
                : null,
        });
    }

    private string DescribeHeaders(Dictionary<string, string> headers, string? bodyReference, int bodyLength)
    {
        var sb = new StringBuilder("{");

        foreach ((string name, string value) in headers)
        {
            string shown = _options.RedactCredentialHeaders
                           && SensitiveHeaders.Contains(name, StringComparer.OrdinalIgnoreCase)
                ? $"[redacted, {value.Length} characters]"
                : value;

            if (sb.Length > 1) sb.Append(',');
            sb.Append(System.Text.Json.JsonSerializer.Serialize(name))
              .Append(':')
              .Append(System.Text.Json.JsonSerializer.Serialize(shown));
        }

        if (bodyReference is not null)
            sb.Append(",\"body_sha256\":").Append(System.Text.Json.JsonSerializer.Serialize(bodyReference));
        sb.Append(",\"body_bytes\":").Append(bodyLength);

        return sb.Append('}').ToString();
    }

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        try { _listener?.Stop(); } catch (SocketException) { }
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
        _shutdown.Dispose();
    }
}
