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
                catch (Exception) { /* a broken connection is ordinary, not a fault */ }
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

        NetworkStream network = client.GetStream();
        var reader = new HttpMessageReader(network);

        HttpRequestLine? request = await reader.ReadRequestLineAsync(_shutdown.Token).ConfigureAwait(false);
        if (request is null) return;

        if (string.Equals(request.Method, "CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            await HandleConnectAsync(client, network, reader, request, attribution).ConfigureAwait(false);
            return;
        }

        await HandlePlainAsync(network, reader, request, attribution).ConfigureAwait(false);
    }

    /// <summary>Handles a plaintext HTTP request forwarded through the proxy.</summary>
    private async Task HandlePlainAsync(
        Stream clientStream, HttpMessageReader reader, HttpRequestLine request,
        Core.Correlation.FlowAttribution attribution)
    {
        Dictionary<string, string> headers = await reader.ReadHeadersAsync(_shutdown.Token).ConfigureAwait(false);
        byte[] body = await reader.ReadBodyAsync(headers, _options.MaxBodyBytes, _shutdown.Token).ConfigureAwait(false);

        Uri? target = Uri.TryCreate(request.Target, UriKind.Absolute, out Uri? absolute)
            ? absolute
            : Uri.TryCreate($"http://{headers.GetValueOrDefault("host")}{request.Target}", UriKind.Absolute, out Uri? relative)
                ? relative
                : null;

        if (target is null) return;

        long requestSeq = Record(EventAction.HttpRequest, attribution, request.Method, target.ToString(), headers, body, 0);

        using var upstream = new TcpClient();
        await upstream.ConnectAsync(target.Host, target.Port, _shutdown.Token).ConfigureAwait(false);

        await ForwardAsync(upstream.GetStream(), clientStream, request, headers, body, target, attribution, requestSeq)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Handles CONNECT by terminating TLS with a minted certificate and opening a
    /// second TLS session to the real server.
    /// </summary>
    private async Task HandleConnectAsync(
        TcpClient client, NetworkStream network, HttpMessageReader reader, HttpRequestLine request,
        Core.Correlation.FlowAttribution attribution)
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
        catch (Exception ex) when (ex is AuthenticationException or IOException)
        {
            // The client refused our certificate. Pinning, a private trust store, or a
            // client that simply does not trust machine roots. Recorded rather than
            // dropped: "this connection could not be read" is itself a finding.
            Interlocked.Increment(ref _opaque);
            RecordOpaque(host, port, attribution, ex.GetType().Name);
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
                    RecordOpaque(host, port, attribution, $"upstream TLS failed: {ex.GetType().Name}");
                    return;
                }

                RecordTlsMetadata(host, serverTls, attribution);

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
                    long seq = Record(EventAction.HttpRequest, attribution, inner_request.Method, url, headers, body, 0);

                    bool keepAlive = await ForwardAsync(
                        serverTls, clientTls, inner_request, headers, body,
                        new Uri(url), attribution, seq).ConfigureAwait(false);

                    if (!keepAlive) break;
                }
            }
        }
    }

    /// <summary>Replays a request upstream and streams the response back, recording it.</summary>
    private async Task<bool> ForwardAsync(
        Stream upstream, Stream downstream, HttpRequestLine request, Dictionary<string, string> headers,
        byte[] body, Uri target, Core.Correlation.FlowAttribution attribution, long requestSeq)
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

        Record(EventAction.HttpResponse, attribution, status.Code.ToString(), target.ToString(),
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
        EventAction action, Core.Correlation.FlowAttribution attribution, string verbOrStatus,
        string url, Dictionary<string, string> headers, byte[] body, long causedBy)
    {
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
            Actor = attribution.Owner,
            Confidence = attribution.Confidence,
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
