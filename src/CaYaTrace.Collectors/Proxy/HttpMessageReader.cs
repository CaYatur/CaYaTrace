using System.Globalization;
using System.Text;

namespace CaYaTrace.Collectors.Proxy;

public sealed record HttpRequestLine(string Method, string Target, string Version);

public sealed record HttpStatusLine(int Code, string Reason, string Version);

/// <summary>
/// Reads HTTP/1.1 messages off a stream, one piece at a time.
/// </summary>
/// <remarks>
/// <para>
/// Hand-written rather than delegating to <c>HttpClient</c> because a proxy needs the
/// message exactly as it arrived — original header order, original casing, the body as
/// bytes — and the framework's client normalizes all of that away while parsing.
/// </para>
/// <para>
/// Every read is bounded. A proxy accepts input from whatever is being analysed, and a
/// header line without a terminator or a chunked body that never ends would otherwise
/// be an easy way for a sample to exhaust the tool's memory.
/// </para>
/// </remarks>
public sealed class HttpMessageReader
{
    private const int MaxLineBytes = 16 * 1024;
    private const int MaxHeaderCount = 200;

    private readonly Stream _stream;
    private readonly byte[] _one = new byte[1];

    public HttpMessageReader(Stream stream) => _stream = stream;

    public async Task<HttpRequestLine?> ReadRequestLineAsync(CancellationToken cancellationToken)
    {
        string? line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line)) return null;

        string[] parts = line.Split(' ', 3);
        return parts.Length < 2 ? null : new HttpRequestLine(parts[0], parts[1], parts.Length > 2 ? parts[2] : "HTTP/1.1");
    }

    public async Task<HttpStatusLine?> ReadStatusLineAsync(CancellationToken cancellationToken)
    {
        string? line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line)) return null;

        string[] parts = line.Split(' ', 3);
        if (parts.Length < 2 || !int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int code))
            return null;

        return new HttpStatusLine(code, parts.Length > 2 ? parts[2] : string.Empty, parts[0]);
    }

    /// <summary>Reads headers until the blank line. Names are lowercased for lookup.</summary>
    public async Task<Dictionary<string, string>> ReadHeadersAsync(CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < MaxHeaderCount; i++)
        {
            string? line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line is null || line.Length == 0) break;

            int colon = line.IndexOf(':');
            if (colon <= 0) continue;

            string name = line[..colon].Trim().ToLowerInvariant();
            string value = line[(colon + 1)..].Trim();

            // Repeated headers are joined per RFC rather than the last winning, which
            // would silently drop all but one Set-Cookie.
            headers[name] = headers.TryGetValue(name, out string? existing) ? $"{existing}, {value}" : value;
        }

        return headers;
    }

    /// <summary>
    /// Reads the body, honouring Content-Length or chunked transfer.
    /// </summary>
    /// <param name="maxBytes">
    /// Cap. A body over the cap is drained but not retained, so the connection stays in
    /// sync while a multi-gigabyte download does not land in memory.
    /// </param>
    public async Task<byte[]> ReadBodyAsync(
        Dictionary<string, string> headers, int maxBytes, CancellationToken cancellationToken)
    {
        if (headers.TryGetValue("transfer-encoding", out string? encoding)
            && encoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            return await ReadChunkedAsync(maxBytes, cancellationToken).ConfigureAwait(false);
        }

        if (!headers.TryGetValue("content-length", out string? lengthHeader)
            || !long.TryParse(lengthHeader, NumberStyles.Integer, CultureInfo.InvariantCulture, out long length)
            || length <= 0)
        {
            return Array.Empty<byte>();
        }

        int retain = (int)Math.Min(length, maxBytes);
        byte[] buffer = new byte[retain];
        int read = 0;

        while (read < retain)
        {
            int chunk = await _stream.ReadAsync(buffer.AsMemory(read, retain - read), cancellationToken)
                .ConfigureAwait(false);
            if (chunk == 0) break;
            read += chunk;
        }

        // Drain the remainder so the next message starts at the right offset.
        long remaining = length - read;
        byte[] scratch = new byte[8192];
        while (remaining > 0)
        {
            int chunk = await _stream
                .ReadAsync(scratch.AsMemory(0, (int)Math.Min(scratch.Length, remaining)), cancellationToken)
                .ConfigureAwait(false);
            if (chunk == 0) break;
            remaining -= chunk;
        }

        return read == retain ? buffer : buffer[..read];
    }

    private async Task<byte[]> ReadChunkedAsync(int maxBytes, CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();

        while (true)
        {
            string? sizeLine = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (sizeLine is null) break;

            // A chunk header may carry extensions after a semicolon.
            string sizeToken = sizeLine.Split(';')[0].Trim();
            if (!int.TryParse(sizeToken, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int size) || size <= 0)
                break;

            byte[] chunk = new byte[size];
            int read = 0;
            while (read < size)
            {
                int got = await _stream.ReadAsync(chunk.AsMemory(read, size - read), cancellationToken)
                    .ConfigureAwait(false);
                if (got == 0) break;
                read += got;
            }

            if (body.Length < maxBytes)
                body.Write(chunk, 0, Math.Min(read, maxBytes - (int)body.Length));

            // Trailing CRLF after each chunk.
            await ReadLineAsync(cancellationToken).ConfigureAwait(false);
        }

        return body.ToArray();
    }

    /// <summary>
    /// Reads one CRLF-terminated line, byte by byte.
    /// </summary>
    /// <remarks>
    /// Unbuffered on purpose. A proxy must hand the stream to TLS or to a body reader
    /// at an exact offset, and a buffered reader that consumed ahead would swallow the
    /// first bytes of whatever comes next.
    /// </remarks>
    private async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        var line = new List<byte>(128);

        while (line.Count < MaxLineBytes)
        {
            int read = await _stream.ReadAsync(_one.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0) return line.Count == 0 ? null : Encoding.Latin1.GetString(line.ToArray());

            if (_one[0] == (byte)'\n')
            {
                if (line.Count > 0 && line[^1] == (byte)'\r') line.RemoveAt(line.Count - 1);
                return Encoding.Latin1.GetString(line.ToArray());
            }

            line.Add(_one[0]);
        }

        // Over the cap: malformed or hostile. Treated as end of message.
        return null;
    }
}
