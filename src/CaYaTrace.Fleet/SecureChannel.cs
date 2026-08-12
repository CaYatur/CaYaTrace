using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace CaYaTrace.Fleet;

public sealed class ChannelException : Exception
{
    public ChannelException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// An authenticated, encrypted frame channel between a host and a fleet agent.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why not TLS.</b> A lab network usually has no usable PKI, and the machines at the
/// far end are disposable VMs. Getting TLS working there means either self-signed
/// certificates with verification switched off — which is not security, only the
/// appearance of it — or installing a trust anchor on every VM, which is the exact
/// system change this tool otherwise goes to lengths to avoid. An application-layer
/// channel authenticated by a pairing code needs neither.
/// </para>
/// <para>
/// <b>Construction.</b> Ephemeral ECDH on P-256 for forward secrecy, HKDF-SHA256 to
/// derive directional keys, and ChaCha20-Poly1305 for the frames. The pairing code is
/// mixed into the key derivation, so a party that does not know it derives different
/// keys and the transcript check fails — that is what stops anything on the network
/// from standing in the middle. P-256 rather than X25519 because X25519 is not reliably
/// reachable through Windows CNG on .NET 8; the security argument is unaffected.
/// </para>
/// <para>
/// <b>Nonces.</b> Each direction has its own key and its own counter, and the channel
/// fails closed rather than wrapping. Reusing a nonce under one key would leak the
/// keystream, which is the failure worth engineering against.
/// </para>
/// </remarks>
public sealed class SecureChannel : IDisposable
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int MaxFrameBytes = 16 * 1024 * 1024;

    private static readonly byte[] Protocol = Encoding.ASCII.GetBytes("CaYaTrace/fleet/v1");

    private readonly Stream _stream;
    private readonly IAeadCipher _send;
    private readonly IAeadCipher _receive;

    private ulong _sendCounter;
    private ulong _receiveCounter;

    private SecureChannel(Stream stream, byte[] sendKey, byte[] receiveKey)
    {
        _stream = stream;
        _send = CreateCipher(sendKey);
        _receive = CreateCipher(receiveKey);
    }

    /// <summary>Fingerprint of the negotiated session, for display on both ends.</summary>
    public string SessionFingerprint { get; private init; } = string.Empty;

    // ------------------------------------------------------------- handshake

    /// <summary>Performs the host side of the handshake.</summary>
    public static Task<SecureChannel> AcceptAsync(Stream stream, string pairingCode, CancellationToken cancellationToken)
        => HandshakeAsync(stream, pairingCode, initiator: false, cancellationToken);

    /// <summary>Performs the agent side of the handshake.</summary>
    public static Task<SecureChannel> ConnectAsync(Stream stream, string pairingCode, CancellationToken cancellationToken)
        => HandshakeAsync(stream, pairingCode, initiator: true, cancellationToken);

    private static async Task<SecureChannel> HandshakeAsync(
        Stream stream, string pairingCode, bool initiator, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(pairingCode))
            throw new ChannelException("a pairing code is required; an unauthenticated channel is not offered");

        using ECDiffieHellman ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] localPublic = ephemeral.PublicKey.ExportSubjectPublicKeyInfo();
        byte[] localNonce = RandomNumberGenerator.GetBytes(32);

        byte[] remotePublic, remoteNonce;

        // Ordered so both sides read and write in a fixed sequence; a symmetric
        // exchange would deadlock on a stream without buffering.
        if (initiator)
        {
            await WriteBlockAsync(stream, localPublic, cancellationToken).ConfigureAwait(false);
            await WriteBlockAsync(stream, localNonce, cancellationToken).ConfigureAwait(false);
            remotePublic = await ReadBlockAsync(stream, cancellationToken).ConfigureAwait(false);
            remoteNonce = await ReadBlockAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            remotePublic = await ReadBlockAsync(stream, cancellationToken).ConfigureAwait(false);
            remoteNonce = await ReadBlockAsync(stream, cancellationToken).ConfigureAwait(false);
            await WriteBlockAsync(stream, localPublic, cancellationToken).ConfigureAwait(false);
            await WriteBlockAsync(stream, localNonce, cancellationToken).ConfigureAwait(false);
        }

        byte[] shared;
        try
        {
            using ECDiffieHellman peer = ECDiffieHellman.Create();
            peer.ImportSubjectPublicKeyInfo(remotePublic, out _);
            shared = ephemeral.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (CryptographicException ex)
        {
            throw new ChannelException("the peer sent an unusable public key", ex);
        }

        // The pairing code enters as salt. Without it both sides derive different keys
        // and the transcript check below fails, which is what authenticates the peer.
        byte[] initiatorNonce = initiator ? localNonce : remoteNonce;
        byte[] responderNonce = initiator ? remoteNonce : localNonce;

        byte[] salt = Concat(
            SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(pairingCode))),
            initiatorNonce, responderNonce);

        byte[] initiatorKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, KeySize, salt,
            Concat(Protocol, Encoding.ASCII.GetBytes("/initiator")));
        byte[] responderKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, KeySize, salt,
            Concat(Protocol, Encoding.ASCII.GetBytes("/responder")));
        byte[] confirmKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, KeySize, salt,
            Concat(Protocol, Encoding.ASCII.GetBytes("/confirm")));

        CryptographicOperations.ZeroMemory(shared);

        var channel = new SecureChannel(
            stream,
            sendKey: initiator ? initiatorKey : responderKey,
            receiveKey: initiator ? responderKey : initiatorKey)
        {
            SessionFingerprint = Convert.ToHexString(SHA256.HashData(confirmKey), 0, 4),
        };

        await channel.ConfirmAsync(confirmKey, initiatorNonce, responderNonce, remotePublic, localPublic,
            initiator, cancellationToken).ConfigureAwait(false);

        return channel;
    }

    /// <summary>
    /// Proves both ends derived the same keys, and therefore both knew the code.
    /// </summary>
    /// <remarks>
    /// Compared in constant time. A comparison that returns early on the first
    /// differing byte leaks how much of the tag was right, which over enough attempts
    /// is enough to forge one.
    /// </remarks>
    private async Task ConfirmAsync(
        byte[] confirmKey, byte[] initiatorNonce, byte[] responderNonce,
        byte[] remotePublic, byte[] localPublic, bool initiator, CancellationToken cancellationToken)
    {
        byte[] transcript = Concat(
            Protocol,
            initiator ? localPublic : remotePublic,
            initiator ? remotePublic : localPublic,
            initiatorNonce, responderNonce);

        byte[] expected = HMACSHA256.HashData(confirmKey, transcript);

        if (initiator)
        {
            await WriteBlockAsync(_stream, expected, cancellationToken).ConfigureAwait(false);
            byte[] theirs = await ReadBlockAsync(_stream, cancellationToken).ConfigureAwait(false);
            Verify(theirs, expected);
        }
        else
        {
            byte[] theirs = await ReadBlockAsync(_stream, cancellationToken).ConfigureAwait(false);
            Verify(theirs, expected);
            await WriteBlockAsync(_stream, expected, cancellationToken).ConfigureAwait(false);
        }

        CryptographicOperations.ZeroMemory(confirmKey);

        static void Verify(byte[] actual, byte[] expected)
        {
            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            {
                throw new ChannelException(
                    "the peer could not prove it knows the pairing code. Either the code is wrong, " +
                    "or something on the network is standing between the two machines.");
            }
        }
    }

    // ----------------------------------------------------------------- frames

    public async Task SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (payload.Length > MaxFrameBytes)
            throw new ChannelException($"frame of {payload.Length} bytes exceeds the {MaxFrameBytes} byte limit");

        byte[] nonce = NextNonce(ref _sendCounter);
        byte[] ciphertext = new byte[payload.Length];
        byte[] tag = new byte[TagSize];

        _send.Encrypt(nonce, payload.Span, ciphertext, tag);

        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, ciphertext.Length + TagSize);

        await _stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await _stream.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
        await _stream.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
        await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<byte[]?> ReceiveAsync(CancellationToken cancellationToken)
    {
        byte[] header = new byte[4];
        if (!await ReadExactAsync(_stream, header, cancellationToken).ConfigureAwait(false)) return null;

        int length = BinaryPrimitives.ReadInt32BigEndian(header);

        // Length is attacker-controlled until the tag verifies, so it is bounded before
        // a single byte is allocated.
        if (length < TagSize || length > MaxFrameBytes + TagSize)
            throw new ChannelException($"the peer announced an implausible frame length ({length})");

        byte[] body = new byte[length];
        if (!await ReadExactAsync(_stream, body, cancellationToken).ConfigureAwait(false)) return null;

        int payloadLength = length - TagSize;
        byte[] plaintext = new byte[payloadLength];
        byte[] nonce = NextNonce(ref _receiveCounter);

        try
        {
            _receive.Decrypt(nonce, body.AsSpan(0, payloadLength), body.AsSpan(payloadLength, TagSize), plaintext);
        }
        catch (CryptographicException ex)
        {
            // Tampering, or a desynchronised counter. Either way the channel is no
            // longer trustworthy and continuing on it would be worse than failing.
            throw new ChannelException("a frame failed authentication; the channel is closed", ex);
        }

        return plaintext;
    }

    /// <summary>
    /// Builds the next nonce for a direction.
    /// </summary>
    /// <remarks>
    /// The counter never repeats within a key: at the limit the channel refuses to
    /// continue rather than wrapping, because a repeated nonce under one key exposes
    /// the keystream for every message that shares it.
    /// </remarks>
    private static byte[] NextNonce(ref ulong counter)
    {
        if (counter == ulong.MaxValue)
            throw new ChannelException("the frame counter is exhausted; reconnect to establish new keys");

        byte[] nonce = new byte[NonceSize];
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), counter++);
        return nonce;
    }

    // ---------------------------------------------------------------- ciphers

    private interface IAeadCipher : IDisposable
    {
        void Encrypt(byte[] nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag);
        void Decrypt(byte[] nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext);
    }

    private sealed class ChaChaCipher : IAeadCipher
    {
        private readonly ChaCha20Poly1305 _cipher;
        public ChaChaCipher(byte[] key) => _cipher = new ChaCha20Poly1305(key);
        public void Encrypt(byte[] n, ReadOnlySpan<byte> p, Span<byte> c, Span<byte> t) => _cipher.Encrypt(n, p, c, t);
        public void Decrypt(byte[] n, ReadOnlySpan<byte> c, ReadOnlySpan<byte> t, Span<byte> p) => _cipher.Decrypt(n, c, t, p);
        public void Dispose() => _cipher.Dispose();
    }

    private sealed class AesGcmCipher : IAeadCipher
    {
        private readonly AesGcm _cipher;
        public AesGcmCipher(byte[] key) => _cipher = new AesGcm(key, TagSize);
        public void Encrypt(byte[] n, ReadOnlySpan<byte> p, Span<byte> c, Span<byte> t) => _cipher.Encrypt(n, p, c, t);
        public void Decrypt(byte[] n, ReadOnlySpan<byte> c, ReadOnlySpan<byte> t, Span<byte> p) => _cipher.Decrypt(n, c, t, p);
        public void Dispose() => _cipher.Dispose();
    }

    /// <summary>
    /// ChaCha20-Poly1305 where the platform provides it, AES-GCM otherwise. Both ends
    /// resolve this identically from the same OS support, so no negotiation is needed.
    /// </summary>
    private static IAeadCipher CreateCipher(byte[] key)
        => ChaCha20Poly1305.IsSupported ? new ChaChaCipher(key) : new AesGcmCipher(key);

    // ---------------------------------------------------------------- helpers

    private static async Task WriteBlockAsync(Stream stream, byte[] block, CancellationToken cancellationToken)
    {
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, block.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(block, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadBlockAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] header = new byte[4];
        if (!await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false))
            throw new ChannelException("the peer closed the connection during the handshake");

        int length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length is < 1 or > 8192)
            throw new ChannelException($"implausible handshake block length ({length})");

        byte[] block = new byte[length];
        if (!await ReadExactAsync(stream, block, cancellationToken).ConfigureAwait(false))
            throw new ChannelException("the peer closed the connection during the handshake");

        return block;
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int got = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken).ConfigureAwait(false);
            if (got == 0) return false;
            read += got;
        }
        return true;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        byte[] result = new byte[parts.Sum(static p => p.Length)];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            Buffer.BlockCopy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }
        return result;
    }

    /// <summary>
    /// Canonicalizes a pairing code so it survives being read aloud or retyped:
    /// case and separators carry no meaning.
    /// </summary>
    internal static string Normalize(string code)
        => new(code.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    public void Dispose()
    {
        _send.Dispose();
        _receive.Dispose();
    }
}
