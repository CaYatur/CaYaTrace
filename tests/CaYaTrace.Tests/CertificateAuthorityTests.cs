using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using CaYaTrace.Collectors.Proxy;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// The certificates the intercepting proxy presents.
/// </summary>
/// <remarks>
/// <para>
/// Both cases here are defects that made HTTPS interception completely non-functional
/// while reporting nothing wrong. Neither was visible from the code, from the tests that
/// existed, or from the session — the exceptions were swallowed two frames above and the
/// session reported zero exchanges, zero failures and no explanation.
/// </para>
/// <para>
/// They are tested against the real certificate machinery rather than mocked, because
/// both failures were in what Windows accepts, not in what the code intends.
/// </para>
/// </remarks>
public sealed class CertificateAuthorityTests : IDisposable
{
    private readonly SessionCertificateAuthority _authority = SessionCertificateAuthority.Create("test-session");

    public void Dispose() => _authority.Dispose();

    /// <summary>
    /// A leaf may not outlive the authority that signed it.
    /// </summary>
    /// <remarks>
    /// The leaf was minted with "now + lifetime" and the authority with "created +
    /// lifetime", so every leaf expired after its issuer by however long the session had
    /// been running. <c>CertificateRequest.Create</c> refuses that outright — so every HTTPS
    /// connection threw, from the very first one, for the whole life of the feature.
    /// </remarks>
    [Fact]
    public void ALeafNeverOutlivesTheAuthorityThatSignedIt()
    {
        using X509Certificate2 leaf = _authority.GetOrCreateLeaf("example.com");

        DateTimeOffset leafExpiry = leaf.NotAfter.ToUniversalTime();

        Assert.True(leafExpiry <= _authority.NotAfter,
            $"leaf expires {leafExpiry:u}, authority expires {_authority.NotAfter:u}");
    }

    /// <summary>
    /// Windows must accept the minted certificate as a TLS server credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the second failure, and the reason the first stayed hidden: a certificate
    /// created with an ephemeral key is a perfectly valid certificate that Schannel
    /// refuses to use as a server credential, with a Win32Exception rather than anything
    /// TLS-shaped.
    /// </para>
    /// <para>
    /// Asserted by actually handing it to <see cref="SslStream"/>, because "has a private
    /// key" was true in the broken version too.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task WindowsAcceptsTheMintedCertificateAsAServerCredential()
    {
        using X509Certificate2 leaf = _authority.GetOrCreateLeaf("example.com");

        Assert.True(leaf.HasPrivateKey, "the leaf has no private key at all");

        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        int port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            Task<System.Net.Sockets.TcpClient> accepted = listener.AcceptTcpClientAsync();

            using var client = new System.Net.Sockets.TcpClient();
            await client.ConnectAsync(System.Net.IPAddress.Loopback, port);

            using System.Net.Sockets.TcpClient server = await accepted;
            await using var serverTls = new SslStream(server.GetStream(), leaveInnerStreamOpen: false);

            // The client half only has to get far enough for the server to present its
            // certificate; whether this test process trusts the authority is not the point.
            await using var clientTls = new SslStream(
                client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);

            Task serverSide = serverTls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leaf,
                ClientCertificateRequired = false,
            });

            Task clientSide = clientTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "example.com",
            });

            // Both sides, so a server-side refusal surfaces as itself rather than as the
            // client timing out.
            await Task.WhenAll(serverSide, clientSide).WaitAsync(TimeSpan.FromSeconds(15));

            Assert.True(serverTls.IsAuthenticated);
            Assert.True(clientTls.IsAuthenticated);
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>The name a client checks has to be in the certificate.</summary>
    /// <remarks>
    /// Modern clients ignore the common name entirely, so a certificate without a matching
    /// subject alternative name fails the handshake however well it is trusted.
    /// </remarks>
    [Fact]
    public void TheHostIsInTheSubjectAlternativeName()
    {
        using X509Certificate2 leaf = _authority.GetOrCreateLeaf("updates.example.com");

        X509Extension? san = leaf.Extensions["2.5.29.17"];
        Assert.NotNull(san);
        Assert.Contains("updates.example.com", san!.Format(false), StringComparison.Ordinal);
    }

    /// <summary>One certificate per host, reused for the length of the session.</summary>
    [Fact]
    public void TheSameHostGetsTheSameCertificate()
    {
        X509Certificate2 first = _authority.GetOrCreateLeaf("example.com");
        X509Certificate2 second = _authority.GetOrCreateLeaf("example.com");

        Assert.Equal(first.Thumbprint, second.Thumbprint);
    }
}
