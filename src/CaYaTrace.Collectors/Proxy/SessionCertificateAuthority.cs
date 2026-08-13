using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CaYaTrace.Collectors.Proxy;

/// <summary>
/// A throwaway certificate authority that exists only for the length of one session.
/// </summary>
/// <remarks>
/// <para>
/// This is the sharpest thing CaYaTrace can do to a machine. While the CA is trusted,
/// anything running as the user can present a certificate for any site and be believed.
/// Every property below exists to bound that:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>The key is generated fresh per session and never leaves memory except as a
///     password-less file inside the session directory</b>, which is itself evidence and
///     is treated as sensitive. No key material ships with the tool — a shipped CA key
///     would be a universal interception key for every user of it, which is how
///     "developer convenience" becomes a supply-chain vulnerability.
///   </description></item>
///   <item><description>
///     <b>Validity is measured in hours, not years.</b> If removal fails and nobody
///     notices, the certificate stops being usable on its own.
///   </description></item>
///   <item><description>
///     <b>The subject name says what it is</b>, so anyone auditing the store sees an
///     explanation rather than a plausible-looking corporate CA.
///   </description></item>
///   <item><description>
///     <b>Removal is verified, not assumed</b>, and re-attempted on the next launch.
///   </description></item>
/// </list>
/// </remarks>
public sealed class SessionCertificateAuthority : IDisposable
{
    /// <summary>
    /// Marker in the subject name. Removal matches on this, so a certificate left by a
    /// crashed run is recognisable without any state file surviving.
    /// </summary>
    /// <remarks>
    /// Contains no comma. A comma is the attribute separator in a distinguished name,
    /// so one inside a value makes the whole subject unparseable and certificate
    /// creation fails outright.
    /// </remarks>
    public const string SubjectMarker = "CaYaTrace Temporary Session CA - safe to delete";

    /// <summary>
    /// Short by design. Long enough for any realistic analysis session, short enough
    /// that a failure to clean up expires on its own rather than persisting.
    /// </summary>
    private static readonly TimeSpan Lifetime = TimeSpan.FromHours(12);

    private readonly X509Certificate2 _authority;
    private readonly ConcurrentDictionary<string, X509Certificate2> _leaves = new(StringComparer.OrdinalIgnoreCase);

    public string Thumbprint => _authority.Thumbprint;

    /// <summary>When the authority stops being usable, and the ceiling on every leaf it signs.</summary>
    public DateTimeOffset NotAfter => _authority.NotAfter.ToUniversalTime();

    public bool IsInstalled { get; private set; }

    private SessionCertificateAuthority(X509Certificate2 authority) => _authority = authority;

    public static SessionCertificateAuthority Create(string sessionId)
    {
        using var key = RSA.Create(2048);

        var request = new CertificateRequest(
            $"CN={SubjectMarker}, O=CaYaDev, OU=session {sessionId}",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true,
                pathLengthConstraint: 0, critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
                critical: true));

        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        DateTimeOffset now = DateTimeOffset.UtcNow;
        X509Certificate2 certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.Add(Lifetime));

        // Re-import as exportable so leaf certificates can be signed with the key on
        // platforms where the ephemeral key handle is not reusable.
        byte[] pfx = certificate.Export(X509ContentType.Pfx);
        certificate.Dispose();

        // X509CertificateLoader is .NET 9+; this targets .NET 8.
        return new SessionCertificateAuthority(
            new X509Certificate2(pfx, (string?)null,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet));
    }

    /// <summary>
    /// Mints a certificate for one host, signed by this session's authority.
    /// </summary>
    /// <remarks>
    /// Cached per host: a page pulling from a dozen origins would otherwise pay an RSA
    /// key generation for each, which is slow enough to look like a hung connection.
    /// </remarks>
    public X509Certificate2 GetOrCreateLeaf(string host)
    {
        return _leaves.GetOrAdd(host, h =>
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(
                $"CN={h}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, critical: true));

            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));

            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new("1.3.6.1.5.5.7.3.1") }, critical: false));   // server auth

            // Modern clients ignore the common name entirely; without a matching SAN
            // the handshake fails regardless of trust.
            var subjectAlternativeName = new SubjectAlternativeNameBuilder();
            if (System.Net.IPAddress.TryParse(h, out System.Net.IPAddress? address))
                subjectAlternativeName.AddIpAddress(address);
            else
                subjectAlternativeName.AddDnsName(h);
            request.CertificateExtensions.Add(subjectAlternativeName.Build());

            // A leaf may not outlive the authority that signed it, and it is minted later
            // than the authority was created — so "now + lifetime" is always past the
            // authority's own expiry, by however many seconds the session has been
            // running. That is not an edge case: it made *every* HTTPS connection throw
            // ArgumentException, from the first one, for the whole life of the feature.
            // The failure was invisible because the exception was swallowed two frames up.
            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset expiry = now.Add(Lifetime);
            DateTimeOffset issuerExpiry = _authority.NotAfter.ToUniversalTime();
            if (expiry > issuerExpiry) expiry = issuerExpiry;

            using X509Certificate2 issued = request.Create(
                _authority,
                now.AddMinutes(-5),
                expiry,
                Guid.NewGuid().ToByteArray());

            // SslStream needs the private key attached, which Create does not carry over.
            using X509Certificate2 withKey = issued.CopyWithPrivateKey(key);

            // Deliberately NOT EphemeralKeySet, and this is the whole reason HTTPS
            // interception recorded nothing at all.
            //
            // Schannel — the Windows TLS implementation behind SslStream — cannot use an
            // ephemeral key as a server credential. It fails with a Win32Exception
            // ("the credentials supplied to the package were not recognized"), which is
            // neither AuthenticationException nor IOException, so it escaped the handler
            // below, killed the connection, and left the session reporting zero exchanges
            // and zero failures. The subject saw "the underlying connection was closed".
            //
            // Without PersistKeySet the key container is removed when this certificate is
            // disposed, so the machine is not left carrying a key per host visited.
            return new X509Certificate2(
                withKey.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);
        });
    }

    /// <summary>
    /// Places the authority in the machine's trusted roots.
    /// </summary>
    /// <remarks>
    /// Only ever called after the operator has explicitly agreed, in a prompt that
    /// names what is about to happen. The caller records the thumbprint so removal can
    /// be verified afterwards.
    /// </remarks>
    public bool Install(out string? error)
    {
        error = null;
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            // Only the public certificate is installed. Trust does not require the
            // private key, and putting it in the store would leave it readable there.
            using var publicOnly = new X509Certificate2(_authority.RawData);
            store.Add(publicOnly);

            IsInstalled = true;
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Removes the authority and confirms it is gone.
    /// </summary>
    /// <returns>True only when a subsequent read of the store no longer finds it.</returns>
    public bool Remove(out string? error)
    {
        bool removed = RemoveByThumbprint(_authority.Thumbprint, out error);
        if (removed) IsInstalled = false;
        return removed;
    }

    /// <summary>
    /// Thumbprints of any CaYaTrace authority currently trusted by this machine.
    /// </summary>
    /// <remarks>
    /// Read-only, and separate from removal for exactly that reason: opening the machine
    /// root store for writing needs administrator rights, so a user-level launch that
    /// called <see cref="RemoveAllStale"/> alone would find nothing and report nothing,
    /// while the certificate sat there trusted. Reading needs no rights, so a launch that
    /// cannot fix this can still say so.
    /// </remarks>
    public static List<string> FindStale()
    {
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            return store.Certificates
                .Where(static c => c.Subject.Contains(SubjectMarker, StringComparison.OrdinalIgnoreCase))
                .Select(static c => c.Thumbprint)
                .ToList();
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new List<string>();
        }
    }

    /// <summary>
    /// Removes any CaYaTrace authority found in the machine root store.
    /// </summary>
    /// <remarks>
    /// Called on every launch, not only after a crash. A tool that can leave a trusted
    /// root behind must clean up without being asked, because the run that failed to
    /// clean up is by definition the run that is not around to notice.
    /// </remarks>
    public static int RemoveAllStale(out List<string> removed)
    {
        removed = new List<string>();

        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            var stale = store.Certificates
                .Where(static c => c.Subject.Contains(SubjectMarker, StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (X509Certificate2 certificate in stale)
            {
                try
                {
                    store.Remove(certificate);
                    removed.Add(certificate.Thumbprint);
                }
                catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException)
                {
                    // Reported by the caller; one stubborn certificate must not stop
                    // the others being cleared.
                }
            }

            return removed.Count;
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return 0;
        }
    }

    /// <summary>True when a certificate with this thumbprint is in the machine root store.</summary>
    public static bool IsTrusted(string thumbprint)
    {
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            return store.Certificates
                .Any(c => string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool RemoveByThumbprint(string thumbprint, out string? error)
    {
        error = null;
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            foreach (X509Certificate2 certificate in store.Certificates
                         .Where(c => string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
                         .ToList())
            {
                store.Remove(certificate);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            error = ex.Message;
            return false;
        }

        // Verified rather than assumed: a removal that silently failed would leave the
        // machine trusting an interception CA while the report claims it was cleaned up.
        if (IsTrusted(thumbprint))
        {
            error = "the certificate is still present in the machine root store after removal was attempted";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Writes the public certificate beside the session, so an operator can confirm
    /// afterwards exactly which certificate was trusted.
    /// </summary>
    public string ExportPublicCertificate(string directory)
    {
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "session-ca.cer");
        File.WriteAllBytes(path, _authority.Export(X509ContentType.Cert));
        return path;
    }

    public void Dispose()
    {
        foreach (X509Certificate2 leaf in _leaves.Values) leaf.Dispose();
        _leaves.Clear();
        _authority.Dispose();
    }
}
