using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Collectors.Etw;

/// <summary>
/// Fills in the facts about a process that ETW does not carry: image hash,
/// Authenticode state, signer, integrity level, and owning user.
/// </summary>
/// <remarks>
/// <para>
/// All of it is expensive — hashing reads the file, signature verification hits the
/// certificate chain and possibly the network for revocation — so none of it happens
/// on the ETW callback thread. Process-start events queue the work and a small pool
/// drains it; the tree renders immediately and these fields appear as they resolve.
/// </para>
/// <para>
/// Results are cached by path so an installer that spawns the same helper forty times
/// verifies it once.
/// </para>
/// </remarks>
internal static class ProcessMetadata
{
    private static readonly ConcurrentDictionary<string, Lazy<ImageFacts>> Cache =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly SemaphoreSlim Throttle = new(2, 2);

    /// <summary>Files larger than this are not hashed; the read cost outweighs the value.</summary>
    private const long MaxHashBytes = 256L * 1024 * 1024;

    internal sealed record ImageFacts(
        string? Sha256,
        SignatureState Signature,
        string? Signer,
        long Size);

    public static void EnrichInBackground(ProcessNode node, CollectorContext ctx)
    {
        if (node.ImagePath.Length == 0 || node.Sha256 is not null) return;

        _ = Task.Run(async () =>
        {
            await Throttle.WaitAsync().ConfigureAwait(false);
            try
            {
                ImageFacts facts = Cache.GetOrAdd(node.ImagePath,
                    static path => new Lazy<ImageFacts>(() => Inspect(path), LazyThreadSafetyMode.ExecutionAndPublication)).Value;

                node.Sha256 ??= facts.Sha256;
                node.Signer ??= facts.Signer;
                if (node.Signature == SignatureState.Unchecked) node.Signature = facts.Signature;
                if (node.ImageSize == 0) node.ImageSize = facts.Size;

                (IntegrityLevel integrity, bool elevated, string? sid, string? user) = InspectToken(node.Pid);
                if (node.Integrity == IntegrityLevel.Unknown) node.Integrity = integrity;
                node.IsElevated |= elevated;
                node.UserSid ??= sid;
                node.UserName ??= user;
            }
            catch (Exception ex)
            {
                ctx.Logger.LogDebugSafe($"metadata enrichment failed for {node.ImagePath}: {ex.Message}");
            }
            finally
            {
                Throttle.Release();
            }
        });
    }

    private static ImageFacts Inspect(string path)
    {
        string? sha = null;
        long size = 0;

        try
        {
            var info = new FileInfo(path);
            if (info.Exists)
            {
                size = info.Length;
                if (size <= MaxHashBytes)
                {
                    using FileStream fs = File.OpenRead(path);
                    sha = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A file locked by the process that created it, or deleted before we got
            // to it. Both are ordinary; the absence of a hash is itself informative.
        }

        (SignatureState state, string? signer) = VerifySignature(path);
        return new ImageFacts(sha, state, signer, size);
    }

    // ------------------------------------------------------------ signatures

    private static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    /// <summary>
    /// Who signed a file on disk, for callers outside the enrichment path.
    /// </summary>
    /// <remarks>
    /// Exposed because "who published this executable" is the only safe basis for offering
    /// to run one, and there should be exactly one answer to that question in this
    /// assembly. Uncached: the callers that need it ask about one file, once, and a stale
    /// answer about a file that has since been replaced is the failure it exists to prevent.
    /// </remarks>
    internal static (SignatureState State, string? Signer) Verify(string path) => VerifySignature(path);

    private static (SignatureState State, string? Signer) VerifySignature(string path)
    {
        if (!File.Exists(path)) return (SignatureState.CheckFailed, null);

        string? signer = null;
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            signer = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        catch (CryptographicException)
        {
            // No embedded signature. It may still be catalog-signed, which
            // WinVerifyTrust below will establish.
        }

        try
        {
            uint result = CallWinVerifyTrust(path);
            SignatureState state = result switch
            {
                0 => SignatureState.SignedValid,
                0x800B0100 => SignatureState.Unsigned,          // TRUST_E_NOSIGNATURE
                0x800B0101 => SignatureState.SignedExpired,     // CERT_E_EXPIRED
                0x800B0109 => SignatureState.SignedUntrustedRoot, // CERT_E_UNTRUSTEDROOT
                0x80096010 => SignatureState.SignedInvalid,     // TRUST_E_BAD_DIGEST
                0x800B010A => SignatureState.SignedInvalid,     // CERT_E_CHAINING
                _ => SignatureState.SignedInvalid,
            };
            return (state, signer);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return (signer is null ? SignatureState.CheckFailed : SignatureState.SignedInvalid, signer);
        }
    }

    private static uint CallWinVerifyTrust(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
        };

        IntPtr fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2,             // WTD_UI_NONE — never prompt
                fdwRevocationChecks = 0,    // WTD_REVOKE_NONE — no network round trip
                dwUnionChoice = 1,          // WTD_CHOICE_FILE
                pFile = fileInfoPtr,
                dwStateAction = 0,
                dwProvFlags = 0x00000010,   // WTD_CACHE_ONLY_URL_RETRIEVAL
            };

            Guid action = WinTrustActionGenericVerifyV2;
            return WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    // ---------------------------------------------------------------- token

    private static (IntegrityLevel, bool, string?, string?) InspectToken(uint pid)
    {
        IntPtr token = IntPtr.Zero;
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById((int)pid);
            if (!OpenProcessToken(process.Handle, TOKEN_QUERY, out token))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

            // WindowsIdentity duplicates the handle rather than taking ownership, so
            // the original must still be closed here or the session leaks one handle
            // per unique process observed.
            using var identity = new System.Security.Principal.WindowsIdentity(token);
            var principal = new System.Security.Principal.WindowsPrincipal(identity);

            IntegrityLevel level = ReadIntegrityLevel(token);
            bool elevated = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

            return (level, elevated, identity.User?.Value, identity.Name);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException
                                       or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            // The process exited, or it is protected (PPL) and its token cannot be
            // opened even from an elevated context. Neither is an error.
            return (IntegrityLevel.Unknown, false, null, null);
        }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    /// <summary>
    /// Reads the token's mandatory integrity level from its integrity SID.
    /// </summary>
    /// <remarks>
    /// Worth doing properly rather than inferring from group membership. The
    /// difference between a Low-integrity browser renderer and a System service is
    /// exactly the kind of thing an analyst reads off the process node, and a value
    /// that is confidently wrong is worse than <see cref="IntegrityLevel.Unknown"/>.
    /// The level lives in the last sub-authority of the integrity SID:
    /// 0x0000 untrusted, 0x1000 low, 0x2000 medium, 0x3000 high, 0x4000 system.
    /// </remarks>
    private static IntegrityLevel ReadIntegrityLevel(IntPtr token)
    {
        const int TokenIntegrityLevel = 25;

        GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out uint needed);
        if (needed == 0) return IntegrityLevel.Unknown;

        IntPtr buffer = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, needed, out _))
                return IntegrityLevel.Unknown;

            var label = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(buffer);
            if (label.Label.Sid == IntPtr.Zero) return IntegrityLevel.Unknown;

            IntPtr countPtr = GetSidSubAuthorityCount(label.Label.Sid);
            if (countPtr == IntPtr.Zero) return IntegrityLevel.Unknown;

            int count = Marshal.ReadByte(countPtr);
            if (count == 0) return IntegrityLevel.Unknown;

            IntPtr ridPtr = GetSidSubAuthority(label.Label.Sid, (uint)(count - 1));
            if (ridPtr == IntPtr.Zero) return IntegrityLevel.Unknown;

            uint rid = unchecked((uint)Marshal.ReadInt32(ridPtr));

            // Levels are ranges, not exact values: Windows defines intermediate RIDs
            // (AppContainer sits between low and medium), so compare by threshold.
            return rid switch
            {
                >= 0x4000 => IntegrityLevel.System,
                >= 0x3000 => IntegrityLevel.High,
                >= 0x2000 => IntegrityLevel.Medium,
                >= 0x1000 => IntegrityLevel.Low,
                _ => IntegrityLevel.Untrusted,
            };
        }
        catch (Exception ex) when (ex is AccessViolationException or ArgumentException)
        {
            return IntegrityLevel.Unknown;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private const uint TOKEN_QUERY = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation,
        uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WINTRUST_DATA data);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}

internal static class LoggerSafeExtensions
{
    /// <summary>
    /// Debug logging that cannot itself become a failure path. Enrichment runs on
    /// background threads where an unhandled exception would be lost anyway.
    /// </summary>
    public static void LogDebugSafe(this Microsoft.Extensions.Logging.ILogger logger, string message)
    {
        try { Microsoft.Extensions.Logging.LoggerExtensions.LogDebug(logger, "{Message}", message); }
        catch (Exception) { /* logging must never throw into a collector */ }
    }
}
