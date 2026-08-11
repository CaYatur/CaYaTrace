using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Remediation;

public enum RemovalKind
{
    File = 0,
    Directory = 1,
    RegistryValue = 2,
    RegistryKey = 3,
    Service = 4,
    ScheduledTask = 5,
    AutorunEntry = 6,
    FirewallRule = 7,
    Certificate = 8,
}

/// <summary>
/// Identifying facts recorded at capture time, checked again before anything is
/// touched on the target machine.
/// </summary>
/// <remarks>
/// This is the mechanism that keeps a package from removing the wrong thing. The same
/// path on a different machine may hold a completely unrelated file: a package built
/// while observing a dropper that wrote <c>%APPDATA%\Update\svc.exe</c> must not delete a
/// legitimate file that happens to sit at that path on the machine being cleaned.
/// When the fingerprint does not match, the item is reported and skipped rather than
/// removed.
/// </remarks>
public sealed record ArtifactFingerprint
{
    public string? Sha256 { get; init; }
    public long Size { get; init; }
    public string? Signer { get; init; }
    public SignatureState Signature { get; init; } = SignatureState.Unchecked;

    /// <summary>Registry value data recorded at capture time.</summary>
    public string? ValueData { get; init; }

    /// <summary>Service image path or task action recorded at capture time.</summary>
    public string? CommandLine { get; init; }

    /// <summary>
    /// How closely the live artifact matches. Content match is decisive; a
    /// metadata-only match still leaves room for a coincidence.
    /// </summary>
    public FingerprintMatch Compare(ArtifactFingerprint live)
    {
        if (Sha256 is { Length: > 0 } && live.Sha256 is { Length: > 0 })
        {
            return string.Equals(Sha256, live.Sha256, StringComparison.OrdinalIgnoreCase)
                ? FingerprintMatch.Exact
                : FingerprintMatch.Conflict;
        }

        if (ValueData is not null && live.ValueData is not null)
        {
            return string.Equals(ValueData, live.ValueData, StringComparison.Ordinal)
                ? FingerprintMatch.Exact
                : FingerprintMatch.Conflict;
        }

        if (CommandLine is { Length: > 0 } && live.CommandLine is { Length: > 0 })
        {
            return string.Equals(CommandLine, live.CommandLine, StringComparison.OrdinalIgnoreCase)
                ? FingerprintMatch.Exact
                : FingerprintMatch.Conflict;
        }

        if (Size > 0 && live.Size > 0)
            return Size == live.Size ? FingerprintMatch.Partial : FingerprintMatch.Conflict;

        return FingerprintMatch.Unknown;
    }
}

public enum FingerprintMatch
{
    /// <summary>Nothing comparable was recorded. Requires confirmation.</summary>
    Unknown = 0,

    /// <summary>Weak agreement — size only. Requires confirmation.</summary>
    Partial = 1,

    /// <summary>Content or command line matches exactly.</summary>
    Exact = 2,

    /// <summary>Something is present but it is demonstrably not what was recorded.</summary>
    Conflict = 3,
}

/// <summary>One thing a removal package proposes to remove.</summary>
public sealed record RemovalItem
{
    public required RemovalKind Kind { get; init; }

    /// <summary>
    /// Tokenized target, e.g. <c>%PROGRAMFILES%\Example\app.exe</c> or
    /// <c>HKLM\SOFTWARE\Example</c>. Expanded against the target machine at apply time.
    /// </summary>
    public required string Target { get; init; }

    /// <summary>Registry value name, when <see cref="Kind"/> is a value.</summary>
    public string? ValueName { get; init; }

    /// <summary>
    /// The target with run-specific segments marked, e.g. <c>%APPDATA%\{*}\svc.exe</c>.
    /// </summary>
    /// <remarks>
    /// Set when the artifact's path varies between installations. Without it a package
    /// recorded against <c>%APPDATA%\a8f3c1\svc.exe</c> matches nothing on a machine where
    /// the same program chose <c>%APPDATA%\d92b47\svc.exe</c> — the package looks clean and
    /// leaves the program installed.
    /// </remarks>
    public string? TargetPattern { get; init; }

    /// <summary>
    /// Whether the pattern's variables were measured across machines or guessed from a
    /// single observation. A guess widens what the plan matches, so it is never applied
    /// without confirmation.
    /// </summary>
    public Analysis.TemplateEvidence PatternEvidence { get; init; } = Analysis.TemplateEvidence.Inferred;

    public ArtifactFingerprint Fingerprint { get; init; } = new();

    /// <summary>Why this is in the plan, shown to the operator before they approve.</summary>
    public required string Rationale { get; init; }

    /// <summary>Observation sequence numbers this was derived from.</summary>
    public List<long> Evidence { get; init; } = new();

    /// <summary>
    /// Ordering weight. Services stop before their binaries are removed; directories
    /// go after their contents. Lower runs first.
    /// </summary>
    public int Order => Kind switch
    {
        RemovalKind.Service => 0,
        RemovalKind.ScheduledTask => 1,
        RemovalKind.AutorunEntry => 2,
        RemovalKind.FirewallRule => 3,
        RemovalKind.RegistryValue => 4,
        RemovalKind.File => 5,
        RemovalKind.RegistryKey => 6,
        RemovalKind.Directory => 7,
        RemovalKind.Certificate => 8,
        _ => 9,
    };

    /// <summary>Machines this artifact was observed on. Multi-VM agreement raises confidence.</summary>
    public List<string> ObservedOn { get; init; } = new();
}

/// <summary>Package metadata, readable without unpacking the whole archive.</summary>
public sealed record PackageManifest
{
    public required string PackageId { get; init; }
    public required string SubjectName { get; init; }
    public string? SubjectPath { get; init; }
    public string? SubjectSha256 { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required string ToolVersion { get; init; }
    public int FormatVersion { get; init; } = 1;

    /// <summary>Machines the evidence came from.</summary>
    public List<MachineProfile> Origins { get; init; } = new();

    public int ItemCount { get; init; }

    /// <summary>
    /// SHA-256 over <c>plan.json</c>. Detects a package damaged or edited in transit.
    /// </summary>
    /// <remarks>
    /// This is an integrity check, not an authenticity one — anyone who edits the plan
    /// can recompute it. Packages are not signed in 0.1, so a package should be treated
    /// with exactly the trust you have in whoever handed it to you. The apply flow
    /// shows every item for approval before acting, which is what actually stands
    /// between a tampered plan and damage.
    /// </remarks>
    public string? PlanHash { get; init; }
}

/// <summary>
/// Reads and writes <c>.ctpkg</c> removal packages.
/// </summary>
/// <remarks>
/// <para>
/// A <c>.ctpkg</c> is a ZIP archive holding <c>manifest.json</c>, <c>plan.json</c>, and optional
/// supporting evidence. It travels as a sidecar next to <c>CaYaTrace.exe</c> rather than
/// being embedded into the executable.
/// </para>
/// <para>
/// That is a measured constraint, not a preference: patching a payload into a .NET
/// single-file bundle's PE resources truncates the bundle and corrupts the binary —
/// a 67 MB published host came back as 9.6 MB and failed to launch with "possible file
/// corruption". A sidecar also keeps the exported remediator boring, which matters
/// when it will be carried onto a possibly-infected machine where a self-modifying
/// executable is exactly the behavior endpoint protection reacts to.
/// </para>
/// </remarks>
public static class RemovalPackage
{
    public const string Extension = ".ctpkg";
    private const string ManifestEntry = "manifest.json";
    private const string PlanEntry = "plan.json";
    private const string EvidenceEntry = "evidence.jsonl";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public static void Write(
        string path,
        PackageManifest manifest,
        IReadOnlyList<RemovalItem> items,
        IEnumerable<Observation>? evidence = null)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);

        string planJson = JsonSerializer.Serialize(items, Json);
        string planHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(planJson))).ToLowerInvariant();

        PackageManifest sealed_ = manifest with { ItemCount = items.Count, PlanHash = planHash };

        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Create);

        WriteEntry(archive, ManifestEntry, JsonSerializer.Serialize(sealed_, Json));
        WriteEntry(archive, PlanEntry, planJson);

        if (evidence is not null)
        {
            ZipArchiveEntry entry = archive.CreateEntry(EvidenceEntry, CompressionLevel.SmallestSize);
            using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            foreach (Observation o in evidence)
                writer.WriteLine(JsonSerializer.Serialize(o, Json));
        }
    }

    public static (PackageManifest Manifest, List<RemovalItem> Items, bool IntegrityOk) Read(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);

        string manifestJson = ReadEntry(archive, ManifestEntry)
            ?? throw new InvalidDataException($"{path} is not a CaYaTrace removal package (no manifest)");
        string planJson = ReadEntry(archive, PlanEntry)
            ?? throw new InvalidDataException($"{path} is missing its removal plan");

        PackageManifest manifest = JsonSerializer.Deserialize<PackageManifest>(manifestJson, Json)
            ?? throw new InvalidDataException($"{path} has an unreadable manifest");

        List<RemovalItem> items = JsonSerializer.Deserialize<List<RemovalItem>>(planJson, Json) ?? new();

        string actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(planJson))).ToLowerInvariant();
        bool integrityOk = manifest.PlanHash is null
                           || string.Equals(manifest.PlanHash, actual, StringComparison.OrdinalIgnoreCase);

        if (manifest.FormatVersion > 1)
        {
            throw new InvalidDataException(
                $"{path} uses package format {manifest.FormatVersion}, which this build does not understand. " +
                "Use a newer CaYaTrace.");
        }

        return (manifest, items, integrityOk);
    }

    private static void WriteEntry(ZipArchive archive, string name, string content)
    {
        ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.SmallestSize);
        using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
        writer.Write(content);
    }

    private static string? ReadEntry(ZipArchive archive, string name)
    {
        ZipArchiveEntry? entry = archive.GetEntry(name);
        if (entry is null) return null;
        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
