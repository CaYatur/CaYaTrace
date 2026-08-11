namespace CaYaTrace.Core.Model;

/// <summary>Authenticode state of an image on disk.</summary>
public enum SignatureState
{
    Unchecked = 0,
    Unsigned = 1,
    SignedValid = 2,
    SignedInvalid = 3,
    SignedExpired = 4,
    SignedUntrustedRoot = 5,
    CheckFailed = 6,
}

/// <summary>Windows process integrity level, coarse buckets.</summary>
public enum IntegrityLevel
{
    Unknown = 0,
    Untrusted = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    System = 5,
}

/// <summary>
/// A single process instance observed during a session, plus everything we learned
/// about it. Mutable because facts arrive from several collectors at different times:
/// the start event gives the command line, a later hash job fills in the digest, and
/// the exit event closes the lifetime.
/// </summary>
public sealed class ProcessNode
{
    public required ProcessKey Key { get; init; }

    public uint Pid => Key.Pid;

    /// <summary>Parent process. <see cref="ProcessKey.None"/> for roots and orphans.</summary>
    public ProcessKey ParentKey { get; set; }

    /// <summary>
    /// Parent PID as reported at start. Retained separately from
    /// <see cref="ParentKey"/> because the parent may already have exited and been
    /// recycled, in which case the PID is all we have and must not be trusted alone.
    /// </summary>
    public uint ParentPid { get; set; }

    public string ImagePath { get; set; } = string.Empty;

    public string ImageName => string.IsNullOrEmpty(ImagePath)
        ? string.Empty
        : Path.GetFileName(ImagePath);

    public string? CommandLine { get; set; }

    public string? WorkingDirectory { get; set; }

    public string? UserSid { get; set; }

    public string? UserName { get; set; }

    public uint SessionId { get; set; }

    public DateTimeOffset StartTime { get; set; }

    public DateTimeOffset? ExitTime { get; set; }

    public int? ExitCode { get; set; }

    public IntegrityLevel Integrity { get; set; }

    public bool IsElevated { get; set; }

    public SignatureState Signature { get; set; } = SignatureState.Unchecked;

    public string? Signer { get; set; }

    public string? Sha256 { get; set; }

    public long ImageSize { get; set; }

    /// <summary>
    /// True when this process is the subject of the investigation — the binary the
    /// analyst launched, or something we decided descends from it. Everything outside
    /// the marked set is background noise from the rest of the machine.
    /// </summary>
    public bool InScope { get; set; }

    /// <summary>
    /// Why this process is in scope. "root" for the launched target, "descendant" for
    /// tree membership, "adopted:&lt;reason&gt;" for processes pulled in by a heuristic
    /// such as a service start or a COM/WMI hand-off that breaks the parent chain.
    /// </summary>
    public string? ScopeReason { get; set; }

    /// <summary>Which machine observed this. Empty for the local host.</summary>
    public string? OriginId { get; set; }

    /// <summary>
    /// Set when the process existed before the session started, so its early activity
    /// was not observed. Anything attributed to it is necessarily partial.
    /// </summary>
    public bool PreExisting { get; set; }

    public List<ProcessKey> Children { get; } = new();

    /// <summary>Modules loaded into this process, keyed by normalized path.</summary>
    public HashSet<string> LoadedModules { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool IsAlive(DateTimeOffset at)
        => at >= StartTime && (ExitTime is null || at <= ExitTime.Value);

    public override string ToString()
        => $"{ImageName} ({Pid})";
}
