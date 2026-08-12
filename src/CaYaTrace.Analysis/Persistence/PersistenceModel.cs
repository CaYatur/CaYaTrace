using CaYaTrace.Core.Graph;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Analysis.Persistence;

/// <summary>
/// The ways a program arranges to run again without being asked.
/// </summary>
/// <remarks>
/// Named by mechanism rather than by registry location, because the location is an
/// implementation detail that varies by Windows version and bitness while the mechanism
/// is what an analyst actually needs to understand and what a removal has to undo.
/// </remarks>
public enum PersistenceKind
{
    Service,
    Driver,
    ScheduledTask,
    RunKey,
    RunOnce,
    StartupFolder,
    WinlogonHook,
    ImageFileExecutionOption,
    AppInitDll,
    AppCertDll,
    SessionManagerExecute,
    LsaProvider,
    SecurityProvider,
    NetshHelper,
    PrintMonitor,
    TimeProvider,
    WinsockProvider,
    ComServer,
    ShellExtension,
    BrowserHelperObject,
    ActiveSetup,
    GroupPolicyScript,
    CommandProcessorAutoRun,
    TerminalServerRun,
    KnownDll,
}

/// <summary>One value making up a persistence entry, with where it came from.</summary>
public sealed record PersistenceValue(
    string Name,
    string? Data,
    string? Previous,
    EvidenceSource Source,
    DateTimeOffset? When);

/// <summary>
/// One way a program arranged to run again, with everything known about it.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately a model rather than a view. Four things consume it — the findings list,
/// the assistant's answers, the removal planner, and the exported report — and building
/// it per-consumer would mean four descriptions of the same service that disagree at the
/// edges. Same reasoning as the session projection: one place decides what a session
/// contains.
/// </para>
/// <para>
/// It merges two sources that each know half the story. Kernel events say who wrote a
/// value and when, but only for values that moved while the session was recording; the
/// before/after inventory has the whole record and no idea who created it. A service
/// entry that carries <c>ImagePath</c>, <c>DisplayName</c>, <c>Start</c>, <c>ObjectName</c> and its
/// recovery actions in one place, attributed to the process that installed it, needs
/// both.
/// </para>
/// </remarks>
public sealed record PersistenceRecord
{
    public required PersistenceKind Kind { get; init; }

    /// <summary>The service name, task path, or value name — what this entry is called.</summary>
    public required string Identity { get; init; }

    /// <summary>Registry key or filesystem path it lives at.</summary>
    public required string Location { get; init; }

    /// <summary>What runs: an image path, command line, or DLL.</summary>
    public string? Command { get; init; }

    /// <summary>The name a person would see, when the mechanism has one.</summary>
    public string? DisplayName { get; init; }

    public IReadOnlyList<PersistenceValue> Values { get; init; } = Array.Empty<PersistenceValue>();

    /// <summary>
    /// Decoded facts in plain words — "starts automatically", "restarts itself 60
    /// seconds after it stops".
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="Reasons"/> because these are neutral statements of what
    /// the configuration says, not arguments about whether it is alarming. An analyst
    /// needs to be able to read the former without being told the latter.
    /// </remarks>
    public IReadOnlyList<string> Traits { get; init; } = Array.Empty<string>();

    public RiskLevel Risk { get; init; }

    public int Score { get; init; }

    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();

    /// <summary>True when this did not exist before the session started.</summary>
    public bool IsNew { get; init; }

    public DateTimeOffset FirstSeen { get; init; }

    /// <summary>The process that created it, when a kernel event named one.</summary>
    public ProcessKey Actor { get; init; }

    public EvidenceSource Source { get; init; }

    public AttributionConfidence Confidence { get; init; }

    /// <summary>
    /// True when this entry is configured to come back after being stopped.
    /// </summary>
    /// <remarks>
    /// Read by the removal planner, which has to disarm this before it stops anything —
    /// a service with recovery actions restarts seconds after being stopped, and a
    /// removal that does not notice looks like it worked right up until the machine is
    /// watched for a minute.
    /// </remarks>
    public bool RestartsItself { get; init; }

    public string Describe() => $"{Kind} {Identity}" + (Command is { Length: > 0 } ? $" → {Command}" : string.Empty);
}

/// <summary>
/// Windows service recovery configuration, decoded.
/// </summary>
/// <remarks>
/// This is the mechanism behind "I stopped it and it came back". Software that resists
/// removal sets it, and so do plenty of ordinary services, so it is reported rather than
/// judged — but a removal that ignores it does not work.
/// </remarks>
public sealed record ServiceRecovery(
    int ResetPeriodSeconds,
    IReadOnlyList<ServiceRecoveryAction> Actions,
    string? Command)
{
    public bool RestartsOnFailure => Actions.Any(static a => a.Type == ServiceRecoveryActionType.Restart);

    public bool RebootsMachine => Actions.Any(static a => a.Type == ServiceRecoveryActionType.Reboot);

    public bool RunsCommand => Actions.Any(static a => a.Type == ServiceRecoveryActionType.RunCommand);
}

public enum ServiceRecoveryActionType
{
    None = 0,
    Restart = 1,
    Reboot = 2,
    RunCommand = 3,
}

public sealed record ServiceRecoveryAction(ServiceRecoveryActionType Type, int DelayMilliseconds);

/// <summary>
/// Reads the binary <c>FailureActions</c> value a service stores its recovery plan in.
/// </summary>
/// <remarks>
/// <para>
/// The layout is a five-DWORD header followed by an array of action pairs:
/// reset period in seconds, an offset to a reboot message, an offset to a command, the
/// action count, and an offset to the array itself — then that many
/// (type, delay-in-milliseconds) pairs.
/// </para>
/// <para>
/// Verified against <c>sc qfailure</c> on real services rather than derived from
/// documentation, because the header length is easy to get wrong by one field and the
/// failure mode is a plausible-looking wrong number. Spooler decoded to a 3600-second
/// reset period and two restarts at 5,000 ms, which is exactly what <c>sc</c> prints for it;
/// WSearch to 86,400 seconds and five restarts at 30,000 ms, likewise. Note that the
/// action count routinely exceeds the number of meaningful actions — the trailing
/// entries are of type None and are dropped here, which is also what <c>sc</c> does.
/// </para>
/// <para>
/// Every read is bounds-checked and anything that does not parse returns null rather
/// than a partial answer. A wrong restart delay in a report is worse than an honest gap,
/// and this value is also what the removal planner uses to decide what it has to disarm.
/// </para>
/// </remarks>
public static class ServiceFailureActions
{
    private const int HeaderBytes = 20;

    public static ServiceRecovery? Decode(byte[]? blob)
    {
        if (blob is null || blob.Length < HeaderBytes) return null;

        int resetPeriod = ReadInt32(blob, 0);
        int actionCount = ReadInt32(blob, 12);
        int actionsOffset = ReadInt32(blob, 16);

        if (actionCount < 0 || actionCount > 64) return null;
        if (actionsOffset < HeaderBytes || actionsOffset > blob.Length) return null;

        long required = (long)actionsOffset + ((long)actionCount * 8);
        if (required > blob.Length) return null;

        var actions = new List<ServiceRecoveryAction>(actionCount);
        for (int i = 0; i < actionCount; i++)
        {
            int at = actionsOffset + (i * 8);
            int type = ReadInt32(blob, at);
            int delay = ReadInt32(blob, at + 4);

            if (type is < 0 or > 3) return null;

            // Trailing None entries are padding, not instructions.
            if (type == 0) continue;

            actions.Add(new ServiceRecoveryAction((ServiceRecoveryActionType)type, delay));
        }

        return new ServiceRecovery(resetPeriod, actions, null);
    }

    /// <summary>Decodes from the hex string form the registry capture records.</summary>
    public static ServiceRecovery? DecodeHex(string? hex)
    {
        if (hex is null) return null;

        string trimmed = hex.Trim();
        if (trimmed.Length == 0 || trimmed.Length % 2 != 0) return null;

        try { return Decode(Convert.FromHexString(trimmed)); }
        catch (FormatException) { return null; }
    }

    public static string Describe(ServiceRecovery recovery)
    {
        if (recovery.Actions.Count == 0) return "no recovery actions";

        IEnumerable<string> parts = recovery.Actions.Select(static a => a.Type switch
        {
            ServiceRecoveryActionType.Restart => $"restart after {a.DelayMilliseconds / 1000.0:0.#}s",
            ServiceRecoveryActionType.Reboot => $"reboot the machine after {a.DelayMilliseconds / 1000.0:0.#}s",
            ServiceRecoveryActionType.RunCommand => $"run a command after {a.DelayMilliseconds / 1000.0:0.#}s",
            _ => "nothing",
        });

        return string.Join(", then ", parts);
    }

    private static int ReadInt32(byte[] buffer, int offset)
        => buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24);
}

/// <summary>How a Windows service is configured to start.</summary>
public static class ServiceStartType
{
    public static string Describe(int value) => value switch
    {
        0 => "loads with the kernel at boot",
        1 => "loads during system startup",
        2 => "starts automatically",
        3 => "starts when something asks for it",
        4 => "disabled",
        _ => $"start type {value}",
    };

    /// <summary>True for the start types that run without anyone logging in.</summary>
    public static bool RunsBeforeLogon(int value) => value is 0 or 1 or 2;
}
