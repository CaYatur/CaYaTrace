using CaYaTrace.Core.Correlation;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;
using CaYaTrace.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CaYaTrace.Collectors;

/// <summary>
/// State shared by every collector in a session.
/// </summary>
/// <remarks>
/// Collectors are deliberately thin: they translate one event source into
/// <see cref="Observation"/> values and hand them here. All identity resolution lives
/// in the shared tables so that a file path learned by the kernel collector is
/// immediately usable by the proxy collector, and a process discovered by a snapshot
/// is the same object the network collector attributes a flow to.
/// </remarks>
public sealed class CollectorContext
{
    public required SessionInfo Session { get; init; }

    public required ObservationSink Sink { get; init; }

    public required SessionStore Store { get; init; }

    public required ProcessTable Processes { get; init; }

    public required FlowTable Flows { get; init; }

    public required PathNormalizer Paths { get; init; }

    public required FileObjectResolver Files { get; init; }

    public required RegistryKeyResolver Registry { get; init; }

    public ILogger Logger { get; init; } = NullLogger.Instance;

    /// <summary>Identifier for the machine this context collects on. Empty for the host.</summary>
    public string? OriginId { get; init; }

    /// <summary>
    /// When set, observations from processes outside the scoped tree are discarded at
    /// ingest rather than stored. Cuts a system-wide session down by one to two orders
    /// of magnitude, at the cost of being unable to widen scope afterwards.
    /// </summary>
    public bool DropOutOfScope { get; set; }

    public DataQuality Quality => Session.Quality;

    /// <summary>
    /// Normalizes and records an observation. The single funnel every collector uses,
    /// so scope filtering, origin stamping, and quality accounting happen once.
    /// </summary>
    public void Emit(Observation observation)
    {
        if (DropOutOfScope && observation.Actor != ProcessKey.None)
        {
            ProcessNode? actor = Processes.Get(observation.Actor);
            if (actor is not null && !actor.InScope) return;
        }

        Observation stamped = observation.OriginId is null && OriginId is not null
            ? observation with { OriginId = OriginId }
            : observation;

        Sink.Write(stamped);
        Interlocked.Increment(ref _collected);
    }

    private long _collected;

    public long Collected => Interlocked.Read(ref _collected);

    /// <summary>
    /// Records a collector problem. These surface in the session header rather than
    /// only in a log file, because a collector that silently failed to start looks
    /// exactly like a program that did nothing.
    /// </summary>
    public void ReportFault(string collector, string message, Exception? ex = null)
    {
        string full = ex is null ? message : $"{message}: {ex.GetType().Name}: {ex.Message}";
        Quality.CollectorFailures.Add($"{collector}: {full}");
        Logger.LogWarning("collector {Collector} fault: {Message}", collector, full);
        try { Store.LogQuality(collector, "error", full); }
        catch (Exception) { /* storage is already unhealthy; the in-memory record stands */ }
    }

    public void ReportSkipped(string collector, string reason)
    {
        Quality.SkippedForPrivilege.Add($"{collector}: {reason}");
        Logger.LogInformation("collector {Collector} skipped: {Reason}", collector, reason);
        try { Store.LogQuality(collector, "skipped", reason); }
        catch (Exception) { /* non-fatal */ }
    }

    /// <summary>Folds live counters into the session's quality record.</summary>
    public void RefreshQuality()
    {
        Quality.EventsCollected = Collected;
        Quality.EventsDroppedBySink = Sink.Dropped;
        Quality.FileNameHitRate = Files.HitRate;
        Quality.RegistryNameHitRate = Registry.HitRate;
        Quality.UnattributedFlows = Flows.UnattributedCount;
    }
}

/// <summary>A source of evidence that runs for the length of a session.</summary>
public interface ICollector : IAsyncDisposable
{
    /// <summary>Stable name used in fault reports and the enabled-collector list.</summary>
    string Name { get; }

    /// <summary>True when this collector cannot function without elevation.</summary>
    bool RequiresElevation { get; }

    /// <summary>
    /// Begins collecting. Implementations must not throw for an expected failure such
    /// as missing privilege; they should report through
    /// <see cref="CollectorContext.ReportSkipped"/> and return false.
    /// </summary>
    Task<bool> StartAsync(CollectorContext context, CancellationToken cancellationToken);

    /// <summary>Stops collecting and flushes anything buffered internally.</summary>
    Task StopAsync(CancellationToken cancellationToken);
}
