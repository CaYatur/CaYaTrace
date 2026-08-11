using System.Text.Json;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Collectors.Snapshots;

/// <summary>
/// Captures system inventories before and after the subject runs, then turns the
/// difference into observations.
/// </summary>
public sealed class SnapshotEngine
{
    public const string PhaseBefore = "before";
    public const string PhaseAfter = "after";

    private readonly CollectorContext _ctx;
    private readonly List<ISnapshotProvider> _providers;

    public SnapshotEngine(CollectorContext ctx, IEnumerable<ISnapshotProvider>? providers = null)
    {
        _ctx = ctx;
        _providers = (providers ?? DefaultProviders()).ToList();
    }

    public static IEnumerable<ISnapshotProvider> DefaultProviders() => new ISnapshotProvider[]
    {
        new ServiceSnapshotProvider(),
        new ScheduledTaskSnapshotProvider(),
        new AutorunSnapshotProvider(),
        new PersistenceSnapshotProvider(),
        new InstalledProgramSnapshotProvider(),
        new DriverSnapshotProvider(),
        new CertificateSnapshotProvider(),
        new HostsFileSnapshotProvider(),
    };

    public IReadOnlyList<string> ProviderKinds => _providers.Select(static p => p.Kind).ToList();

    /// <summary>
    /// Captures every provider into the given phase. Runs on a worker thread; a
    /// full inventory takes a few seconds and must not block session start.
    /// </summary>
    public async Task CaptureAsync(string phase, CancellationToken cancellationToken = default)
    {
        DateTimeOffset takenAt = DateTimeOffset.UtcNow;

        foreach (ISnapshotProvider provider in _providers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                List<SnapshotRow> rows = await Task.Run(
                    () => provider.Capture().ToList(), cancellationToken).ConfigureAwait(false);

                _ctx.Store.WriteSnapshot(
                    phase, provider.Kind, takenAt,
                    rows.Select(static r => (r.Identity, r.Payload)),
                    _ctx.OriginId);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _ctx.ReportFault($"snapshot:{provider.Kind}", $"{phase} capture failed", ex);
            }
        }

        _ctx.Emit(new Observation
        {
            Timestamp = takenAt,
            Category = EventCategory.Session,
            Action = EventAction.SnapshotTaken,
            Target = phase,
            Source = EvidenceSource.ApiPoll,
            Status = EventStatus.Success,
        });
    }

    /// <summary>
    /// Compares the two phases and emits one observation per change.
    /// </summary>
    /// <remarks>
    /// Diff-derived observations are unattributed by design: a snapshot proves a
    /// change exists but says nothing about who made it. Attribution is added
    /// separately by <see cref="AttributeFromLiveEvents"/>, which looks for a live
    /// kernel event touching the same artifact — and leaves the entry unattributed
    /// when it finds none, rather than assuming the subject did it.
    /// </remarks>
    public int Diff()
    {
        int changes = 0;
        DateTimeOffset now = DateTimeOffset.UtcNow;

        foreach (ISnapshotProvider provider in _providers)
        {
            Dictionary<string, string> before = _ctx.Store.ReadSnapshot(PhaseBefore, provider.Kind, _ctx.OriginId);
            Dictionary<string, string> after = _ctx.Store.ReadSnapshot(PhaseAfter, provider.Kind, _ctx.OriginId);

            // A provider that failed to capture a "before" would otherwise report
            // every existing item on the machine as newly added.
            if (before.Count == 0 && after.Count > 0)
            {
                _ctx.ReportFault($"snapshot:{provider.Kind}",
                    "no baseline captured; diff skipped to avoid reporting pre-existing state as new");
                continue;
            }

            foreach ((string identity, string payload) in after)
            {
                if (!before.TryGetValue(identity, out string? previous))
                {
                    Emit(provider.Kind, AddAction(provider.Kind), identity, null, payload, now);
                    changes++;
                }
                else if (!string.Equals(previous, payload, StringComparison.Ordinal))
                {
                    Emit(provider.Kind, ModifyAction(provider.Kind), identity, previous, payload, now);
                    changes++;
                }
            }

            foreach ((string identity, string payload) in before)
            {
                if (after.ContainsKey(identity)) continue;
                Emit(provider.Kind, RemoveAction(provider.Kind), identity, payload, null, now);
                changes++;
            }
        }

        return changes;
    }

    private void Emit(string kind, (EventCategory Category, EventAction Action) verb,
        string identity, string? before, string? after, DateTimeOffset at)
    {
        _ctx.Emit(new Observation
        {
            Timestamp = at,
            Category = verb.Category,
            Action = verb.Action,
            Actor = ProcessKey.None,
            Target = identity,
            Target2 = kind,
            OldValue = Summarize(before),
            NewValue = Summarize(after),
            Source = EvidenceSource.SnapshotDiff,
            Confidence = AttributionConfidence.None,
            Status = EventStatus.Success,
            Details = after ?? before,
        });
    }

    /// <summary>
    /// Links snapshot-derived changes to the process that most plausibly caused them,
    /// by looking for a live kernel event that touched the same artifact.
    /// </summary>
    /// <remarks>
    /// The match must be specific — same artifact identity appearing in a live event's
    /// target — and within the session window. Anything looser produces confident,
    /// wrong attributions, which are worse than none: an analyst can act on
    /// "unattributed", but not on "attributed to the wrong process".
    /// </remarks>
    public int AttributeFromLiveEvents()
    {
        var exact = new Dictionary<string, ProcessKey>(StringComparer.OrdinalIgnoreCase);

        // Secondary index on path segments. A service snapshot row is keyed by the
        // bare service name, while the live event that created it wrote under
        // HKLM\SYSTEM\CurrentControlSet\Services\<name>. Indexing segments once turns
        // that fallback from a scan of every live target into a dictionary hit —
        // on a real installer the two sets are both five figures.
        var bySegment = new Dictionary<string, ProcessKey>(StringComparer.OrdinalIgnoreCase);

        foreach (Observation live in _ctx.Store.Query(new Storage.ObservationQuery
                 {
                     Categories = new List<EventCategory> { EventCategory.Registry, EventCategory.File },
                     OriginId = _ctx.OriginId ?? string.Empty,
                 }).ToList())
        {
            if (live.Actor == ProcessKey.None || live.Source == EvidenceSource.SnapshotDiff) continue;

            string key = live.Target2 is { Length: > 0 } && live.Category == EventCategory.Registry
                ? $"{live.Target}::{live.Target2}"
                : live.Target;
            exact.TryAdd(key, live.Actor);

            foreach (string segment in live.Target.Split('\\', StringSplitOptions.RemoveEmptyEntries))
            {
                if (segment.Length >= 3) bySegment.TryAdd(segment, live.Actor);
            }
        }

        // The diff rows are materialized before any write: the sink's background
        // writer commits on the same connection this reader is streaming from, and a
        // commit mid-enumeration can invalidate the open reader.
        List<Observation> pending = _ctx.Store
            .Query(new Storage.ObservationQuery { OriginId = _ctx.OriginId ?? string.Empty })
            .Where(static o => o.Source == EvidenceSource.SnapshotDiff && o.Actor == ProcessKey.None)
            .ToList();

        int attributed = 0;
        foreach (Observation diff in pending)
        {
            if (!TryMatch(exact, bySegment, diff.Target, out ProcessKey actor)) continue;

            _ctx.Sink.Write(diff with
            {
                Actor = actor,
                Confidence = AttributionConfidence.Probable,
                Details = AppendEvidence(diff.Details, "attributed by matching a live kernel event on the same artifact"),
            });
            attributed++;
        }

        return attributed;
    }

    private static bool TryMatch(
        Dictionary<string, ProcessKey> exact,
        Dictionary<string, ProcessKey> bySegment,
        string identity,
        out ProcessKey actor)
    {
        if (exact.TryGetValue(identity, out actor)) return true;

        // Fall back to the last meaningful segment of the identity — the service
        // name, the task name, the value name.
        string leaf = identity;
        int sep = leaf.LastIndexOf("::", StringComparison.Ordinal);
        if (sep >= 0) leaf = leaf[(sep + 2)..];
        int slash = leaf.LastIndexOf('\\');
        if (slash >= 0) leaf = leaf[(slash + 1)..];

        return leaf.Length >= 3 && bySegment.TryGetValue(leaf, out actor);
    }

    private static string? Summarize(string? payload)
    {
        if (string.IsNullOrEmpty(payload)) return null;
        try
        {
            using JsonDocument doc = JsonDocument.Parse(payload);
            foreach (string field in new[] { "Command", "ImagePath", "Value", "Debugger", "UninstallString", "Line", "Subject" })
            {
                if (doc.RootElement.TryGetProperty(field, out JsonElement value) && value.ValueKind == JsonValueKind.String)
                    return value.GetString();
            }
            return payload.Length <= 512 ? payload : payload[..512] + "…";
        }
        catch (JsonException)
        {
            return payload.Length <= 512 ? payload : payload[..512] + "…";
        }
    }

    private static string AppendEvidence(string? details, string note)
        => string.IsNullOrEmpty(details) ? note : $"{details}\n{note}";

    private static (EventCategory, EventAction) AddAction(string kind) => kind switch
    {
        "service" => (EventCategory.Service, EventAction.ServiceInstall),
        "task" => (EventCategory.ScheduledTask, EventAction.TaskRegister),
        "autorun" => (EventCategory.Autorun, EventAction.AutorunAdd),
        "persistence" => (EventCategory.Autorun, EventAction.AutorunAdd),
        "driver" => (EventCategory.Driver, EventAction.DriverLoad),
        "certificate" => (EventCategory.Security, EventAction.ValueSet),
        "program" => (EventCategory.Registry, EventAction.KeyCreate),
        "hosts" => (EventCategory.File, EventAction.FileWrite),
        _ => (EventCategory.Unknown, EventAction.Unknown),
    };

    private static (EventCategory, EventAction) ModifyAction(string kind) => kind switch
    {
        "service" => (EventCategory.Service, EventAction.ServiceModify),
        "task" => (EventCategory.ScheduledTask, EventAction.TaskModify),
        "autorun" => (EventCategory.Autorun, EventAction.AutorunModify),
        "persistence" => (EventCategory.Autorun, EventAction.AutorunModify),
        "driver" => (EventCategory.Driver, EventAction.DriverLoad),
        "certificate" => (EventCategory.Security, EventAction.ValueSet),
        "program" => (EventCategory.Registry, EventAction.ValueSet),
        "hosts" => (EventCategory.File, EventAction.FileWrite),
        _ => (EventCategory.Unknown, EventAction.Unknown),
    };

    private static (EventCategory, EventAction) RemoveAction(string kind) => kind switch
    {
        "service" => (EventCategory.Service, EventAction.ServiceDelete),
        "task" => (EventCategory.ScheduledTask, EventAction.TaskDelete),
        "autorun" => (EventCategory.Autorun, EventAction.AutorunRemove),
        "persistence" => (EventCategory.Autorun, EventAction.AutorunRemove),
        "certificate" => (EventCategory.Security, EventAction.ValueDelete),
        "program" => (EventCategory.Registry, EventAction.KeyDelete),
        "hosts" => (EventCategory.File, EventAction.FileDelete),
        _ => (EventCategory.Unknown, EventAction.Unknown),
    };
}
