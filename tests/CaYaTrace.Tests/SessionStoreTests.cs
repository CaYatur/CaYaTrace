using CaYaTrace.Core.Model;
using CaYaTrace.Storage;
using Xunit;

namespace CaYaTrace.Tests;

public sealed class SessionStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cayatrace-tests", Guid.NewGuid().ToString("n"));

    private string DbPath => Path.Combine(_dir, "session.ctdb");

    public SessionStoreTests() => Directory.CreateDirectory(_dir);

    [Fact]
    public void CreateBuildsTheSchemaBeforeAnythingQueriesIt()
    {
        // Regression: Create used to open the connection through a helper that read
        // MAX(seq) from observations, which does not exist until the schema runs.
        // Every new session died on "no such table".
        using SessionStore store = SessionStore.Create(DbPath);

        Assert.Equal(0, store.CountObservations());
        Assert.Equal(1, store.NextSequence());
    }

    [Fact]
    public void QualityListsSurviveARoundTripThroughStorage()
    {
        // Regression, and the most consequential kind: the model's collections are
        // get-only properties initialized in place. System.Text.Json serializes those
        // but skips them on deserialize by default, so a session that skipped kernel
        // tracing reloaded reporting *no* problems at all — the exact misreading the
        // data-quality machinery exists to prevent.
        var session = new SessionInfo
        {
            SessionId = "test",
            Name = "subject.exe",
            StartedAt = DateTimeOffset.UtcNow,
        };
        session.Quality.SkippedForPrivilege.Add("kernel-etw: requires elevation");
        session.Quality.CollectorFailures.Add("proxy: port in use");
        session.Quality.EventsLost = 512;
        session.EnabledCollectors.Add("snapshots");

        using (SessionStore store = SessionStore.Create(DbPath))
            store.SaveSessionInfo(session);

        using SessionStore reopened = SessionStore.Open(DbPath);
        SessionInfo? loaded = reopened.LoadSessionInfo();

        Assert.NotNull(loaded);
        Assert.Equal(512, loaded.Quality.EventsLost);
        Assert.Contains("kernel-etw: requires elevation", loaded.Quality.SkippedForPrivilege);
        Assert.Contains("proxy: port in use", loaded.Quality.CollectorFailures);
        Assert.Contains("snapshots", loaded.EnabledCollectors);
        Assert.True(loaded.Quality.IsDegraded);
    }

    [Fact]
    public void ObservationsRoundTripWithTheirAttributionIntact()
    {
        var actor = ProcessKey.FromStartKey(4812, 0x1000, DateTimeOffset.UtcNow);
        var observation = new Observation
        {
            Seq = 1,
            Timestamp = new DateTimeOffset(2026, 8, 11, 12, 0, 0, TimeSpan.Zero),
            Category = EventCategory.Registry,
            Action = EventAction.ValueSet,
            Actor = actor,
            Target = @"HKLM\SOFTWARE\Example",
            Target2 = "Start",
            OldValue = "0",
            NewValue = "1",
            Source = EvidenceSource.KernelEtw,
            Confidence = AttributionConfidence.Direct,
            Bytes = 4,
        };

        using SessionStore store = SessionStore.Create(DbPath);
        store.ImportObservations(new[] { observation });

        Observation loaded = Assert.Single(store.Query());

        Assert.Equal(actor, loaded.Actor);
        Assert.Equal(EventAction.ValueSet, loaded.Action);
        Assert.Equal("0", loaded.OldValue);
        Assert.Equal("1", loaded.NewValue);
        Assert.Equal(AttributionConfidence.Direct, loaded.Confidence);
        Assert.Equal(observation.Timestamp, loaded.Timestamp);
    }

    [Fact]
    public void SequenceContinuesAfterReopeningSoAnalysisPassesCannotCollide()
    {
        using (SessionStore store = SessionStore.Create(DbPath))
        {
            store.ImportObservations(new[]
            {
                new Observation { Seq = 1, Target = "a" },
                new Observation { Seq = 2, Target = "b" },
            });
        }

        using SessionStore reopened = SessionStore.Open(DbPath);

        Assert.Equal(3, reopened.NextSequence());
    }

    [Fact]
    public void PersistentChangeFilterExcludesReads()
    {
        using SessionStore store = SessionStore.Create(DbPath);
        store.ImportObservations(new[]
        {
            new Observation { Seq = 1, Category = EventCategory.File, Action = EventAction.FileCreate, Target = "created" },
            new Observation { Seq = 2, Category = EventCategory.File, Action = EventAction.FileRead, Target = "read" },
            new Observation { Seq = 3, Category = EventCategory.Registry, Action = EventAction.KeyOpen, Target = "opened" },
        });

        List<Observation> changes = store.Query(new ObservationQuery { PersistentChangesOnly = true }).ToList();

        Assert.Single(changes);
        Assert.Equal("created", changes[0].Target);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* a held file handle should not fail the suite */ }
        catch (UnauthorizedAccessException) { }
    }
}
