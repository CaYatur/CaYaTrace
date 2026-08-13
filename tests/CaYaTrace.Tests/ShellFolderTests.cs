using CaYaTrace.Core.Model;
using CaYaTrace.Remediation;
using CaYaTrace.Storage;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// Folders Windows maintains never become removal candidates.
/// </summary>
/// <remarks>
/// The kernel reports a directory create when a program <em>opens</em> a directory with a
/// create disposition, which every program does to a folder it is about to read. That is
/// indistinguishable from actually making one, so a program that merely looked inside
/// Documents produced an event reading "created by", and the plan offered to delete the
/// operator's Documents folder — ticked, because everything the subject created is ticked.
/// </remarks>
public sealed class ShellFolderTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "cayatrace-shell-" + Guid.NewGuid().ToString("n")[..8]);

    private SessionStore Store()
    {
        Directory.CreateDirectory(_directory);
        return SessionStore.Create(Path.Combine(_directory, "session.ctdb"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>
    /// A stand-in for the subject.
    /// </summary>
    /// <remarks>
    /// Every observation carries one. Without an actor these would be filtered before the
    /// shell-folder check ever ran, and the test would pass without exercising it.
    /// </remarks>
    private static readonly ProcessKey Subject =
        ProcessKey.TryParse("k:ffff000011112222:4772", out ProcessKey parsed) ? parsed : ProcessKey.None;

    private static Observation DirectoryCreated(long seq, string path) => new()
    {
        Seq = seq,
        Actor = Subject,
        Timestamp = DateTimeOffset.UtcNow,
        Category = EventCategory.File,
        Action = EventAction.DirectoryCreate,
        Target = path,
        Source = EvidenceSource.KernelEtw,
        Status = EventStatus.Success,
    };

    /// <summary>
    /// The operator's own folders are never offered for deletion.
    /// </summary>
    /// <remarks>
    /// Resolved from this machine rather than compared against names, because a profile
    /// can be redirected to another drive and a name comparison would miss it — which is
    /// the case where deleting it costs the most.
    /// </remarks>
    [Fact]
    public void AFolderWindowsMaintainsIsNeverAcandidate()
    {
        using SessionStore store = Store();

        var session = new SessionInfo { SessionId = "test", Name = "subject.exe" };
        store.SaveSessionInfo(session);

        var batch = new List<Observation>();
        long seq = 1;
        foreach (Environment.SpecialFolder folder in new[]
                 {
                     Environment.SpecialFolder.UserProfile,
                     Environment.SpecialFolder.MyDocuments,
                     Environment.SpecialFolder.Desktop,
                     Environment.SpecialFolder.ApplicationData,
                     Environment.SpecialFolder.LocalApplicationData,
                     Environment.SpecialFolder.InternetCache,
                     Environment.SpecialFolder.Cookies,
                     Environment.SpecialFolder.History,
                 })
        {
            string path = Environment.GetFolderPath(folder);
            if (path.Length > 0) batch.Add(DirectoryCreated(seq++, path));
        }

        store.ImportObservations(batch);

        List<RemovalItem> plan = new RemovalPlanner(store).Build(session);

        Assert.DoesNotContain(plan, i => i.Kind == RemovalKind.Directory);
    }

    /// <summary>A directory the program genuinely made is still a candidate.</summary>
    /// <remarks>
    /// The other half. Refusing every directory would be a different bug with the same
    /// symptom — a plan that leaves the program's own folder behind.
    /// </remarks>
    [Fact]
    public void AFolderTheProgramMadeIsStillOffered()
    {
        using SessionStore store = Store();

        var session = new SessionInfo { SessionId = "test", Name = "subject.exe" };
        store.SaveSessionInfo(session);

        string own = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ContosoWidget");

        store.ImportObservations(new List<Observation> { DirectoryCreated(1, own) });

        List<RemovalItem> plan = new RemovalPlanner(store).Build(session);

        Assert.Contains(plan, i => i.Kind == RemovalKind.Directory
                                   && i.Target.Contains("ContosoWidget", StringComparison.OrdinalIgnoreCase));
    }
}
