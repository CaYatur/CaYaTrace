using System.Collections.Concurrent;
using System.Text.Json;
using System.Windows.Forms;
using CaYaTrace.Collectors;
using CaYaTrace.Collectors.Etw;
using CaYaTrace.Collectors.Proxy;
using CaYaTrace.Core.Model;
using CaYaTrace.Storage;

namespace CaYaTrace.App.Modes;

/// <summary>
/// Recording, from the workbench.
/// </summary>
/// <remarks>
/// The same <see cref="SessionOrchestrator"/> the CLI drives, with two differences that
/// only matter in a UI: progress is pushed to the page while it runs, and the consent
/// for HTTPS interception is asked as a modal that requires a typed word rather than as
/// a console prompt.
/// </remarks>
public sealed partial class WorkbenchWindow
{
    private SessionOrchestrator? _capture;
    private System.Windows.Forms.Timer? _captureTimer;
    private DateTimeOffset _captureStarted;
    private string? _captureDirectory;
    private CancellationTokenSource? _captureDuration;

    /// <summary>Modal questions the page is currently answering, by id.</summary>
    private readonly ConcurrentDictionary<string, TaskCompletionSource<bool>> _modals = new();

    // ------------------------------------------------------------------ pickers

    private void PickFile(string? purpose)
    {
        using var dialog = new OpenFileDialog
        {
            Title = Strings.T("capture.pick_target"),
            Filter = "Programs (*.exe;*.msi;*.bat;*.cmd)|*.exe;*.msi;*.bat;*.cmd|All files (*.*)|*.*",
            CheckFileExists = true,
        };

        if (dialog.ShowDialog(this) == DialogResult.OK)
            Post("picked", new { purpose, path = dialog.FileName });
    }

    private void PickFolder(string? purpose)
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = purpose == "sessionRoot"
                ? Strings.T("capture.pick_folder")
                : Strings.T("sessions.open_folder"),
            UseDescriptionForTitle = true,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        switch (purpose)
        {
            case "sessionRoot":
                _settings.SessionRoot = dialog.SelectedPath;
                _settings.Save();
                Post("picked", new { purpose, path = dialog.SelectedPath });
                break;

            case "openSession":
                LoadSession(dialog.SelectedPath);
                break;

            default:
                Post("picked", new { purpose, path = dialog.SelectedPath });
                break;
        }
    }

    // ------------------------------------------------------------------ capture

    private void StartCapture(JsonElement payload)
    {
        if (_capture is not null) return;

        string mode = Str(payload, "mode") ?? "launch";
        string? target = Str(payload, "target");
        string root = Str(payload, "root") is { Length: > 0 } r ? r : UserSettings.DefaultSessionRoot;

        JsonElement options = payload.TryGetProperty("options", out JsonElement o) ? o : default;
        bool Option(string name) => options.ValueKind == JsonValueKind.Object
                                    && options.TryGetProperty(name, out JsonElement v)
                                    && v.ValueKind == JsonValueKind.True;

        if (mode == "launch")
        {
            if (string.IsNullOrWhiteSpace(target) || !File.Exists(target))
            {
                Post("captureState", new { state = "idle", message = Strings.T("capture.needs_target"), error = true });
                return;
            }
            target = Path.GetFullPath(target);
        }

        var sessionOptions = new SessionOptions
        {
            Mode = mode switch
            {
                "attach" => SessionMode.AttachExisting,
                "system" => SessionMode.SystemWide,
                _ => SessionMode.LaunchTarget,
            },
            TargetPath = mode == "launch" ? target : null,
            TargetArguments = Str(payload, "args"),
            AttachPid = (uint)Math.Max(0, Int(payload, "pid")),
            SessionRoot = root,
            Name = Str(payload, "name") is { Length: > 0 } name ? name : null,
            CaptureSnapshots = Option("snapshots"),
            DropOutOfScope = Option("scoped"),
            CapturePackets = Option("packets"),

            // The only way to read what two programs on this machine said to each other.
            // Off by default because it needs a packet driver this tool does not install,
            // and because it widens what a recording contains: local conversations from
            // every process on the machine, not only the subject's.
            CaptureLoopback = Option("loopback"),

            // A callback, not a flag. Ticking the box is not consent; it only makes the
            // question get asked, and the question needs a typed answer because what it
            // installs is a trusted root certificate authority.
            InterceptionConsent = Option("intercept") ? AskForInterceptionConsent : null,
            Kernel = new KernelCollectorOptions { CollectReads = Option("reads") },
        };

        int duration = Int(payload, "duration");

        _settings.SessionRoot = root;
        _settings.Save();

        Post("captureState", new { state = "starting", events = 0, elapsed = 0 });
        _ = RunCaptureAsync(sessionOptions, duration);
    }

    private async Task RunCaptureAsync(SessionOptions options, int durationSeconds)
    {
        var orchestrator = new SessionOrchestrator(options);

        try
        {
            // Started off the UI thread on purpose. The interception consent callback
            // blocks the thread it runs on while the operator reads a modal; if that
            // thread were the UI thread, the modal could never be drawn and the app
            // would hang at exactly the moment it asked permission to change the
            // machine.
            SessionInfo started = await Task.Run(() => orchestrator.StartAsync(CancellationToken.None))
                .ConfigureAwait(true);

            _capture = orchestrator;
            _captureStarted = DateTimeOffset.UtcNow;
            _captureDirectory = orchestrator.SessionDirectory;

            _captureTimer?.Dispose();
            _captureTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            _captureTimer.Tick += (_, _) => PublishCaptureProgress();
            _captureTimer.Start();

            Post("captureState", new
            {
                state = "running",
                events = 0,
                elapsed = 0,
                sessionId = started.SessionId,
            });

            if (durationSeconds > 0)
            {
                _captureDuration = new CancellationTokenSource();
                CancellationToken token = _captureDuration.Token;
                _ = Task.Delay(TimeSpan.FromSeconds(durationSeconds), token)
                    .ContinueWith(task =>
                    {
                        if (!task.IsCanceled) BeginInvoke(StopCapture);
                    }, TaskScheduler.Default);
            }
        }
        catch (Exception ex)
        {
            await orchestrator.DisposeAsync().ConfigureAwait(true);
            _capture = null;
            Post("captureState", new
            {
                state = "idle",
                message = $"{Strings.T("error.capture_failed")} {ex.Message}",
                error = true,
            });
        }
    }

    private void PublishCaptureProgress()
    {
        if (_capture is null) return;

        long events = _capture.Context?.Collected ?? 0;
        Post("captureState", new
        {
            state = "running",
            events,
            elapsed = (int)(DateTimeOffset.UtcNow - _captureStarted).TotalSeconds,
        });
    }

    private void StopCapture()
    {
        if (_capture is null) return;
        _ = StopCaptureAsync();
    }

    private async Task StopCaptureAsync()
    {
        SessionOrchestrator? orchestrator = _capture;
        if (orchestrator is null) return;

        _capture = null;
        _captureTimer?.Stop();
        _captureTimer?.Dispose();
        _captureTimer = null;
        _captureDuration?.Cancel();
        _captureDuration = null;

        Post("captureState", new { state = "stopping" });

        try
        {
            // Stopping is the expensive half: it is what makes the kernel emit the
            // file-name and registry-key rundowns the whole session depends on, and it
            // takes the after-snapshot. Off the UI thread so the window stays alive.
            SessionInfo finished = await Task.Run(() => orchestrator.StopAsync(CancellationToken.None))
                .ConfigureAwait(true);

            string? degraded = finished.Quality.Summarize();
            Post("captureState", new
            {
                state = "idle",
                message = Strings.T("capture.finished"),
                error = false,
                degraded,
            });

            if (_captureDirectory is not null) LoadSession(_captureDirectory);
            ListSessions(_settings.SessionRoot);
        }
        catch (Exception ex)
        {
            Post("captureState", new { state = "idle", message = ex.Message, error = true });
        }
        finally
        {
            await orchestrator.DisposeAsync().ConfigureAwait(true);
        }
    }

    /// <summary>
    /// Stops a capture during window close, without returning to the message loop.
    /// </summary>
    /// <remarks>
    /// Blocking is the point. The window is going away; if this returned before the ETW
    /// session was closed, the process would exit with a kernel tracing session still
    /// registered and the session on disk would have no after-snapshot.
    /// </remarks>
    private void StopCaptureSynchronously()
    {
        SessionOrchestrator? orchestrator = _capture;
        if (orchestrator is null) return;

        _capture = null;
        _captureTimer?.Stop();

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            orchestrator.StopAsync(cts.Token).GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidOperationException)
        {
            // Nothing useful to show: the window is closing.
        }
        finally
        {
            orchestrator.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    // ------------------------------------------------------------------ consent

    /// <summary>
    /// Asks the operator to confirm HTTPS interception, and blocks until they answer.
    /// </summary>
    /// <remarks>
    /// A typed word, not a button. This installs a trusted root certificate authority
    /// into the machine's store, and a dialog that a reflexive Enter dismisses is not
    /// consent to that. Anything other than a clear yes — a closed dialog, a timeout, a
    /// window that went away — is a no.
    /// </remarks>
    private bool AskForInterceptionConsent(InterceptionConsentRequest request)
    {
        string id = Guid.NewGuid().ToString("N");
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _modals[id] = completion;

        Post("modal", new
        {
            id,
            title = Strings.T("consent.intercept_title"),
            body = request.Describe(),
            acceptLabel = Strings.T("consent.intercept_accept"),
            declineLabel = Strings.T("consent.intercept_decline"),
            requireTyped = "INTERCEPT",
            typedPrompt = Strings.T("consent.intercept_typed"),
        });

        try
        {
            // Two minutes is long enough to read what is about to change and short
            // enough that a session started by automation does not sit forever.
            return completion.Task.Wait(TimeSpan.FromMinutes(2)) && completion.Task.Result;
        }
        finally
        {
            _modals.TryRemove(id, out _);
        }
    }

    private void CompleteModal(string? id, bool accepted)
    {
        if (id is not null && _modals.TryRemove(id, out TaskCompletionSource<bool>? completion))
            completion.TrySetResult(accepted);
    }

    // ----------------------------------------------------------------- sessions

    private void ListSessions(string? root)
    {
        string folder = root is { Length: > 0 } ? root : _settings.SessionRoot ?? UserSettings.DefaultSessionRoot;
        _ = Task.Run(() => ScanSessions(folder));
    }

    private void ScanSessions(string root)
    {
        var found = new List<object>();

        try
        {
            if (Directory.Exists(root))
            {
                IEnumerable<string> directories = Directory.EnumerateDirectories(root, "session_*")
                    .OrderByDescending(Directory.GetLastWriteTimeUtc)
                    .Take(300);

                foreach (string directory in directories)
                {
                    string database = Path.Combine(directory, SessionPaths.DatabaseName);
                    if (!File.Exists(database)) continue;

                    try
                    {
                        using SessionStore store = SessionStore.Open(database);
                        SessionInfo? info = store.LoadSessionInfo();
                        if (info is null) continue;

                        found.Add(new
                        {
                            path = directory,
                            name = info.Name,
                            started = info.StartedAt,
                            machine = info.Machine.MachineName,
                            events = info.Quality.EventsCollected,
                            size = DirectorySize(directory),
                            degraded = info.Quality.IsDegraded,
                            target = info.TargetPath,
                        });
                    }
                    catch (Exception ex) when (ex is IOException or Microsoft.Data.Sqlite.SqliteException)
                    {
                        // A session still being written, or one from a crashed run. It
                        // is not listable, but it is also not a reason to show nothing.
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // An unreadable session root lists as empty rather than as an error: the
            // operator is one click from choosing a different one.
        }

        Post("sessions", new { root, sessions = found });
    }

    private static long DirectorySize(string path)
    {
        try
        {
            return new DirectoryInfo(path)
                .EnumerateFiles("*", SearchOption.AllDirectories)
                .Sum(static f => f.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private void DeleteSession(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;

        string full = Path.GetFullPath(path);

        // The page asked for this by path, and a path is the one thing a page must never
        // be trusted with. It has to be a directory that actually holds a session, under
        // the configured session root — otherwise this method is a delete-anything
        // primitive reachable from rendered content.
        string root = Path.GetFullPath(_settings.SessionRoot ?? UserSettings.DefaultSessionRoot);
        bool underRoot = full.StartsWith(
            root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);

        if (!underRoot || !Directory.Exists(full) || !File.Exists(Path.Combine(full, SessionPaths.DatabaseName)))
        {
            Toast(Strings.Format("error.not_a_session", full), "error");
            return;
        }

        // Close it first: SQLite holds the file open, and on Windows a delete of an open
        // database fails rather than being deferred.
        if (string.Equals(_sessionPath, Path.Combine(full, SessionPaths.DatabaseName), StringComparison.OrdinalIgnoreCase))
        {
            _store?.Dispose();
            _store = null;
            _session = null;
            _sessionPath = null;
            ResetAssistant();
        }

        try
        {
            Directory.Delete(full, recursive: true);
            ListSessions(_settings.SessionRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Toast(ex.Message, "error");
        }
    }
}
