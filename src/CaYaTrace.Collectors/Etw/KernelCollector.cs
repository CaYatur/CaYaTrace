using System.Net;
using CaYaTrace.Core.Model;
using CaYaTrace.Core.Naming;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace CaYaTrace.Collectors.Etw;

public sealed class KernelCollectorOptions
{
    /// <summary>
    /// ETW buffer pool size. The default is deliberately large. An MSI install can
    /// emit six figures of file and registry events in a few seconds; with the stock
    /// buffer size the kernel starts discarding them, and a discarded <c>KCBCreate</c> or
    /// file-name event breaks path resolution for everything that follows. Memory is
    /// far cheaper than a session that quietly under-reports.
    /// </summary>
    public int BufferSizeMB { get; init; } = 256;

    public bool CollectFile { get; init; } = true;
    public bool CollectRegistry { get; init; } = true;
    public bool CollectNetwork { get; init; } = true;
    public bool CollectImageLoad { get; init; } = true;

    /// <summary>
    /// Record read operations. Off by default: reads are roughly an order of magnitude
    /// more numerous than writes and rarely change a conclusion, but they matter when
    /// profiling what an unknown binary is looking for.
    /// </summary>
    public bool CollectReads { get; init; }

    /// <summary>
    /// Capture registry value data by reading the key back when a set is observed.
    /// The provider reports that a value changed but never what it changed to.
    /// </summary>
    public bool CaptureRegistryValues { get; init; } = true;

    public static KernelCollectorOptions Default { get; } = new();
}

/// <summary>
/// The primary evidence source: a real-time kernel ETW session covering process,
/// thread, image, file, registry, and TCP/UDP activity.
/// </summary>
/// <remarks>
/// <para>
/// This is where the depth the project needs actually comes from, and it is also the
/// component with the most ways to be subtly wrong. Three of them are handled
/// explicitly here:
/// </para>
/// <list type="number">
///   <item><description>
///     <b>Names arrive separately from operations.</b> File and registry events carry
///     pointers; the names were announced earlier. Every handler routes through the
///     shared resolvers rather than reading a name field that is usually empty.
///   </description></item>
///   <item><description>
///     <b>PIDs are recycled.</b> Every event resolves its PID against the process
///     generation alive at that event's timestamp.
///   </description></item>
///   <item><description>
///     <b>The callback thread must never block.</b> Everything here is an in-memory
///     dictionary operation plus a non-blocking enqueue. Any stall causes kernel-level
///     event loss across all providers at once.
///   </description></item>
/// </list>
/// </remarks>
public sealed class KernelCollector : ICollector
{
    private readonly KernelCollectorOptions _options;
    private readonly string _sessionName;

    private TraceEventSession? _session;
    private Task? _processing;
    private CollectorContext? _ctx;
    private RegistryValueCapture? _valueCapture;
    private volatile bool _stopping;

    public KernelCollector(KernelCollectorOptions? options = null, string? sessionName = null)
    {
        _options = options ?? KernelCollectorOptions.Default;
        _sessionName = sessionName ?? $"CaYaTrace-Kernel-{Environment.ProcessId}";
    }

    public string Name => "kernel-etw";

    public bool RequiresElevation => true;

    /// <summary>Events the kernel discarded. Non-zero means the session is incomplete.</summary>
    public int EventsLost => _session?.EventsLost ?? 0;

    public Task<bool> StartAsync(CollectorContext context, CancellationToken cancellationToken)
    {
        _ctx = context;

        if (!TraceEventSession.IsElevated().GetValueOrDefault())
        {
            context.ReportSkipped(Name, "kernel tracing requires an elevated process");
            return Task.FromResult(false);
        }

        try
        {
            _session = CreateSession();
            _session.BufferSizeMB = _options.BufferSizeMB;
            _session.StopOnDispose = true;

            KernelTraceEventParser.Keywords keywords = BuildKeywords();
            _session.EnableKernelProvider(keywords, BuildStackKeywords());

            if (_options.CaptureRegistryValues)
                _valueCapture = context.RegistryValues;

            Subscribe(_session.Source, context);

            _processing = Task.Run(() =>
            {
                try
                {
                    _session.Source.Process();
                }
                catch (Exception ex) when (!_stopping)
                {
                    context.ReportFault(Name, "trace processing stopped unexpectedly", ex);
                }
            }, CancellationToken.None);

            context.Session.EnabledCollectors.Add(Name);
            return Task.FromResult(true);
        }
        catch (UnauthorizedAccessException ex)
        {
            context.ReportSkipped(Name, $"access denied starting kernel session: {ex.Message}");
            return Task.FromResult(false);
        }
        catch (Exception ex)
        {
            context.ReportFault(Name, "could not start kernel session", ex);
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Opens the kernel session, clearing anything we left behind first.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Windows 8 and later allow several concurrent kernel sessions under private
    /// names, which is what lets CaYaTrace run alongside another tracing tool.
    /// </para>
    /// <para>
    /// <b>ETW sessions outlive the process that created them.</b> If CaYaTrace is killed —
    /// by the analyst, by a crash, or by whatever is being analysed — the session stays
    /// registered with the kernel and keeps consuming buffers indefinitely. The next
    /// launch then fails to create a session with the same name. Sweeping our own
    /// orphans before starting turns a permanent failure into a non-event; sessions
    /// belonging to other tools are left strictly alone.
    /// </para>
    /// </remarks>
    private TraceEventSession CreateSession()
    {
        CleanUpOrphanedSessions();

        try
        {
            return new TraceEventSession(_sessionName);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            // A same-named session survived the sweep — most likely created by another
            // CaYaTrace instance that is still running. A unique name lets both coexist
            // rather than one silently displacing the other.
            return new TraceEventSession($"{_sessionName}-{Guid.NewGuid():N}"[..Math.Min(200, _sessionName.Length + 33)]);
        }
    }

    /// <summary>
    /// Stops kernel sessions this tool left registered by a previous run.
    /// </summary>
    /// <remarks>
    /// Matching is on our own name prefix only. Stopping a session we do not own would
    /// break whatever created it — potentially an EDR agent or another investigator's
    /// capture running on the same machine.
    /// </remarks>
    private static void CleanUpOrphanedSessions()
    {
        const string prefix = "CaYaTrace-Kernel-";

        IEnumerable<string> names;
        try { names = TraceEventSession.GetActiveSessionNames(); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            return;
        }

        foreach (string name in names)
        {
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;

            // A session belonging to a still-running instance must survive; only the
            // one matching this process id, or one whose owner is gone, is ours to stop.
            string suffix = name[prefix.Length..];
            int separator = suffix.IndexOf('-');
            string pidPart = separator < 0 ? suffix : suffix[..separator];

            if (int.TryParse(pidPart, out int ownerPid) && ownerPid != Environment.ProcessId && IsProcessAlive(ownerPid))
                continue;

            try { TraceEventSession.GetActiveSession(name)?.Stop(noThrow: true); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                // Another user's session with a colliding name. Not ours to touch.
            }
        }
    }

    private static bool IsProcessAlive(int pid)
    {
        try
        {
            using System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private KernelTraceEventParser.Keywords BuildKeywords()
    {
        // Process and thread are never optional: without them nothing can be
        // attributed, and every other keyword becomes an unlabelled pointer dump.
        KernelTraceEventParser.Keywords k =
            KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.Thread;

        if (_options.CollectImageLoad)
            k |= KernelTraceEventParser.Keywords.ImageLoad;

        if (_options.CollectFile)
        {
            // FileIOInit carries the create/delete/rename/set-info operations;
            // DiskFileIO carries the name and rundown events that make FileKey
            // lookups resolvable. FileIO adds read/write completions.
            k |= KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.DiskFileIO;
            if (_options.CollectReads) k |= KernelTraceEventParser.Keywords.FileIO;
        }

        if (_options.CollectRegistry)
            k |= KernelTraceEventParser.Keywords.Registry;

        if (_options.CollectNetwork)
            k |= KernelTraceEventParser.Keywords.NetworkTCPIP;

        return k;
    }

    /// <summary>
    /// Stack collection is off. Walking user-mode stacks on every file and registry
    /// operation multiplies event volume several times over and needs symbol
    /// resolution to be readable — a poor trade when the causal chain already comes
    /// from process lineage.
    /// </summary>
    private static KernelTraceEventParser.Keywords BuildStackKeywords()
        => KernelTraceEventParser.Keywords.None;

    private void Subscribe(ETWTraceEventSource source, CollectorContext ctx)
    {
        KernelTraceEventParser kernel = source.Kernel;

        SubscribeProcess(kernel, ctx);
        if (_options.CollectImageLoad) SubscribeImage(kernel, ctx);
        if (_options.CollectFile) SubscribeFile(kernel, ctx);
        if (_options.CollectRegistry) SubscribeRegistry(kernel, ctx);
        if (_options.CollectNetwork) SubscribeNetwork(kernel, ctx);
    }

    // ------------------------------------------------------------- process

    private void SubscribeProcess(KernelTraceEventParser kernel, CollectorContext ctx)
    {
        kernel.ProcessStart += data => OnProcessStart(data, ctx, preExisting: false);

        // DCStart is the rundown: every process already running when the session
        // opened. Without it, anything the target does through an existing process
        // is unattributed.
        kernel.ProcessDCStart += data => OnProcessStart(data, ctx, preExisting: true);

        kernel.ProcessStop += data =>
        {
            ProcessKey key = ResolveActor(ctx, data.ProcessID, data.TimeStamp);
            if (key == ProcessKey.None) return;

            ctx.Processes.MarkExit(key, data.TimeStamp, data.ExitStatus);
            ctx.Emit(new Observation
            {
                Timestamp = data.TimeStamp,
                Category = EventCategory.Process,
                Action = EventAction.Stop,
                Actor = key,
                ThreadId = (uint)data.ThreadID,
                Target = ctx.Paths.Tokenize(data.ImageFileName),
                NewValue = data.ExitStatus.ToString(),
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
                Status = EventStatus.Success,
            });
        };

        kernel.ThreadStart += data =>
        {
            ProcessKey owner = ResolveActor(ctx, data.ProcessID, data.TimeStamp);
            if (owner != ProcessKey.None) ctx.Processes.SetThreadOwner((uint)data.ThreadID, owner);

            // A thread created in a process other than its creator is process
            // injection — one of the highest-value signals this tool can produce, and
            // therefore one worth being strict about, because a false one at critical
            // severity sits at the top of every report and trains the reader to skip
            // the section.
            //
            // The exclusions here are the structural ones only — facts available at event
            // time that can never become truer later:
            //
            //   * A process id at or below 4. Those are the idle and system processes,
            //     where the kernel's own threads land. This produced
            //     "REMOTE THREAD Idle (0)" as the two highest-ranked findings of a
            //     252,000-event session.
            //
            //   * The initial thread of a process that has just started. Every process
            //     launch has its first thread created by the launcher, so this rule
            //     without the exclusion reports every CreateProcess as injection — five
            //     critical findings in a session whose subject started five programs,
            //     all of them ordinary.
            //
            //   * Either end unresolvable. Naming a process this session never saw start
            //     is a guess, and a guess at critical severity is worse than silence.
            //
            // Whether this is worth reporting is decided later, by the scorer, and
            // deliberately not here. The judgment needs code signatures, which are
            // verified on a background thread and are usually not populated yet at the
            // moment a thread starts — deciding here would be deciding on missing data.
            // Discarding here would also be permanent, and a suppression rule that turns
            // out to be wrong should be re-judgeable against a session already recorded.
            if (data.ProcessID > 4 && data.ParentProcessID > 4 && data.ParentProcessID != data.ProcessID)
            {
                ProcessKey injector = ResolveActor(ctx, data.ParentProcessID, data.TimeStamp);
                if (injector == ProcessKey.None || injector == owner) return;
                if (IsProcessStartup(ctx, owner, data.TimeStamp)) return;

                ProcessNode? injectorNode = ctx.Processes.Get(injector);
                ProcessNode? ownerNode = ctx.Processes.Get(owner);
                if (injectorNode is null || ownerNode is null) return;
                if (injectorNode.Pid <= 4 || ownerNode.Pid <= 4) return;

                ctx.Emit(new Observation
                {
                    Timestamp = data.TimeStamp,
                    Category = EventCategory.Process,
                    Action = EventAction.RemoteThread,
                    Actor = injector,
                    ThreadId = (uint)data.ThreadID,
                    Target = DescribeProcess(ctx, owner),
                    Target2 = $"0x{data.Win32StartAddr:x}",

                    // Carried so the finding can say who did it, not only to whom. An
                    // injection finding that names only the victim is half a sentence.
                    NewValue = $"{injectorNode.ImageName} ({injectorNode.Pid})",

                    // The owning process, in a form the scorer can look back up. Both
                    // ends have to be identifiable to judge whether this is Windows
                    // going about its business or something putting code where it does
                    // not belong.
                    Details = $"{{\"owner\":\"{owner}\"}}",
                    Source = EvidenceSource.KernelEtw,
                    Confidence = AttributionConfidence.Direct,
                    Status = EventStatus.Success,
                });
            }
        };

        kernel.ThreadDCStart += data =>
        {
            ProcessKey owner = ResolveActor(ctx, data.ProcessID, data.TimeStamp);
            if (owner != ProcessKey.None) ctx.Processes.SetThreadOwner((uint)data.ThreadID, owner);
        };

        kernel.ThreadStop += data => ctx.Processes.ClearThread((uint)data.ThreadID);
    }

    private void OnProcessStart(ProcessTraceData data, CollectorContext ctx, bool preExisting)
    {
        string image = ctx.Paths.Normalize(
            !string.IsNullOrEmpty(data.ImageFileName) ? data.ImageFileName : data.KernelImageFileName);

        var key = data.UniqueProcessKey != 0
            ? ProcessKey.FromStartKey((uint)data.ProcessID, data.UniqueProcessKey, data.TimeStamp)
            : ProcessKey.FromCreateTime((uint)data.ProcessID, data.TimeStamp);

        var node = new ProcessNode
        {
            Key = key,
            ParentPid = (uint)Math.Max(0, data.ParentID),
            ImagePath = image,
            CommandLine = string.IsNullOrWhiteSpace(data.CommandLine) ? null : data.CommandLine,
            SessionId = (uint)Math.Max(0, data.SessionID),
            StartTime = data.TimeStamp,
            PreExisting = preExisting,
            OriginId = ctx.OriginId,
        };

        ProcessNode stored = ctx.Processes.AddOrUpdate(node);

        // Rundown entries describe the past; emitting them as events would put a
        // fabricated "process started" at session start for every process on the box.
        if (preExisting) return;

        ctx.Emit(new Observation
        {
            Timestamp = data.TimeStamp,
            Category = EventCategory.Process,
            Action = EventAction.Start,
            Actor = stored.Key,
            ThreadId = (uint)data.ThreadID,
            Target = ctx.Paths.Tokenize(image),
            Target2 = stored.CommandLine,
            Source = EvidenceSource.KernelEtw,
            Confidence = AttributionConfidence.Direct,
            Status = EventStatus.Success,
        });

        ProcessMetadata.EnrichInBackground(stored, ctx);
    }

    // --------------------------------------------------------------- image

    private void SubscribeImage(KernelTraceEventParser kernel, CollectorContext ctx)
    {
        kernel.ImageLoad += data =>
        {
            ProcessKey actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp);
            if (actor == ProcessKey.None) return;

            string path = ctx.Paths.Normalize(data.FileName);
            if (path.Length == 0) return;

            ProcessNode? node = ctx.Processes.Get(actor);
            // A module is loaded once per process but the event repeats; dedupe here
            // rather than storing thousands of identical rows.
            if (node is not null && !node.LoadedModules.Add(path)) return;

            ctx.Emit(new Observation
            {
                Timestamp = data.TimeStamp,
                Category = EventCategory.Module,
                Action = EventAction.ImageLoad,
                Actor = actor,
                ThreadId = (uint)data.ThreadID,
                Target = ctx.Paths.Tokenize(path),
                Bytes = data.ImageSize,
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
                Status = EventStatus.Success,
            });
        };
    }

    // ---------------------------------------------------------------- file

    private void SubscribeFile(KernelTraceEventParser kernel, CollectorContext ctx)
    {
        // Name announcements. These make every later pointer-only event resolvable.
        kernel.FileIOName += data => ctx.Files.NoteName(data.FileKey, data.FileName);
        kernel.FileIOFileCreate += data => ctx.Files.NoteName(data.FileKey, data.FileName);
        kernel.FileIOFileRundown += data => ctx.Files.NoteName(data.FileKey, data.FileName);
        kernel.FileIOFileDelete += data => ctx.Files.NoteNameDelete(data.FileKey);

        kernel.FileIOCreate += data =>
        {
            ctx.Files.NoteOpen(data.FileObject, 0, data.FileName);

            ProcessKey actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp);
            string path = ctx.Paths.Normalize(data.FileName);
            if (path.Length == 0) return;

            // CreateDisposition distinguishes "opened an existing file" from
            // "brought a new file into existence" — only the latter is a system change
            // a removal plan should act on.
            bool creates = data.CreateDisposition is
                CreateDisposition.CREATE_NEW or
                CreateDisposition.CREATE_ALWAYS or
                CreateDisposition.OPEN_ALWAYS;

            bool isDirectory = (data.CreateOptions & CreateOptions.FILE_ATTRIBUTE_DIRECTORY) != 0
                               || (data.FileAttributes & FileAttributes.Directory) != 0;

            if (!creates && !_options.CollectReads) return;

            ctx.Emit(new Observation
            {
                Timestamp = data.TimeStamp,
                Category = EventCategory.File,
                Action = creates
                    ? (isDirectory ? EventAction.DirectoryCreate : EventAction.FileCreate)
                    : EventAction.FileOpen,
                Actor = actor,
                ThreadId = (uint)data.ThreadID,
                Target = ctx.Paths.Tokenize(path),
                Source = EvidenceSource.KernelEtw,
                Confidence = actor == ProcessKey.None ? AttributionConfidence.None : AttributionConfidence.Direct,
                Status = EventStatus.Success,
            });
        };

        kernel.FileIOWrite += data =>
        {
            var template = new Observation
            {
                Timestamp = data.TimeStamp,
                Category = EventCategory.File,
                Action = EventAction.FileWrite,
                Actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp),
                ThreadId = (uint)data.ThreadID,
                Bytes = data.IoSize,
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
                Status = EventStatus.Success,
            };

            if (!ctx.Files.TryResolve(data.FileObject, data.FileKey, data.FileName, out string path))
            {
                Defer(ctx, template, data.FileObject, data.FileKey, null, isRegistry: false);
                return;
            }

            ctx.Files.NoteResolved();
            ctx.Emit(template with { Target = ctx.Paths.Tokenize(path) });
        };

        if (_options.CollectReads)
        {
            kernel.FileIORead += data =>
            {
                // Same reasoning as RegistryOpen: park it rather than discard it, so a
                // name that only arrives with the rundown still finds its operation.
                if (!ctx.Files.TryResolve(data.FileObject, data.FileKey, data.FileName, out string path))
                {
                    Defer(ctx, new Observation
                    {
                        Timestamp = data.TimeStamp,
                        Category = EventCategory.File,
                        Action = EventAction.FileRead,
                        Actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp),
                        ThreadId = (uint)data.ThreadID,
                        Bytes = data.IoSize,
                        Source = EvidenceSource.KernelEtw,
                        Confidence = AttributionConfidence.Direct,
                        Status = StatusOf(0),
                    }, data.FileObject, data.FileKey, null, isRegistry: false);
                    return;
                }

                ctx.Files.NoteReadResolved();

                ctx.Emit(new Observation
                {
                    Timestamp = data.TimeStamp,
                    Category = EventCategory.File,
                    Action = EventAction.FileRead,
                    Actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp),
                    ThreadId = (uint)data.ThreadID,
                    Target = ctx.Paths.Tokenize(path),
                    Bytes = data.IoSize,
                    Source = EvidenceSource.KernelEtw,
                    Confidence = AttributionConfidence.Direct,
                });
            };
        }

        kernel.FileIODelete += data =>
        {
            var template = new Observation
            {
                Timestamp = data.TimeStamp,
                Category = EventCategory.File,
                Action = EventAction.FileDelete,
                Actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp),
                ThreadId = (uint)data.ThreadID,
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
                Status = EventStatus.Success,
            };

            if (!ctx.Files.TryResolve(data.FileObject, data.FileKey, data.FileName, out string path))
            {
                Defer(ctx, template, data.FileObject, data.FileKey, null, isRegistry: false);
                return;
            }

            ctx.Files.NoteResolved();
            ctx.Emit(template with { Target = ctx.Paths.Tokenize(path) });
        };

        kernel.FileIORename += data =>
        {
            // The rename event names the destination; the source is whatever the
            // object resolved to before we applied the change.
            string oldPath = ctx.Files.Resolve(data.FileObject, data.FileKey);
            string newPath = ctx.Paths.Normalize(data.FileName);
            if (oldPath.Length == 0 && newPath.Length == 0) return;

            if (newPath.Length > 0)
                ctx.Files.ApplyRename(data.FileObject, data.FileKey, newPath);

            ctx.Emit(new Observation
            {
                Timestamp = data.TimeStamp,
                Category = EventCategory.File,
                Action = EventAction.FileRename,
                Actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp),
                ThreadId = (uint)data.ThreadID,
                Target = ctx.Paths.Tokenize(oldPath.Length > 0 ? oldPath : newPath),
                Target2 = ctx.Paths.Tokenize(newPath),
                OldValue = oldPath.Length > 0 ? ctx.Paths.Tokenize(oldPath) : null,
                NewValue = newPath.Length > 0 ? ctx.Paths.Tokenize(newPath) : null,
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
                Status = EventStatus.Success,
            });
        };

        kernel.FileIOSetInfo += data =>
        {
            string path = ctx.Files.Resolve(data.FileObject, data.FileKey, data.FileName);
            if (path.Length == 0) return;

            ctx.Emit(new Observation
            {
                Timestamp = data.TimeStamp,
                Category = EventCategory.File,
                Action = EventAction.FileSetInfo,
                Actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp),
                ThreadId = (uint)data.ThreadID,
                Target = ctx.Paths.Tokenize(path),
                Target2 = FileInfoClass.Describe(data.InfoClass),
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
            });
        };

        // Cleanup precedes close and is the point the handle stops being usable.
        kernel.FileIOCleanup += data => ctx.Files.NoteClose(data.FileObject);
        kernel.FileIOClose += data => ctx.Files.NoteClose(data.FileObject);
    }

    // ------------------------------------------------------------ registry

    private void SubscribeRegistry(KernelTraceEventParser kernel, CollectorContext ctx)
    {
        // Key-control-block announcements. Everything else depends on these.
        kernel.RegistryKCBCreate += data => ctx.Registry.NoteKcb(data.KeyHandle, data.KeyName);
        kernel.RegistryKCBRundownBegin += data => ctx.Registry.NoteKcb(data.KeyHandle, data.KeyName);
        kernel.RegistryKCBRundownEnd += data => ctx.Registry.NoteKcb(data.KeyHandle, data.KeyName);
        kernel.RegistryKCBDelete += data => ctx.Registry.NoteKcbDelete(data.KeyHandle);

        kernel.RegistryCreate += data =>
            EmitRegistry(ctx, data, EventAction.KeyCreate);

        kernel.RegistrySetValue += data =>
        {
            var template = new Observation
            {
                Timestamp = data.TimeStamp,
                Category = EventCategory.Registry,
                Action = EventAction.ValueSet,
                Actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp),
                ThreadId = (uint)data.ThreadID,
                Target2 = string.IsNullOrEmpty(data.ValueName) ? "(Default)" : data.ValueName,
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
                Status = StatusOf(data.Status),
            };

            // Value data must be read now or not at all: by the time the end-of-session
            // rundown could name this key, the data may have changed again or the key
            // may be gone. A deferred write therefore keeps its name but loses its
            // before/after data — which is why the value capture is attempted eagerly.
            if (!ctx.Registry.TryResolve(data.KeyHandle, data.KeyName, out string path))
            {
                Defer(ctx, template, data.KeyHandle, 0, data.KeyName, isRegistry: true);
                return;
            }

            ctx.Registry.NoteResolved();

            // The provider reports that a value was set but never the data. Reading it
            // back is the only way to answer "changed from what, to what" — see
            // RegistryValueCapture for why the answer is best-effort.
            (string? before, string? after) = _valueCapture?.Capture(path, data.ValueName) ?? (null, null);

            ctx.Emit(template with { Target = path, OldValue = before, NewValue = after });
        };

        kernel.RegistryDeleteValue += data =>
        {
            var template = new Observation
            {
                Timestamp = data.TimeStamp,
                Category = EventCategory.Registry,
                Action = EventAction.ValueDelete,
                Actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp),
                ThreadId = (uint)data.ThreadID,
                Target2 = string.IsNullOrEmpty(data.ValueName) ? "(Default)" : data.ValueName,
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
                Status = StatusOf(data.Status),
            };

            if (!ctx.Registry.TryResolve(data.KeyHandle, data.KeyName, out string path))
            {
                Defer(ctx, template, data.KeyHandle, 0, data.KeyName, isRegistry: true);
                return;
            }

            ctx.Registry.NoteResolved();
            ctx.Emit(template with
            {
                Target = path,
                OldValue = _valueCapture?.ReadCurrent(path, data.ValueName),
            });
        };

        kernel.RegistryDelete += data => EmitRegistry(ctx, data, EventAction.KeyDelete);

        kernel.RegistrySetInformation += data => EmitRegistry(ctx, data, EventAction.KeySetSecurity);

        if (_options.CollectReads)
        {
            // Parked like everything else when the key has no name yet, rather than
            // resolved-or-dropped on the spot. Measured: a session recording reads
            // reported 35% of registry operations resolved, and almost all of the
            // shortfall was reads being discarded at this line — evidence thrown away,
            // and a data-quality figure that alarmed the operator about the wrong thing.
            kernel.RegistryOpen += data => EmitRegistry(ctx, data, EventAction.KeyOpen);
        }
    }

    /// <summary>
    /// Emits a registry operation, parking it if its key has no name yet.
    /// </summary>
    private void EmitRegistry(CollectorContext ctx, RegistryTraceData data, EventAction action)
    {
        var template = new Observation
        {
            Timestamp = data.TimeStamp,
            Category = EventCategory.Registry,
            Action = action,
            Actor = ResolveActor(ctx, data.ProcessID, data.TimeStamp),
            ThreadId = (uint)data.ThreadID,
            Source = EvidenceSource.KernelEtw,
            Confidence = AttributionConfidence.Direct,
            Status = StatusOf(data.Status),
        };

        if (!ctx.Registry.TryResolve(data.KeyHandle, data.KeyName, out string path))
        {
            Defer(ctx, template, data.KeyHandle, 0, data.KeyName, isRegistry: true);
            return;
        }

        // A read that resolved and a change that resolved are counted apart, so the
        // session's quality figure answers "is the evidence complete" rather than
        // "how much of everything the machine did could be named".
        if (action.IsPersistentChange()) ctx.Registry.NoteResolved();
        else ctx.Registry.NoteReadResolved();

        ctx.Emit(template with { Target = path });
    }

    // ------------------------------------------------- deferred resolution

    /// <summary>
    /// An operation whose object had no name yet, held until one arrives.
    /// </summary>
    private readonly record struct Deferred(
        Observation Template, ulong Handle, ulong SecondaryHandle, string? RelativeName, bool IsRegistry);

    /// <summary>
    /// Operations parked awaiting a name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists because of a timing property of the kernel providers that is easy to
    /// miss and quietly halves the tool's output. The file-name and key-control-block
    /// <em>rundowns</em> — the events that announce what every already-open handle refers to —
    /// are delivered when the session <b>stops</b>, not when it starts. Measured on a live
    /// system: 68,258 <c>FileIO/FileRundown</c> and 6,718 <c>Registry/KCBRundownEnd</c> events, all
    /// at the end, and not a single <c>Registry/KCBCreate</c> during the run.
    /// </para>
    /// <para>
    /// So during collection only objects opened <em>after</em> we started can be named — which
    /// happens to cover the subject we launch suspended, but not the handles it inherited
    /// or that already existed. Resolving eagerly and discarding the rest threw away
    /// roughly 80% of file operations and 95% of registry operations.
    /// </para>
    /// <para>
    /// Parking them and re-resolving once the rundown has been consumed recovers that.
    /// The buffer is bounded: past the cap, operations are counted as unresolved rather
    /// than allowed to grow without limit.
    /// </para>
    /// </remarks>
    private readonly List<Deferred> _deferred = new();

    /// <summary>
    /// How many operations may wait for the end-of-session rundown to name them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A key or file whose control block was created before recording started has no name
    /// until the rundown announces it, so the operation is parked and re-resolved at the
    /// end. Parking is memory; the cap is where that stops.
    /// </para>
    /// <para>
    /// Raised from 200,000 after a real session on someone else's machine reported
    /// <b>59.7% of registry operations unresolved</b>. The buffer had filled and everything
    /// after it was discarded — and it filled because that session was recording reads,
    /// which outnumber writes by roughly an order of magnitude.
    /// </para>
    /// </remarks>
    private const int MaxDeferredChanges = 1_500_000;

    /// <summary>
    /// Reads get their own, much smaller allowance.
    /// </summary>
    /// <remarks>
    /// This is the important half of the fix. A read that cannot be named is close to
    /// worthless — it says something looked at something. A <em>write</em> that cannot be named
    /// is evidence that has been lost. Sharing one buffer meant a flood of reads could
    /// push out the writes, which is exactly the wrong way round.
    /// </remarks>
    private const int MaxDeferredReads = 400_000;

    private long _deferredDropped;
    private long _deferredReadsDropped;
    private int _deferredReadCount;

    private void Defer(CollectorContext ctx, Observation template, ulong handle, ulong secondary, string? relative, bool isRegistry)
    {
        // ETW delivers on a single processing thread per session, so no lock is needed
        // between here and the flush, which runs after that thread has finished.
        bool isChange = template.Action.IsPersistentChange();

        if (!isChange)
        {
            if (_deferredReadCount >= MaxDeferredReads)
            {
                _deferredReadsDropped++;
                if (isRegistry) ctx.Registry.NoteReadPartial();
                else ctx.Files.NoteReadUnresolved();
                return;
            }

            _deferredReadCount++;
        }
        else if (_deferred.Count - _deferredReadCount >= MaxDeferredChanges)
        {
            _deferredDropped++;
            if (isRegistry) ctx.Registry.NotePartial();
            else ctx.Files.NoteUnresolved();
            return;
        }

        _deferred.Add(new Deferred(template, handle, secondary, relative, isRegistry));
    }

    /// <summary>
    /// Re-resolves everything parked, now that the end-of-session rundown has populated
    /// the name maps. Runs after trace processing has finished.
    /// </summary>
    private void FlushDeferred(CollectorContext ctx)
    {
        int recovered = 0;

        foreach (Deferred item in _deferred)
        {
            bool ok = item.IsRegistry
                ? ctx.Registry.TryResolve(item.Handle, item.RelativeName, out string path)
                : ctx.Files.TryResolve(item.Handle, item.SecondaryHandle, null, out path);

            bool isChange = item.Template.Action.IsPersistentChange();

            if (!ok)
            {
                if (item.IsRegistry)
                {
                    if (isChange) ctx.Registry.NotePartial();
                    else ctx.Registry.NoteReadPartial();
                }
                else if (isChange) ctx.Files.NoteUnresolved();
                else ctx.Files.NoteReadUnresolved();
                continue;
            }

            if (item.IsRegistry)
            {
                if (isChange) ctx.Registry.NoteResolved();
                else ctx.Registry.NoteReadResolved();
            }
            else if (isChange) ctx.Files.NoteResolved();
            else ctx.Files.NoteReadResolved();

            ctx.Emit(item.Template with
            {
                Target = item.IsRegistry ? path : ctx.Paths.Tokenize(path),
            });
            recovered++;
        }

        int parked = _deferred.Count;
        _deferred.Clear();
        _deferredReadCount = 0;

        if (parked > 0)
        {
            ctx.Store.LogQuality(Name, "info",
                $"resolved {recovered:N0} of {parked:N0} operations from the end-of-session rundown");
        }

        // Said separately, because the two mean different things to a reader. Losing
        // reads narrows what the session can say about what a program looked at; losing
        // changes means evidence of what it did is gone.
        if (_deferredDropped > 0)
        {
            ctx.Store.LogQuality(Name, "warning",
                $"{_deferredDropped:N0} changes were discarded unresolved because the buffer for them was full. "
                + "Record for a shorter period, or narrow the categories, to keep all of them.");
        }

        if (_deferredReadsDropped > 0)
        {
            ctx.Store.LogQuality(Name, "info",
                $"{_deferredReadsDropped:N0} read operations were discarded unresolved. Reads are dropped "
                + "before changes are, so this does not mean any change was lost.");
        }
    }

    // ------------------------------------------------------------- network

    private void SubscribeNetwork(KernelTraceEventParser kernel, CollectorContext ctx)
    {
        kernel.TcpIpConnect += data => OnConnect(ctx, data.TimeStamp, data.ProcessID, data.ThreadID,
            data.saddr, (ushort)data.sport, data.daddr, (ushort)data.dport, TransportProtocol.Tcp);

        kernel.TcpIpConnectIPV6 += data => OnConnect(ctx, data.TimeStamp, data.ProcessID, data.ThreadID,
            data.saddr, (ushort)data.sport, data.daddr, (ushort)data.dport, TransportProtocol.Tcp);

        kernel.TcpIpAccept += data => OnAccept(ctx, data.TimeStamp, data.ProcessID, data.ThreadID,
            data.saddr, (ushort)data.sport, data.daddr, (ushort)data.dport);

        kernel.TcpIpAcceptIPV6 += data => OnAccept(ctx, data.TimeStamp, data.ProcessID, data.ThreadID,
            data.saddr, (ushort)data.sport, data.daddr, (ushort)data.dport);

        kernel.TcpIpSend += data => OnTransfer(ctx, data.TimeStamp, data.ProcessID,
            data.saddr, (ushort)data.sport, data.daddr, (ushort)data.dport,
            TransportProtocol.Tcp, sent: data.size, received: 0);

        kernel.TcpIpRecv += data => OnTransfer(ctx, data.TimeStamp, data.ProcessID,
            data.daddr, (ushort)data.dport, data.saddr, (ushort)data.sport,
            TransportProtocol.Tcp, sent: 0, received: data.size);

        kernel.TcpIpDisconnect += data =>
        {
            var key = new FlowKey(TransportProtocol.Tcp, data.saddr, (ushort)data.sport, data.daddr, (ushort)data.dport);
            ctx.Flows.NoteClose(key, data.TimeStamp);
        };

        kernel.UdpIpSend += data => OnTransfer(ctx, data.TimeStamp, data.ProcessID,
            data.saddr, (ushort)data.sport, data.daddr, (ushort)data.dport,
            TransportProtocol.Udp, sent: data.size, received: 0);

        kernel.UdpIpRecv += data => OnTransfer(ctx, data.TimeStamp, data.ProcessID,
            data.daddr, (ushort)data.dport, data.saddr, (ushort)data.sport,
            TransportProtocol.Udp, sent: 0, received: data.size);
    }

    private static void OnConnect(CollectorContext ctx, DateTimeOffset ts, int pid, int tid,
        IPAddress local, ushort localPort, IPAddress remote, ushort remotePort, TransportProtocol protocol)
    {
        ProcessKey actor = ResolveActor(ctx, pid, ts);
        var key = new FlowKey(protocol, local, localPort, remote, remotePort);
        ctx.Flows.NoteConnect(key, actor, ts);

        ctx.Emit(new Observation
        {
            Timestamp = ts,
            Category = EventCategory.Network,
            Action = EventAction.Connect,
            Actor = actor,
            ThreadId = (uint)tid,
            Target = FlowKey.Format(remote, remotePort),
            Target2 = FlowKey.Format(local, localPort),
            Source = EvidenceSource.KernelEtw,
            Confidence = AttributionConfidence.Direct,
            Status = EventStatus.Success,
        });
    }

    private static void OnAccept(CollectorContext ctx, DateTimeOffset ts, int pid, int tid,
        IPAddress local, ushort localPort, IPAddress remote, ushort remotePort)
    {
        ProcessKey actor = ResolveActor(ctx, pid, ts);
        var key = new FlowKey(TransportProtocol.Tcp, local, localPort, remote, remotePort);
        ctx.Flows.NoteConnect(key, actor, ts, "kernel-network-accept");

        ctx.Emit(new Observation
        {
            Timestamp = ts,
            Category = EventCategory.Network,
            Action = EventAction.Accept,
            Actor = actor,
            ThreadId = (uint)tid,
            Target = FlowKey.Format(remote, remotePort),
            Target2 = FlowKey.Format(local, localPort),
            Source = EvidenceSource.KernelEtw,
            Confidence = AttributionConfidence.Direct,
            Status = EventStatus.Success,
        });
    }

    /// <summary>
    /// Per-packet send/receive events are folded into the flow rather than stored
    /// individually. A single file download would otherwise produce hundreds of
    /// thousands of rows that say nothing the byte totals do not.
    /// </summary>
    private static void OnTransfer(CollectorContext ctx, DateTimeOffset ts, int pid,
        IPAddress local, ushort localPort, IPAddress remote, ushort remotePort,
        TransportProtocol protocol, int sent, int received)
    {
        var key = new FlowKey(protocol, local, localPort, remote, remotePort);
        ctx.Flows.NoteBytes(key, ts, sent, received, sent > 0 ? 1 : 0, received > 0 ? 1 : 0);

        NetworkFlow? flow = ctx.Flows.Find(key);
        if (flow is { Owner.IsNone: true } or null)
        {
            ProcessKey actor = ResolveActor(ctx, pid, ts);
            if (actor != ProcessKey.None)
                ctx.Flows.NoteConnect(key, actor, ts, "kernel-network-transfer");
        }
    }

    // --------------------------------------------------------------- shared

    private static ProcessKey ResolveActor(CollectorContext ctx, int pid, DateTimeOffset at)
        => pid <= 0 ? ProcessKey.None : ctx.Processes.Resolve((uint)pid, at);

    private static string DescribeProcess(CollectorContext ctx, ProcessKey key)
    {
        ProcessNode? node = ctx.Processes.Get(key);
        return node is null ? key.ToString() : $"{node.ImageName} ({node.Pid})";
    }

    /// <summary>
    /// True when a thread is one a process was born with rather than one injected into
    /// it later.
    /// </summary>
    /// <remarks>
    /// Decided on age rather than on thread ordering, because thread events arrive
    /// interleaved and a rundown can deliver an existing thread at any point. A window
    /// of a quarter second is generously longer than the gap between a process start
    /// event and its initial thread event, and far shorter than the time it takes an
    /// operator to launch something and a second program to then inject into it.
    /// </remarks>
    private static bool IsProcessStartup(CollectorContext ctx, ProcessKey owner, DateTimeOffset when)
    {
        ProcessNode? node = ctx.Processes.Get(owner);

        // Unknown process: the safer reading is that this is a start we have not seen
        // yet, not an injection into something we cannot name.
        if (node is null) return true;

        TimeSpan age = when - node.StartTime;
        return age >= TimeSpan.Zero && age < TimeSpan.FromMilliseconds(250);
    }

    private static EventStatus StatusOf(int ntStatus) => ntStatus switch
    {
        0 => EventStatus.Success,
        unchecked((int)0xC0000022) => EventStatus.AccessDenied, // STATUS_ACCESS_DENIED
        _ => ntStatus < 0 ? EventStatus.Failed : EventStatus.Success,
    };

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _stopping = true;

        // EventsLost must be read while the session is still registered. After Stop the
        // underlying query fails with 0x80071069, so reading it later would replace a
        // real number with an exception.
        if (_ctx is not null && _session is not null)
        {
            int lost = 0;
            try { lost = _session.EventsLost; }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException) { }

            _ctx.Quality.EventsLost += lost;
            if (lost > 0)
            {
                _ctx.Store.LogQuality(Name, "warning",
                    $"{lost} events lost to buffer pressure; " +
                    "increase BufferSizeMB or narrow the collected keywords");
            }
        }

        try { _session?.Stop(); }
        catch (Exception ex) { _ctx?.ReportFault(Name, "failed to stop session cleanly", ex); }

        if (_processing is not null)
        {
            // Source.Process() returns once the session stops — and stopping is what
            // makes the kernel emit the file-name and key-control-block rundowns. The
            // wait is therefore not just for tidiness: those events are what make the
            // deferred operations resolvable. The timeout is generous because a busy
            // machine can produce tens of thousands of rundown records.
            await Task.WhenAny(_processing, Task.Delay(TimeSpan.FromSeconds(60), cancellationToken))
                .ConfigureAwait(false);
        }

        // Now that the rundown has been consumed, everything parked for want of a name
        // gets a second chance.
        if (_ctx is not null) FlushDeferred(_ctx);
    }

    public async ValueTask DisposeAsync()
    {
        if (!_stopping)
        {
            try { await StopAsync(CancellationToken.None).ConfigureAwait(false); }
            catch (Exception) { /* disposal must not throw */ }
        }
        _session?.Dispose();
    }
}

/// <summary>Human-readable names for the NT file information classes.</summary>
internal static class FileInfoClass
{
    public static string Describe(int infoClass) => infoClass switch
    {
        4 => "BasicInformation",
        10 => "RenameInformation",
        13 => "DispositionInformation (delete-on-close)",
        14 => "PositionInformation",
        19 => "AllocationInformation",
        20 => "EndOfFileInformation",
        _ => $"InfoClass {infoClass}",
    };
}
