using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using CaYaTrace.Core.Model;

namespace CaYaTrace.Storage;

public sealed class ObservationSinkOptions
{
    /// <summary>
    /// Events held in memory between the collectors and the writer. Sized to absorb
    /// the burst an MSI install produces (tens of thousands of events in a couple of
    /// seconds) without blocking an ETW callback, which would cause the kernel to
    /// drop events wholesale.
    /// </summary>
    public int QueueCapacity { get; init; } = 262_144;

    /// <summary>Rows per transaction. Larger batches trade latency for throughput.</summary>
    public int BatchSize { get; init; } = 4_096;

    /// <summary>Longest a partial batch waits before being flushed anyway.</summary>
    public TimeSpan FlushInterval { get; init; } = TimeSpan.FromMilliseconds(400);

    /// <summary>
    /// Mirror every observation to an append-only JSONL file. Costs disk but means a
    /// hard kill (or a crash caused by whatever is being analysed) still leaves usable
    /// evidence, since SQLite's last uncommitted transaction would otherwise be lost.
    /// </summary>
    public bool WriteRawJournal { get; init; } = true;

    public static ObservationSinkOptions Default { get; } = new();
}

/// <summary>
/// The write path from collectors to disk.
/// </summary>
/// <remarks>
/// <para>
/// Nothing on a collection thread is allowed to touch SQLite. ETW delivers events on a
/// dedicated processing thread per session, and any stall there — a lock, a page fault,
/// a transaction commit — causes the kernel to fill its buffers and start discarding
/// events. Those losses are unrecoverable and, worse, silent. So collectors do a
/// non-blocking enqueue and a background writer does everything expensive.
/// </para>
/// <para>
/// When the queue does fill, the sink drops the newest event and counts it rather than
/// applying back-pressure. Blocking would convert a storage stall into kernel-level
/// event loss across every provider, which is a strictly worse failure. The drop count
/// is surfaced in <see cref="DataQuality"/>, so a session that lost data says so.
/// </para>
/// </remarks>
public sealed class ObservationSink : IAsyncDisposable
{
    private readonly SessionStore _store;
    private readonly ObservationSinkOptions _options;
    private readonly Channel<Observation> _channel;
    private readonly Task _writer;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly StreamWriter? _journal;
    private readonly object _journalGate = new();

    private long _accepted;
    private long _dropped;
    private long _written;

    public ObservationSink(SessionStore store, string sessionDirectory, ObservationSinkOptions? options = null)
    {
        _store = store;
        _options = options ?? ObservationSinkOptions.Default;

        _channel = Channel.CreateBounded<Observation>(new BoundedChannelOptions(_options.QueueCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropWrite,
            AllowSynchronousContinuations = false,
        });

        if (_options.WriteRawJournal)
        {
            Directory.CreateDirectory(sessionDirectory);
            var stream = new FileStream(
                Path.Combine(sessionDirectory, "raw-events.jsonl"),
                FileMode.Append, FileAccess.Write, FileShare.Read,
                bufferSize: 1 << 16, FileOptions.SequentialScan);
            _journal = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = false };
        }

        _writer = Task.Run(DrainAsync);
    }

    public long Accepted => Interlocked.Read(ref _accepted);
    public long Dropped => Interlocked.Read(ref _dropped);
    public long Written => Interlocked.Read(ref _written);

    /// <summary>Depth of the pending queue. A persistently high value means storage is losing the race.</summary>
    public int QueueDepth => _channel.Reader.Count;

    /// <summary>
    /// Enqueues an observation, assigning its sequence number. Never blocks and never
    /// throws; a full queue increments <see cref="Dropped"/> instead.
    /// </summary>
    public void Write(Observation observation)
    {
        Observation stamped = observation.Seq != 0
            ? observation
            : observation with { Seq = _store.NextSequence() };

        if (_channel.Writer.TryWrite(stamped))
            Interlocked.Increment(ref _accepted);
        else
            Interlocked.Increment(ref _dropped);
    }

    /// <summary>Blocks until everything currently queued has reached disk.</summary>
    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        while (_channel.Reader.Count > 0 && !cancellationToken.IsCancellationRequested)
            await Task.Delay(25, cancellationToken).ConfigureAwait(false);

        lock (_journalGate) _journal?.Flush();
    }

    private async Task DrainAsync()
    {
        var batch = new List<Observation>(_options.BatchSize);
        CancellationToken token = _shutdown.Token;

        try
        {
            while (await _channel.Reader.WaitToReadAsync(token).ConfigureAwait(false))
            {
                DateTimeOffset deadline = DateTimeOffset.UtcNow + _options.FlushInterval;

                while (batch.Count < _options.BatchSize && _channel.Reader.TryRead(out Observation? item))
                {
                    batch.Add(item);
                    if (DateTimeOffset.UtcNow >= deadline) break;
                }

                if (batch.Count > 0)
                {
                    Persist(batch);
                    batch.Clear();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown requested. Drain whatever is still queued before returning:
            // these are events already accepted from collectors and losing them here
            // would be our own fault rather than the kernel's.
        }
        finally
        {
            while (_channel.Reader.TryRead(out Observation? item))
            {
                batch.Add(item);
                if (batch.Count >= _options.BatchSize)
                {
                    Persist(batch);
                    batch.Clear();
                }
            }
            if (batch.Count > 0) Persist(batch);

            lock (_journalGate)
            {
                _journal?.Flush();
                _journal?.Dispose();
            }
        }
    }

    private void Persist(List<Observation> batch)
    {
        // The journal is written first: it is the cheaper, more durable of the two,
        // so if the process dies mid-batch the raw record still exists.
        if (_journal is not null)
        {
            lock (_journalGate)
            {
                foreach (Observation o in batch)
                    _journal.WriteLine(JsonSerializer.Serialize(o, SessionStore.JsonOptions));
                _journal.Flush();
            }
        }

        try
        {
            _store.WriteObservationBatch(batch);
            Interlocked.Add(ref _written, batch.Count);
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException)
        {
            // A failed batch must not take the writer loop down; the journal already
            // holds this data and the session is marked degraded.
            Interlocked.Add(ref _dropped, batch.Count);
            try { _store.LogQuality("sink", "error", $"batch write failed: {ex.Message}"); }
            catch (Exception) { /* the store itself is unhealthy; nothing further to do */ }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _channel.Writer.TryComplete();
        _shutdown.Cancel();
        try { await _writer.ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        _shutdown.Dispose();
    }
}
