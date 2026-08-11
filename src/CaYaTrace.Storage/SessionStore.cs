using System.Data;
using System.Globalization;
using System.Net;
using System.Text.Json;
using CaYaTrace.Core.Model;
using Microsoft.Data.Sqlite;

namespace CaYaTrace.Storage;

/// <summary>
/// Read/write access to one session's evidence database.
/// </summary>
/// <remarks>
/// Writes go through <see cref="ObservationSink"/>, which batches them off the
/// collection threads; this class owns the connection and the SQL. Reads are issued
/// directly by the UI and export layers.
/// </remarks>
public sealed class SessionStore : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly object _writeGate = new();
    private long _nextSeq;

    public string Path { get; }

    private SessionStore(SqliteConnection connection, string path)
    {
        _connection = connection;
        Path = path;
    }

    public static SessionStore Create(string path)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        var store = Open(path);
        using SqliteCommand cmd = store._connection.CreateCommand();
        cmd.CommandText = SessionSchema.Create;
        cmd.ExecuteNonQuery();
        store.SetMeta("schema_version", SessionSchema.Version.ToString(CultureInfo.InvariantCulture));
        return store;
    }

    public static SessionStore Open(string path)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        };

        var connection = new SqliteConnection(builder.ToString());
        connection.Open();

        using (SqliteCommand pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;";
            pragma.ExecuteNonQuery();
        }

        var store = new SessionStore(connection, path);
        store._nextSeq = store.QueryScalarLong("SELECT COALESCE(MAX(seq), 0) FROM observations") + 1;
        return store;
    }

    /// <summary>Allocates the next observation sequence number. Thread-safe.</summary>
    public long NextSequence() => Interlocked.Increment(ref _nextSeq) - 1;

    // ---------------------------------------------------------------- metadata

    public void SetMeta(string key, string? value)
    {
        lock (_writeGate)
        {
            using SqliteCommand cmd = _connection.CreateCommand();
            cmd.CommandText = "INSERT INTO meta(key,value) VALUES($k,$v) ON CONFLICT(key) DO UPDATE SET value=$v";
            cmd.Parameters.AddWithValue("$k", key);
            cmd.Parameters.AddWithValue("$v", (object?)value ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }
    }

    public string? GetMeta(string key)
    {
        using SqliteCommand cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT value FROM meta WHERE key=$k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void SaveSessionInfo(SessionInfo info)
        => SetMeta("session", JsonSerializer.Serialize(info, JsonOptions));

    public SessionInfo? LoadSessionInfo()
    {
        string? json = GetMeta("session");
        return json is null ? null : JsonSerializer.Deserialize<SessionInfo>(json, JsonOptions);
    }

    // --------------------------------------------------------------- processes

    public void UpsertProcesses(IEnumerable<ProcessNode> nodes)
    {
        lock (_writeGate)
        {
            using SqliteTransaction tx = _connection.BeginTransaction();
            using SqliteCommand cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO processes
                    (key,pid,start_key,parent_key,parent_pid,image_path,command_line,working_dir,
                     user_sid,user_name,win_session,start_time,exit_time,exit_code,integrity,elevated,
                     signature,signer,sha256,image_size,in_scope,scope_reason,pre_existing,origin_id)
                VALUES
                    ($key,$pid,$sk,$pkey,$ppid,$img,$cmd,$wd,$sid,$user,$wsess,$start,$exit,$code,
                     $integ,$elev,$sig,$signer,$sha,$size,$scope,$reason,$pre,$origin)
                ON CONFLICT(key) DO UPDATE SET
                    parent_key   = COALESCE(excluded.parent_key, parent_key),
                    image_path   = COALESCE(NULLIF(excluded.image_path,''), image_path),
                    command_line = COALESCE(excluded.command_line, command_line),
                    working_dir  = COALESCE(excluded.working_dir, working_dir),
                    user_sid     = COALESCE(excluded.user_sid, user_sid),
                    user_name    = COALESCE(excluded.user_name, user_name),
                    exit_time    = COALESCE(excluded.exit_time, exit_time),
                    exit_code    = COALESCE(excluded.exit_code, exit_code),
                    signature    = MAX(excluded.signature, signature),
                    signer       = COALESCE(excluded.signer, signer),
                    sha256       = COALESCE(excluded.sha256, sha256),
                    image_size   = MAX(excluded.image_size, image_size),
                    in_scope     = MAX(excluded.in_scope, in_scope),
                    scope_reason = COALESCE(excluded.scope_reason, scope_reason)
                """;

            SqliteParameter key = cmd.Parameters.Add("$key", SqliteType.Text);
            SqliteParameter pid = cmd.Parameters.Add("$pid", SqliteType.Integer);
            SqliteParameter sk = cmd.Parameters.Add("$sk", SqliteType.Integer);
            SqliteParameter pkey = cmd.Parameters.Add("$pkey", SqliteType.Text);
            SqliteParameter ppid = cmd.Parameters.Add("$ppid", SqliteType.Integer);
            SqliteParameter img = cmd.Parameters.Add("$img", SqliteType.Text);
            SqliteParameter cmdline = cmd.Parameters.Add("$cmd", SqliteType.Text);
            SqliteParameter wd = cmd.Parameters.Add("$wd", SqliteType.Text);
            SqliteParameter sid = cmd.Parameters.Add("$sid", SqliteType.Text);
            SqliteParameter user = cmd.Parameters.Add("$user", SqliteType.Text);
            SqliteParameter wsess = cmd.Parameters.Add("$wsess", SqliteType.Integer);
            SqliteParameter start = cmd.Parameters.Add("$start", SqliteType.Integer);
            SqliteParameter exit = cmd.Parameters.Add("$exit", SqliteType.Integer);
            SqliteParameter code = cmd.Parameters.Add("$code", SqliteType.Integer);
            SqliteParameter integ = cmd.Parameters.Add("$integ", SqliteType.Integer);
            SqliteParameter elev = cmd.Parameters.Add("$elev", SqliteType.Integer);
            SqliteParameter sig = cmd.Parameters.Add("$sig", SqliteType.Integer);
            SqliteParameter signer = cmd.Parameters.Add("$signer", SqliteType.Text);
            SqliteParameter sha = cmd.Parameters.Add("$sha", SqliteType.Text);
            SqliteParameter size = cmd.Parameters.Add("$size", SqliteType.Integer);
            SqliteParameter scope = cmd.Parameters.Add("$scope", SqliteType.Integer);
            SqliteParameter reason = cmd.Parameters.Add("$reason", SqliteType.Text);
            SqliteParameter pre = cmd.Parameters.Add("$pre", SqliteType.Integer);
            SqliteParameter origin = cmd.Parameters.Add("$origin", SqliteType.Text);

            foreach (ProcessNode n in nodes)
            {
                key.Value = n.Key.ToString();
                pid.Value = n.Pid;
                sk.Value = (long)n.Key.StartKey;
                pkey.Value = n.ParentKey == ProcessKey.None ? DBNull.Value : n.ParentKey.ToString();
                ppid.Value = n.ParentPid;
                img.Value = n.ImagePath;
                cmdline.Value = (object?)n.CommandLine ?? DBNull.Value;
                wd.Value = (object?)n.WorkingDirectory ?? DBNull.Value;
                sid.Value = (object?)n.UserSid ?? DBNull.Value;
                user.Value = (object?)n.UserName ?? DBNull.Value;
                wsess.Value = n.SessionId;
                start.Value = n.StartTime.UtcTicks;
                exit.Value = n.ExitTime.HasValue ? n.ExitTime.Value.UtcTicks : DBNull.Value;
                code.Value = n.ExitCode.HasValue ? n.ExitCode.Value : DBNull.Value;
                integ.Value = (int)n.Integrity;
                elev.Value = n.IsElevated ? 1 : 0;
                sig.Value = (int)n.Signature;
                signer.Value = (object?)n.Signer ?? DBNull.Value;
                sha.Value = (object?)n.Sha256 ?? DBNull.Value;
                size.Value = n.ImageSize;
                scope.Value = n.InScope ? 1 : 0;
                reason.Value = (object?)n.ScopeReason ?? DBNull.Value;
                pre.Value = n.PreExisting ? 1 : 0;
                origin.Value = (object?)n.OriginId ?? DBNull.Value;
                cmd.ExecuteNonQuery();
            }

            tx.Commit();
        }
    }

    public List<ProcessNode> LoadProcesses()
    {
        var result = new List<ProcessNode>();
        using SqliteCommand cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM processes";
        using SqliteDataReader r = cmd.ExecuteReader();

        while (r.Read())
        {
            ProcessKey.TryParse(r.GetString(r.GetOrdinal("key")), out ProcessKey key);
            ProcessKey parent = ProcessKey.None;
            if (!r.IsDBNull(r.GetOrdinal("parent_key")))
                ProcessKey.TryParse(r.GetString(r.GetOrdinal("parent_key")), out parent);

            result.Add(new ProcessNode
            {
                Key = key,
                ParentKey = parent,
                ParentPid = (uint)r.GetInt64(r.GetOrdinal("parent_pid")),
                ImagePath = r.GetStringOrEmpty("image_path"),
                CommandLine = r.GetStringOrNull("command_line"),
                WorkingDirectory = r.GetStringOrNull("working_dir"),
                UserSid = r.GetStringOrNull("user_sid"),
                UserName = r.GetStringOrNull("user_name"),
                SessionId = (uint)r.GetInt64(r.GetOrdinal("win_session")),
                StartTime = new DateTimeOffset(r.GetInt64(r.GetOrdinal("start_time")), TimeSpan.Zero),
                ExitTime = r.GetTicksOrNull("exit_time"),
                ExitCode = r.GetIntOrNull("exit_code"),
                Integrity = (IntegrityLevel)r.GetInt64(r.GetOrdinal("integrity")),
                IsElevated = r.GetInt64(r.GetOrdinal("elevated")) != 0,
                Signature = (SignatureState)r.GetInt64(r.GetOrdinal("signature")),
                Signer = r.GetStringOrNull("signer"),
                Sha256 = r.GetStringOrNull("sha256"),
                ImageSize = r.GetInt64(r.GetOrdinal("image_size")),
                InScope = r.GetInt64(r.GetOrdinal("in_scope")) != 0,
                ScopeReason = r.GetStringOrNull("scope_reason"),
                PreExisting = r.GetInt64(r.GetOrdinal("pre_existing")) != 0,
                OriginId = r.GetStringOrNull("origin_id"),
            });
        }

        // Rebuild child links; they are derivable and not worth a second table.
        var byKey = result.ToDictionary(static p => p.Key);
        foreach (ProcessNode p in result)
        {
            if (p.ParentKey != ProcessKey.None && byKey.TryGetValue(p.ParentKey, out ProcessNode? parent))
                parent.Children.Add(p.Key);
        }

        return result;
    }

    // ------------------------------------------------------------ observations

    internal void WriteObservationBatch(IReadOnlyList<Observation> batch)
    {
        if (batch.Count == 0) return;

        lock (_writeGate)
        {
            using SqliteTransaction tx = _connection.BeginTransaction();
            using SqliteCommand cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT OR REPLACE INTO observations
                    (seq,ts,category,action,actor,thread_id,target,target2,old_value,new_value,
                     status,bytes,source,confidence,origin_id,caused_by,details)
                VALUES
                    ($seq,$ts,$cat,$act,$actor,$tid,$t1,$t2,$old,$new,$st,$by,$src,$conf,$origin,$cause,$det)
                """;

            SqliteParameter seq = cmd.Parameters.Add("$seq", SqliteType.Integer);
            SqliteParameter ts = cmd.Parameters.Add("$ts", SqliteType.Integer);
            SqliteParameter cat = cmd.Parameters.Add("$cat", SqliteType.Integer);
            SqliteParameter act = cmd.Parameters.Add("$act", SqliteType.Integer);
            SqliteParameter actor = cmd.Parameters.Add("$actor", SqliteType.Text);
            SqliteParameter tid = cmd.Parameters.Add("$tid", SqliteType.Integer);
            SqliteParameter t1 = cmd.Parameters.Add("$t1", SqliteType.Text);
            SqliteParameter t2 = cmd.Parameters.Add("$t2", SqliteType.Text);
            SqliteParameter oldV = cmd.Parameters.Add("$old", SqliteType.Text);
            SqliteParameter newV = cmd.Parameters.Add("$new", SqliteType.Text);
            SqliteParameter st = cmd.Parameters.Add("$st", SqliteType.Integer);
            SqliteParameter by = cmd.Parameters.Add("$by", SqliteType.Integer);
            SqliteParameter src = cmd.Parameters.Add("$src", SqliteType.Integer);
            SqliteParameter conf = cmd.Parameters.Add("$conf", SqliteType.Integer);
            SqliteParameter origin = cmd.Parameters.Add("$origin", SqliteType.Text);
            SqliteParameter cause = cmd.Parameters.Add("$cause", SqliteType.Integer);
            SqliteParameter det = cmd.Parameters.Add("$det", SqliteType.Text);

            foreach (Observation o in batch)
            {
                seq.Value = o.Seq;
                ts.Value = o.Timestamp.UtcTicks;
                cat.Value = (int)o.Category;
                act.Value = (int)o.Action;
                actor.Value = o.Actor == ProcessKey.None ? DBNull.Value : o.Actor.ToString();
                tid.Value = o.ThreadId;
                t1.Value = o.Target;
                t2.Value = (object?)o.Target2 ?? DBNull.Value;
                oldV.Value = (object?)o.OldValue ?? DBNull.Value;
                newV.Value = (object?)o.NewValue ?? DBNull.Value;
                st.Value = (int)o.Status;
                by.Value = o.Bytes;
                src.Value = (int)o.Source;
                conf.Value = (int)o.Confidence;
                origin.Value = (object?)o.OriginId ?? DBNull.Value;
                cause.Value = o.CausedBySeq;
                det.Value = (object?)o.Details ?? DBNull.Value;
                cmd.ExecuteNonQuery();
            }

            tx.Commit();
        }
    }

    /// <summary>
    /// Streams observations matching a filter. Returns an enumerable rather than a
    /// list because a session can hold millions of rows and the export path should
    /// never need all of them resident at once.
    /// </summary>
    public IEnumerable<Observation> Query(ObservationQuery? filter = null)
    {
        filter ??= new ObservationQuery();

        using SqliteCommand cmd = _connection.CreateCommand();
        var where = new List<string>();

        if (filter.Categories is { Count: > 0 })
            where.Add($"category IN ({string.Join(",", filter.Categories.Select(static c => (int)c))})");
        if (filter.Actor is { } a)
        {
            where.Add("actor = $actor");
            cmd.Parameters.AddWithValue("$actor", a.ToString());
        }
        if (filter.OriginId is not null)
        {
            where.Add("COALESCE(origin_id,'') = $origin");
            cmd.Parameters.AddWithValue("$origin", filter.OriginId);
        }
        if (filter.From is { } from)
        {
            where.Add("ts >= $from");
            cmd.Parameters.AddWithValue("$from", from.UtcTicks);
        }
        if (filter.To is { } to)
        {
            where.Add("ts <= $to");
            cmd.Parameters.AddWithValue("$to", to.UtcTicks);
        }
        if (!string.IsNullOrWhiteSpace(filter.TargetContains))
        {
            where.Add("target LIKE $needle");
            cmd.Parameters.AddWithValue("$needle", $"%{filter.TargetContains}%");
        }
        if (filter.PersistentChangesOnly)
        {
            IEnumerable<int> actions = Enum.GetValues<EventAction>()
                .Where(static x => x.IsPersistentChange())
                .Select(static x => (int)x);
            where.Add($"action IN ({string.Join(",", actions)})");
        }

        string clause = where.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", where);
        string limit = filter.Limit > 0 ? $" LIMIT {filter.Limit}" : string.Empty;
        cmd.CommandText = $"SELECT * FROM observations{clause} ORDER BY seq{limit}";

        using SqliteDataReader r = cmd.ExecuteReader();
        while (r.Read())
        {
            ProcessKey actorKey = ProcessKey.None;
            if (!r.IsDBNull(r.GetOrdinal("actor")))
                ProcessKey.TryParse(r.GetString(r.GetOrdinal("actor")), out actorKey);

            yield return new Observation
            {
                Seq = r.GetInt64(r.GetOrdinal("seq")),
                Timestamp = new DateTimeOffset(r.GetInt64(r.GetOrdinal("ts")), TimeSpan.Zero),
                Category = (EventCategory)r.GetInt64(r.GetOrdinal("category")),
                Action = (EventAction)r.GetInt64(r.GetOrdinal("action")),
                Actor = actorKey,
                ThreadId = (uint)r.GetInt64(r.GetOrdinal("thread_id")),
                Target = r.GetStringOrEmpty("target"),
                Target2 = r.GetStringOrNull("target2"),
                OldValue = r.GetStringOrNull("old_value"),
                NewValue = r.GetStringOrNull("new_value"),
                Status = (EventStatus)r.GetInt64(r.GetOrdinal("status")),
                Bytes = r.GetInt64(r.GetOrdinal("bytes")),
                Source = (EvidenceSource)r.GetInt64(r.GetOrdinal("source")),
                Confidence = (AttributionConfidence)r.GetInt64(r.GetOrdinal("confidence")),
                OriginId = r.GetStringOrNull("origin_id"),
                CausedBySeq = r.GetInt64(r.GetOrdinal("caused_by")),
                Details = r.GetStringOrNull("details"),
            };
        }
    }

    public long CountObservations() => QueryScalarLong("SELECT COUNT(*) FROM observations");

    public Dictionary<EventCategory, long> CountByCategory()
    {
        var result = new Dictionary<EventCategory, long>();
        using SqliteCommand cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT category, COUNT(*) FROM observations GROUP BY category";
        using SqliteDataReader r = cmd.ExecuteReader();
        while (r.Read()) result[(EventCategory)r.GetInt64(0)] = r.GetInt64(1);
        return result;
    }

    // ------------------------------------------------------------------- flows

    public void UpsertFlows(IEnumerable<NetworkFlow> flows)
    {
        lock (_writeGate)
        {
            using SqliteTransaction tx = _connection.BeginTransaction();
            using SqliteCommand cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO flows
                    (protocol,local_addr,local_port,remote_addr,remote_port,owner,confidence,
                     owner_evidence,first_seen,last_seen,closed_at,bytes_sent,bytes_recv,
                     packets_sent,packets_recv,resolved_host,server_name,tls_version,alpn,
                     fingerprint,origin_id)
                VALUES
                    ($proto,$la,$lp,$ra,$rp,$owner,$conf,$ev,$first,$last,$closed,$bs,$br,
                     $ps,$pr,$host,$sni,$tls,$alpn,$fp,$origin)
                ON CONFLICT(protocol,local_addr,local_port,remote_addr,remote_port,origin_id)
                DO UPDATE SET
                    owner        = COALESCE(excluded.owner, owner),
                    confidence   = MAX(excluded.confidence, confidence),
                    last_seen    = MAX(excluded.last_seen, last_seen),
                    closed_at    = COALESCE(excluded.closed_at, closed_at),
                    bytes_sent   = MAX(excluded.bytes_sent, bytes_sent),
                    bytes_recv   = MAX(excluded.bytes_recv, bytes_recv),
                    resolved_host= COALESCE(excluded.resolved_host, resolved_host),
                    server_name  = COALESCE(excluded.server_name, server_name),
                    tls_version  = COALESCE(excluded.tls_version, tls_version),
                    alpn         = COALESCE(excluded.alpn, alpn),
                    fingerprint  = COALESCE(excluded.fingerprint, fingerprint)
                """;

            foreach (NetworkFlow f in flows)
            {
                cmd.Parameters.Clear();
                cmd.Parameters.AddWithValue("$proto", (int)f.Key.Protocol);
                cmd.Parameters.AddWithValue("$la", f.Key.LocalAddress.ToString());
                cmd.Parameters.AddWithValue("$lp", f.Key.LocalPort);
                cmd.Parameters.AddWithValue("$ra", f.Key.RemoteAddress.ToString());
                cmd.Parameters.AddWithValue("$rp", f.Key.RemotePort);
                cmd.Parameters.AddWithValue("$owner", f.Owner == ProcessKey.None ? DBNull.Value : f.Owner.ToString());
                cmd.Parameters.AddWithValue("$conf", (int)f.OwnerConfidence);
                cmd.Parameters.AddWithValue("$ev", (object?)f.OwnerEvidence ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$first", f.FirstSeen.UtcTicks);
                cmd.Parameters.AddWithValue("$last", f.LastSeen.UtcTicks);
                cmd.Parameters.AddWithValue("$closed", f.ClosedAt.HasValue ? f.ClosedAt.Value.UtcTicks : DBNull.Value);
                cmd.Parameters.AddWithValue("$bs", f.BytesSent);
                cmd.Parameters.AddWithValue("$br", f.BytesReceived);
                cmd.Parameters.AddWithValue("$ps", f.PacketsSent);
                cmd.Parameters.AddWithValue("$pr", f.PacketsReceived);
                cmd.Parameters.AddWithValue("$host", (object?)f.ResolvedHost ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$sni", (object?)f.ServerName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$tls", (object?)f.TlsVersion ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$alpn", (object?)f.Alpn ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$fp", (object?)f.ClientFingerprint ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$origin", f.OriginId ?? string.Empty);
                cmd.ExecuteNonQuery();
            }

            tx.Commit();
        }
    }

    public List<NetworkFlow> LoadFlows()
    {
        var result = new List<NetworkFlow>();
        using SqliteCommand cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM flows ORDER BY first_seen";
        using SqliteDataReader r = cmd.ExecuteReader();

        while (r.Read())
        {
            ProcessKey owner = ProcessKey.None;
            if (!r.IsDBNull(r.GetOrdinal("owner")))
                ProcessKey.TryParse(r.GetString(r.GetOrdinal("owner")), out owner);

            var key = new FlowKey(
                (TransportProtocol)r.GetInt64(r.GetOrdinal("protocol")),
                IPAddress.Parse(r.GetString(r.GetOrdinal("local_addr"))),
                (ushort)r.GetInt64(r.GetOrdinal("local_port")),
                IPAddress.Parse(r.GetString(r.GetOrdinal("remote_addr"))),
                (ushort)r.GetInt64(r.GetOrdinal("remote_port")));

            result.Add(new NetworkFlow
            {
                Key = key,
                Owner = owner,
                OwnerConfidence = (AttributionConfidence)r.GetInt64(r.GetOrdinal("confidence")),
                OwnerEvidence = r.GetStringOrNull("owner_evidence"),
                FirstSeen = new DateTimeOffset(r.GetInt64(r.GetOrdinal("first_seen")), TimeSpan.Zero),
                LastSeen = new DateTimeOffset(r.GetInt64(r.GetOrdinal("last_seen")), TimeSpan.Zero),
                ClosedAt = r.GetTicksOrNull("closed_at"),
                BytesSent = r.GetInt64(r.GetOrdinal("bytes_sent")),
                BytesReceived = r.GetInt64(r.GetOrdinal("bytes_recv")),
                PacketsSent = r.GetInt64(r.GetOrdinal("packets_sent")),
                PacketsReceived = r.GetInt64(r.GetOrdinal("packets_recv")),
                ResolvedHost = r.GetStringOrNull("resolved_host"),
                ServerName = r.GetStringOrNull("server_name"),
                TlsVersion = r.GetStringOrNull("tls_version"),
                Alpn = r.GetStringOrNull("alpn"),
                ClientFingerprint = r.GetStringOrNull("fingerprint"),
                OriginId = r.GetStringOrNull("origin_id"),
            });
        }

        return result;
    }

    // --------------------------------------------------------------- snapshots

    public void WriteSnapshot(string phase, string kind, DateTimeOffset takenAt,
        IEnumerable<(string Identity, string Payload)> rows, string? originId = null)
    {
        lock (_writeGate)
        {
            using SqliteTransaction tx = _connection.BeginTransaction();
            using SqliteCommand cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO snapshots(phase,kind,taken_at,identity,payload,origin_id)
                VALUES($phase,$kind,$at,$id,$payload,$origin)
                """;

            SqliteParameter p = cmd.Parameters.Add("$phase", SqliteType.Text);
            SqliteParameter k = cmd.Parameters.Add("$kind", SqliteType.Text);
            SqliteParameter at = cmd.Parameters.Add("$at", SqliteType.Integer);
            SqliteParameter id = cmd.Parameters.Add("$id", SqliteType.Text);
            SqliteParameter payload = cmd.Parameters.Add("$payload", SqliteType.Text);
            SqliteParameter origin = cmd.Parameters.Add("$origin", SqliteType.Text);

            p.Value = phase;
            k.Value = kind;
            at.Value = takenAt.UtcTicks;
            origin.Value = (object?)originId ?? DBNull.Value;

            foreach ((string identity, string body) in rows)
            {
                id.Value = identity;
                payload.Value = body;
                cmd.ExecuteNonQuery();
            }

            tx.Commit();
        }
    }

    public Dictionary<string, string> ReadSnapshot(string phase, string kind, string? originId = null)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using SqliteCommand cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT identity,payload FROM snapshots WHERE phase=$p AND kind=$k AND COALESCE(origin_id,'')=$o";
        cmd.Parameters.AddWithValue("$p", phase);
        cmd.Parameters.AddWithValue("$k", kind);
        cmd.Parameters.AddWithValue("$o", originId ?? string.Empty);
        using SqliteDataReader r = cmd.ExecuteReader();
        while (r.Read()) result[r.GetString(0)] = r.GetString(1);
        return result;
    }

    public List<string> SnapshotKinds()
    {
        var result = new List<string>();
        using SqliteCommand cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT DISTINCT kind FROM snapshots";
        using SqliteDataReader r = cmd.ExecuteReader();
        while (r.Read()) result.Add(r.GetString(0));
        return result;
    }

    // ------------------------------------------------------------------- blobs

    public void WriteBlob(string sha256, byte[] content, string? mediaType)
    {
        lock (_writeGate)
        {
            using SqliteCommand cmd = _connection.CreateCommand();
            cmd.CommandText = "INSERT OR IGNORE INTO blobs(sha256,size,media_type,content) VALUES($s,$n,$m,$c)";
            cmd.Parameters.AddWithValue("$s", sha256);
            cmd.Parameters.AddWithValue("$n", content.Length);
            cmd.Parameters.AddWithValue("$m", (object?)mediaType ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$c", content);
            cmd.ExecuteNonQuery();
        }
    }

    public byte[]? ReadBlob(string sha256)
    {
        using SqliteCommand cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT content FROM blobs WHERE sha256=$s";
        cmd.Parameters.AddWithValue("$s", sha256);
        return cmd.ExecuteScalar() as byte[];
    }

    // ----------------------------------------------------------------- quality

    public void LogQuality(string collector, string severity, string message)
    {
        lock (_writeGate)
        {
            using SqliteCommand cmd = _connection.CreateCommand();
            cmd.CommandText = "INSERT INTO quality_events(ts,collector,severity,message) VALUES($t,$c,$s,$m)";
            cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.UtcTicks);
            cmd.Parameters.AddWithValue("$c", collector);
            cmd.Parameters.AddWithValue("$s", severity);
            cmd.Parameters.AddWithValue("$m", message);
            cmd.ExecuteNonQuery();
        }
    }

    public List<(DateTimeOffset Ts, string Collector, string Severity, string Message)> ReadQualityLog()
    {
        var result = new List<(DateTimeOffset, string, string, string)>();
        using SqliteCommand cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT ts,collector,severity,message FROM quality_events ORDER BY id";
        using SqliteDataReader r = cmd.ExecuteReader();
        while (r.Read())
        {
            result.Add((new DateTimeOffset(r.GetInt64(0), TimeSpan.Zero), r.GetString(1), r.GetString(2), r.GetString(3)));
        }
        return result;
    }

    /// <summary>
    /// Compacts the WAL into the main file. Called when a session stops so the
    /// resulting file is a single self-contained artifact.
    /// </summary>
    public void Checkpoint()
    {
        lock (_writeGate)
        {
            using SqliteCommand cmd = _connection.CreateCommand();
            cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            cmd.ExecuteNonQuery();
        }
    }

    private long QueryScalarLong(string sql)
    {
        using SqliteCommand cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        object? value = cmd.ExecuteScalar();
        return value is null or DBNull ? 0 : Convert.ToInt64(value, CultureInfo.InvariantCulture);
    }

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public void Dispose()
    {
        try { Checkpoint(); }
        catch (SqliteException) { /* closing a store that failed mid-write must not throw */ }
        _connection.Dispose();
    }
}

/// <summary>Filter applied when streaming observations back out.</summary>
public sealed class ObservationQuery
{
    public List<EventCategory>? Categories { get; init; }
    public ProcessKey? Actor { get; init; }
    public string? OriginId { get; init; }
    public DateTimeOffset? From { get; init; }
    public DateTimeOffset? To { get; init; }
    public string? TargetContains { get; init; }

    /// <summary>Restrict to actions that changed the system, for removal planning.</summary>
    public bool PersistentChangesOnly { get; init; }

    public int Limit { get; init; }
}

internal static class ReaderExtensions
{
    public static string GetStringOrEmpty(this IDataRecord r, string column)
    {
        int i = r.GetOrdinal(column);
        return r.IsDBNull(i) ? string.Empty : r.GetString(i);
    }

    public static string? GetStringOrNull(this IDataRecord r, string column)
    {
        int i = r.GetOrdinal(column);
        return r.IsDBNull(i) ? null : r.GetString(i);
    }

    public static int? GetIntOrNull(this IDataRecord r, string column)
    {
        int i = r.GetOrdinal(column);
        return r.IsDBNull(i) ? null : (int)r.GetInt64(i);
    }

    public static DateTimeOffset? GetTicksOrNull(this IDataRecord r, string column)
    {
        int i = r.GetOrdinal(column);
        return r.IsDBNull(i) ? null : new DateTimeOffset(r.GetInt64(i), TimeSpan.Zero);
    }
}
