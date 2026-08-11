namespace CaYaTrace.Storage;

/// <summary>
/// The on-disk shape of a session database.
/// </summary>
/// <remarks>
/// <para>
/// SQLite in WAL mode, one file per session. A session is a self-contained evidence
/// unit: it can be copied to another machine, attached to a ticket, or handed to
/// another analyst without the tool that made it. That property is worth more than
/// the marginal query speed of a shared database.
/// </para>
/// <para>
/// Timestamps are stored as UTC ticks rather than ISO strings: ordering is the single
/// most common operation, integers sort correctly without collation, and 100ns
/// resolution is preserved. ETW routinely produces several events inside the same
/// millisecond and a lower-resolution column would scramble their order.
/// </para>
/// </remarks>
internal static class SessionSchema
{
    /// <summary>Bumped whenever the shape changes in a way readers must know about.</summary>
    public const int Version = 1;

    public const string Create = """
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA cache_size = -65536;

        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS processes (
            key          TEXT PRIMARY KEY,
            pid          INTEGER NOT NULL,
            start_key    INTEGER NOT NULL DEFAULT 0,
            parent_key   TEXT,
            parent_pid   INTEGER NOT NULL DEFAULT 0,
            image_path   TEXT,
            command_line TEXT,
            working_dir  TEXT,
            user_sid     TEXT,
            user_name    TEXT,
            win_session  INTEGER NOT NULL DEFAULT 0,
            start_time   INTEGER NOT NULL DEFAULT 0,
            exit_time    INTEGER,
            exit_code    INTEGER,
            integrity    INTEGER NOT NULL DEFAULT 0,
            elevated     INTEGER NOT NULL DEFAULT 0,
            signature    INTEGER NOT NULL DEFAULT 0,
            signer       TEXT,
            sha256       TEXT,
            image_size   INTEGER NOT NULL DEFAULT 0,
            in_scope     INTEGER NOT NULL DEFAULT 0,
            scope_reason TEXT,
            pre_existing INTEGER NOT NULL DEFAULT 0,
            origin_id    TEXT
        );

        CREATE INDEX IF NOT EXISTS ix_proc_parent ON processes(parent_key);
        CREATE INDEX IF NOT EXISTS ix_proc_scope  ON processes(in_scope);
        CREATE INDEX IF NOT EXISTS ix_proc_origin ON processes(origin_id);

        CREATE TABLE IF NOT EXISTS observations (
            seq        INTEGER PRIMARY KEY,
            ts         INTEGER NOT NULL,
            category   INTEGER NOT NULL,
            action     INTEGER NOT NULL,
            actor      TEXT,
            thread_id  INTEGER NOT NULL DEFAULT 0,
            target     TEXT,
            target2    TEXT,
            old_value  TEXT,
            new_value  TEXT,
            status     INTEGER NOT NULL DEFAULT 0,
            bytes      INTEGER NOT NULL DEFAULT 0,
            source     INTEGER NOT NULL DEFAULT 0,
            confidence INTEGER NOT NULL DEFAULT 0,
            origin_id  TEXT,
            caused_by  INTEGER NOT NULL DEFAULT 0,
            details    TEXT
        );

        -- Index set chosen for the three queries the UI actually issues: expand a
        -- process subtree, filter a category, and scrub a time range.
        CREATE INDEX IF NOT EXISTS ix_obs_actor  ON observations(actor, category);
        CREATE INDEX IF NOT EXISTS ix_obs_cat    ON observations(category, action);
        CREATE INDEX IF NOT EXISTS ix_obs_ts     ON observations(ts);
        CREATE INDEX IF NOT EXISTS ix_obs_target ON observations(target);
        CREATE INDEX IF NOT EXISTS ix_obs_cause  ON observations(caused_by) WHERE caused_by <> 0;

        CREATE TABLE IF NOT EXISTS flows (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol     INTEGER NOT NULL,
            local_addr   TEXT NOT NULL,
            local_port   INTEGER NOT NULL,
            remote_addr  TEXT NOT NULL,
            remote_port  INTEGER NOT NULL,
            owner        TEXT,
            confidence   INTEGER NOT NULL DEFAULT 0,
            owner_evidence TEXT,
            first_seen   INTEGER NOT NULL,
            last_seen    INTEGER NOT NULL,
            closed_at    INTEGER,
            bytes_sent   INTEGER NOT NULL DEFAULT 0,
            bytes_recv   INTEGER NOT NULL DEFAULT 0,
            packets_sent INTEGER NOT NULL DEFAULT 0,
            packets_recv INTEGER NOT NULL DEFAULT 0,
            resolved_host TEXT,
            server_name  TEXT,
            tls_version  TEXT,
            alpn         TEXT,
            fingerprint  TEXT,
            origin_id    TEXT
        );

        CREATE UNIQUE INDEX IF NOT EXISTS ux_flow_tuple
            ON flows(protocol, local_addr, local_port, remote_addr, remote_port, origin_id);
        CREATE INDEX IF NOT EXISTS ix_flow_owner ON flows(owner);
        CREATE INDEX IF NOT EXISTS ix_flow_host  ON flows(resolved_host);

        -- Before/after system inventories. Kept as rows rather than blobs so a diff
        -- is a SQL query instead of a full deserialize of two large documents.
        CREATE TABLE IF NOT EXISTS snapshots (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            phase     TEXT NOT NULL,          -- 'before' | 'after'
            kind      TEXT NOT NULL,          -- 'service' | 'task' | 'autorun' | 'firewall' | 'driver' | 'certificate'
            taken_at  INTEGER NOT NULL,
            identity  TEXT NOT NULL,
            payload   TEXT NOT NULL,
            origin_id TEXT
        );

        CREATE INDEX IF NOT EXISTS ix_snap_lookup ON snapshots(kind, phase, identity, origin_id);

        -- Content-addressed store for captured payloads: request/response bodies,
        -- registry value data too large to inline, dropped-file hashes.
        CREATE TABLE IF NOT EXISTS blobs (
            sha256     TEXT PRIMARY KEY,
            size       INTEGER NOT NULL,
            media_type TEXT,
            content    BLOB
        );

        CREATE TABLE IF NOT EXISTS quality_events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        INTEGER NOT NULL,
            collector TEXT NOT NULL,
            severity  TEXT NOT NULL,
            message   TEXT NOT NULL
        );
        """;
}
