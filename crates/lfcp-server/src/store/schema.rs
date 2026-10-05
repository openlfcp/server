//! The store schema and its migrations.
//!
//! `schema_version` holds one row, the number of applied migrations.
//! Opening a database applies the missing migrations in order, each in its
//! own transaction, so a fresh database always ends up with the same
//! schema. Migrations are append-only: a released one is never edited.
//!
//! Every object table keeps the exact received bytes (`bytes`, the
//! authoritative copy) next to index columns derived from those bytes by
//! the sdk-rs decoders at insert time. There is no column for application
//! data: the server cannot decrypt Data Units or Snapshots and never
//! decodes the Shared Objects profile.

use rusqlite::{Connection, OptionalExtension};

/// The migrations, in order. Index `i` brings the schema to version `i + 1`.
pub const MIGRATIONS: &[&str] = &[
    // 1: the LFCP-045 model.
    r#"
    CREATE TABLE resources (
        resource_id   BLOB PRIMARY KEY CHECK (length(resource_id) = 32),
        genesis_id    BLOB NOT NULL UNIQUE CHECK (length(genesis_id) = 32)
    ) STRICT;

    -- Every stored Control Record, Genesis included. (resource, seq) is
    -- not unique: competing records of a fork are kept as evidence
    -- (WIRE-01 §13.2).
    CREATE TABLE control_records (
        record_id     BLOB PRIMARY KEY CHECK (length(record_id) = 32),
        resource_id   BLOB NOT NULL CHECK (length(resource_id) = 32),
        seq           INTEGER NOT NULL CHECK (seq >= 0),
        previous_id   BLOB CHECK (previous_id IS NULL OR length(previous_id) = 32),
        issuer        BLOB NOT NULL CHECK (length(issuer) = 32),
        control_type  INTEGER NOT NULL CHECK (control_type >= 0),
        bytes         BLOB NOT NULL
    ) STRICT;
    CREATE INDEX control_records_by_seq ON control_records (resource_id, seq);

    -- The accepted Control Head of each Resource. Moved only by
    -- compare-and-set (WIRE-01 §47).
    CREATE TABLE control_head (
        resource_id   BLOB PRIMARY KEY REFERENCES resources (resource_id),
        record_id     BLOB NOT NULL REFERENCES control_records (record_id),
        seq           INTEGER NOT NULL CHECK (seq >= 0)
    ) STRICT;

    -- (resource, actor, seq) is not unique: equivocation must be storable
    -- and detectable (WIRE-01 §26.2); the object ID is.
    CREATE TABLE data_units (
        unit_id       BLOB PRIMARY KEY CHECK (length(unit_id) = 32),
        resource_id   BLOB NOT NULL REFERENCES resources (resource_id),
        actor         BLOB NOT NULL CHECK (length(actor) = 32),
        seq           INTEGER NOT NULL CHECK (seq >= 1),
        epoch         INTEGER NOT NULL CHECK (epoch >= 0),
        previous_id   BLOB CHECK (previous_id IS NULL OR length(previous_id) = 32),
        control_head  BLOB NOT NULL CHECK (length(control_head) = 32),
        bytes         BLOB NOT NULL
    ) STRICT;
    CREATE INDEX data_units_by_actor ON data_units (resource_id, actor, seq);
    CREATE INDEX data_units_by_epoch ON data_units (resource_id, epoch);

    -- Several valid packages may exist for one (resource, epoch,
    -- recipient) (WIRE-01 §25.2); none is unique but the package ID.
    CREATE TABLE key_packages (
        package_id    BLOB PRIMARY KEY CHECK (length(package_id) = 32),
        resource_id   BLOB NOT NULL REFERENCES resources (resource_id),
        epoch         INTEGER NOT NULL CHECK (epoch >= 0),
        recipient     BLOB NOT NULL CHECK (length(recipient) = 32),
        sender        BLOB NOT NULL CHECK (length(sender) = 32),
        control_head  BLOB NOT NULL CHECK (length(control_head) = 32),
        bytes         BLOB NOT NULL
    ) STRICT;
    CREATE INDEX key_packages_by_recipient ON key_packages (resource_id, epoch, recipient);

    CREATE TABLE snapshots (
        snapshot_id   BLOB PRIMARY KEY CHECK (length(snapshot_id) = 32),
        resource_id   BLOB NOT NULL REFERENCES resources (resource_id),
        epoch         INTEGER NOT NULL CHECK (epoch >= 0),
        publisher     BLOB NOT NULL CHECK (length(publisher) = 32),
        seq           INTEGER NOT NULL CHECK (seq >= 1),
        control_head  BLOB NOT NULL CHECK (length(control_head) = 32),
        bytes         BLOB NOT NULL
    ) STRICT;
    CREATE INDEX snapshots_by_publisher ON snapshots (resource_id, epoch, publisher, seq);

    -- Hosting metadata: which session Principal hosted a Resource here and
    -- the durability promised. Infrastructure only: Resource authority is
    -- derived from the Control Chain, never from this table.
    CREATE TABLE hosting (
        resource_id   BLOB PRIMARY KEY REFERENCES resources (resource_id),
        host          BLOB NOT NULL CHECK (length(host) = 32),
        durability    INTEGER NOT NULL CHECK (durability BETWEEN 0 AND 3)
    ) STRICT;
    "#,
    // 2: server administration (LFCP-046). Infrastructure only: nothing
    // here is LFCP Resource authority.
    r#"
    -- The one-time setup code while no administrator is paired: only its
    -- hash, its expiry (Unix seconds) and the failed attempts.
    CREATE TABLE admin_setup (
        id            INTEGER PRIMARY KEY CHECK (id = 1),
        code_hash     BLOB NOT NULL CHECK (length(code_hash) = 32),
        expires_at    INTEGER NOT NULL,
        failures      INTEGER NOT NULL DEFAULT 0
    ) STRICT;

    -- The LFCP Principals paired as server administrators.
    CREATE TABLE admins (
        principal     BLOB PRIMARY KEY CHECK (length(principal) = 32),
        descriptor    BLOB NOT NULL,
        paired_at     INTEGER NOT NULL
    ) STRICT;

    -- Server settings changed through the admin API, such as the hosting
    -- policy (JSON).
    CREATE TABLE settings (
        key           TEXT PRIMARY KEY,
        value         TEXT NOT NULL
    ) STRICT;
    "#,
];

/// The schema version a fully migrated database has.
pub fn latest_version() -> u32 {
    MIGRATIONS.len() as u32
}

/// The applied version, 0 for an empty database.
pub fn version(conn: &Connection) -> rusqlite::Result<u32> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL) STRICT",
    )?;
    Ok(conn
        .query_row("SELECT version FROM schema_version", [], |row| {
            row.get::<_, u32>(0)
        })
        .optional()?
        .unwrap_or(0))
}

/// Apply every missing migration, each in its own transaction.
pub fn migrate(conn: &mut Connection) -> rusqlite::Result<u32> {
    let mut current = version(conn)?;
    for (index, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        let next = index as u32 + 1;
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute("DELETE FROM schema_version", [])?;
        tx.execute("INSERT INTO schema_version (version) VALUES (?1)", [next])?;
        tx.commit()?;
        current = next;
    }
    Ok(current)
}
