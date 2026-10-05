//! The server's durable store: SQLite, one connection owned by one thread.
//!
//! [`Store`] is an async facade: every operation is sent to the connection
//! thread over a channel and runs there in its own transaction, so
//! operations are serialized and a write is acknowledged only after it has
//! committed.
//!
//! Durability: WAL journal with `synchronous = FULL`. In WAL mode,
//! `NORMAL` can lose the last committed transactions on power loss (the
//! database stays consistent), which would break an ACK promising durable
//! local persistence (WIRE-01 §37 level 2, §40 RESOURCE_HOSTED). `FULL`
//! syncs the WAL on every commit, so a committed write survives a crash or
//! power loss on hardware that honors fsync. The store therefore supports
//! durability level 2; it does not replicate (level 3).
//!
//! Objects are stored as their exact received bytes. Index columns are
//! derived from those bytes with the sdk-rs parsers (structure only;
//! signatures and authority are checked by the ingest layer, LFCP-050),
//! never taken from the client separately. See [`schema`] for the tables.

pub mod schema;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use lfcp::base::{ControlRecordId, Hash32, PrincipalId, ResourceId};
use lfcp::wire::control::body::ControlBody;
use lfcp::wire::control::ReceivedControlRecord;
use lfcp::wire::data_unit::ReceivedDataUnit;
use lfcp::wire::key_package::ReceivedKeyPackage;
use lfcp::wire::snapshot::ReceivedSnapshot;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use tokio::sync::oneshot;

/// The database file in the state directory.
pub const DATABASE_FILE: &str = "server.sqlite3";

/// The durability level the store supports (WIRE-01 §37: durable local
/// persistence).
pub const DURABILITY: u8 = 2;

/// Why a store operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// SQLite failed.
    Sqlite(String),
    /// The bytes are not a structurally valid object of the expected kind.
    Malformed(lfcp::base::Error),
    /// A Genesis was expected and the record is another type, or the other
    /// way round.
    WrongRecordType,
    /// The object names a Resource that is not hosted here.
    UnknownResource,
    /// A different Genesis is already hosted for this Resource.
    GenesisConflict {
        /// The Genesis already stored.
        existing: ControlRecordId,
    },
    /// An integer from the object does not fit SQLite's signed 64 bits.
    OutOfRange,
    /// The connection thread has stopped.
    Closed,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sqlite(e) => write!(f, "SQLite: {e}"),
            StoreError::Malformed(e) => write!(f, "malformed object: {e}"),
            StoreError::WrongRecordType => f.write_str("wrong Control Record type"),
            StoreError::UnknownResource => f.write_str("Resource not hosted here"),
            StoreError::GenesisConflict { existing } => {
                write!(f, "another Genesis is hosted: {}", existing.to_hex())
            }
            StoreError::OutOfRange => f.write_str("integer out of range"),
            StoreError::Closed => f.write_str("store closed"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> StoreError {
        StoreError::Sqlite(e.to_string())
    }
}

/// Whether a put stored a new object or found it already stored. Objects
/// are content-addressed, so a duplicate has exactly the same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Put {
    /// Newly stored.
    Inserted,
    /// Already stored; nothing changed.
    Duplicate,
}

/// A stored object: its ID and exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject {
    /// The §10.6 object ID.
    pub id: Hash32,
    /// The exact received bytes.
    pub bytes: Vec<u8>,
}

/// A stored Control Record with its derived index values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredControlRecord {
    /// The record ID.
    pub id: ControlRecordId,
    /// The Control Sequence.
    pub seq: u64,
    /// The previous record.
    pub previous: Option<ControlRecordId>,
    /// The issuer.
    pub issuer: PrincipalId,
    /// The §14 type code.
    pub control_type: u64,
    /// The exact bytes.
    pub bytes: Vec<u8>,
}

/// The accepted Control Head of a Resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// The head record.
    pub id: ControlRecordId,
    /// Its Control Sequence.
    pub seq: u64,
}

/// Hosting metadata (infrastructure, never authority).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hosting {
    /// The session Principal that hosted the Resource here.
    pub host: PrincipalId,
    /// The durability level promised to it (WIRE-01 §37).
    pub durability: u8,
}

/// What the store knows about a hosted Resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceInfo {
    /// The Genesis record ID.
    pub genesis: ControlRecordId,
    /// The accepted Control Head.
    pub head: Head,
    /// Hosting metadata.
    pub hosting: Hosting,
}

/// The outcome of a Control Head compare-and-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    /// The record was stored and is the new head.
    Committed(Put),
    /// The expected head is not the current one; nothing changed
    /// (WIRE-01 §47: NACK(CONTROL_HEAD_MISMATCH) with `current`).
    HeadMismatch {
        /// The current head.
        current: Head,
    },
    /// The record does not continue the expected head (its previous
    /// record or sequence differ); nothing changed.
    NotSuccessor,
}

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// The store: a handle to the connection thread. Cheap to share by
/// reference; dropping the last handle closes the database.
pub struct Store {
    jobs: Option<mpsc::Sender<Job>>,
    thread: Option<thread::JoinHandle<()>>,
    path: PathBuf,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish()
    }
}

fn i64_of(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::OutOfRange)
}

fn id32(blob: Vec<u8>) -> Hash32 {
    Hash32::from_bytes(blob.try_into().expect("the schema checks 32-byte IDs"))
}

impl Store {
    /// Open (or create) `<state_dir>/server.sqlite3`, configure it and run
    /// the migrations, on a new connection thread.
    pub fn open(state_dir: &Path) -> Result<Store, StoreError> {
        std::fs::create_dir_all(state_dir).map_err(|e| StoreError::Sqlite(e.to_string()))?;
        let path = state_dir.join(DATABASE_FILE);
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), StoreError>>();
        let (jobs, inbox) = mpsc::channel::<Job>();
        let db = path.clone();
        let thread = thread::Builder::new()
            .name("lfcp-store".into())
            .spawn(move || {
                let mut conn = match open_connection(&db) {
                    Ok(conn) => conn,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                for job in inbox {
                    job(&mut conn);
                }
            })
            .map_err(|e| StoreError::Sqlite(e.to_string()))?;
        ready_rx.recv().map_err(|_| StoreError::Closed)??;
        Ok(Store {
            jobs: Some(jobs),
            thread: Some(thread),
            path,
        })
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Run `f` on the connection thread and wait for its result.
    async fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<R, StoreError> + Send + 'static,
    ) -> Result<R, StoreError> {
        let (reply, result) = oneshot::channel();
        let job: Job = Box::new(move |conn| {
            let _ = reply.send(f(conn));
        });
        self.jobs
            .as_ref()
            .ok_or(StoreError::Closed)?
            .send(job)
            .map_err(|_| StoreError::Closed)?;
        result.await.map_err(|_| StoreError::Closed)?
    }

    /// The applied schema version.
    pub async fn schema_version(&self) -> Result<u32, StoreError> {
        self.call(|conn| Ok(schema::version(conn)?)).await
    }

    /// Host a Resource from its Genesis (RESOURCE_HOST, WIRE-01 §39): store
    /// the Genesis, the Resource, the Genesis as its head and the hosting
    /// metadata, in one transaction. Hosting the same Genesis again is a
    /// duplicate; a different Genesis for the Resource is refused.
    pub async fn host_resource(
        &self,
        genesis: Vec<u8>,
        hosting: Hosting,
    ) -> Result<Put, StoreError> {
        let record = ReceivedControlRecord::parse(&genesis).map_err(StoreError::Malformed)?;
        if !matches!(record.body(), ControlBody::Genesis(_)) {
            return Err(StoreError::WrongRecordType);
        }
        let header = record.header().clone();
        let id = record.id();
        let control_type = record.body().control_type();
        self.call(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT genesis_id FROM resources WHERE resource_id = ?1",
                    [header.resource_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                let existing = ControlRecordId::from_bytes(*id32(existing).as_bytes());
                return if existing == id {
                    Ok(Put::Duplicate)
                } else {
                    Err(StoreError::GenesisConflict { existing })
                };
            }
            tx.execute(
                "INSERT INTO resources (resource_id, genesis_id) VALUES (?1, ?2)",
                params![
                    header.resource_id.as_bytes().as_slice(),
                    id.as_bytes().as_slice()
                ],
            )?;
            insert_control(&tx, &header, id, control_type, &genesis)?;
            tx.execute(
                "INSERT INTO control_head (resource_id, record_id, seq) VALUES (?1, ?2, 0)",
                params![
                    header.resource_id.as_bytes().as_slice(),
                    id.as_bytes().as_slice()
                ],
            )?;
            tx.execute(
                "INSERT INTO hosting (resource_id, host, durability) VALUES (?1, ?2, ?3)",
                params![
                    header.resource_id.as_bytes().as_slice(),
                    hosting.host.as_bytes().as_slice(),
                    hosting.durability
                ],
            )?;
            tx.commit()?;
            Ok(Put::Inserted)
        })
        .await
    }

    /// Store a Control Record of a hosted Resource without moving the head:
    /// for records received from peers, including competing ones, which are
    /// kept as fork evidence (WIRE-01 §13.2).
    pub async fn put_control_record(&self, bytes: Vec<u8>) -> Result<Put, StoreError> {
        let record = ReceivedControlRecord::parse(&bytes).map_err(StoreError::Malformed)?;
        if matches!(record.body(), ControlBody::Genesis(_)) {
            return Err(StoreError::WrongRecordType);
        }
        let header = record.header().clone();
        let id = record.id();
        let control_type = record.body().control_type();
        self.call(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_resource(&tx, &header.resource_id)?;
            let put = insert_control(&tx, &header, id, control_type, &bytes)?;
            tx.commit()?;
            Ok(put)
        })
        .await
    }

    /// Store a Control Record and make it the head if, and only if, the
    /// head is `expected` and the record continues it: previous record
    /// `expected`, sequence head + 1. One transaction: the atomic step the
    /// Control Coordinator (LFCP-049) builds on. Whether the record is
    /// signed and authorized is the caller's check.
    pub async fn commit_control_record(
        &self,
        bytes: Vec<u8>,
        expected: ControlRecordId,
    ) -> Result<CasOutcome, StoreError> {
        let record = ReceivedControlRecord::parse(&bytes).map_err(StoreError::Malformed)?;
        if matches!(record.body(), ControlBody::Genesis(_)) {
            return Err(StoreError::WrongRecordType);
        }
        let header = record.header().clone();
        let id = record.id();
        let control_type = record.body().control_type();
        self.call(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_resource(&tx, &header.resource_id)?;
            let current = head(&tx, &header.resource_id)?.ok_or(StoreError::UnknownResource)?;
            if current.id != expected {
                return Ok(CasOutcome::HeadMismatch { current });
            }
            if header.previous != Some(expected)
                || Some(header.sequence) != current.seq.checked_add(1)
            {
                return Ok(CasOutcome::NotSuccessor);
            }
            let put = insert_control(&tx, &header, id, control_type, &bytes)?;
            tx.execute(
                "UPDATE control_head SET record_id = ?2, seq = ?3 WHERE resource_id = ?1",
                params![
                    header.resource_id.as_bytes().as_slice(),
                    id.as_bytes().as_slice(),
                    i64_of(header.sequence)?
                ],
            )?;
            tx.commit()?;
            Ok(CasOutcome::Committed(put))
        })
        .await
    }

    /// The Resource's Genesis, head and hosting metadata.
    pub async fn resource(&self, resource: ResourceId) -> Result<Option<ResourceInfo>, StoreError> {
        self.call(move |conn| {
            let row = conn
                .query_row(
                    "SELECT r.genesis_id, h.record_id, h.seq, o.host, o.durability
                     FROM resources r JOIN control_head h USING (resource_id) JOIN hosting o USING (resource_id)
                     WHERE r.resource_id = ?1",
                    [resource.as_bytes().as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, u8>(4)?,
                        ))
                    },
                )
                .optional()?;
            Ok(row.map(|(genesis, head_id, seq, host, durability)| ResourceInfo {
                genesis: ControlRecordId::from_bytes(*id32(genesis).as_bytes()),
                head: Head {
                    id: ControlRecordId::from_bytes(*id32(head_id).as_bytes()),
                    seq: seq as u64,
                },
                hosting: Hosting {
                    host: PrincipalId::from_bytes(*id32(host).as_bytes()),
                    durability,
                },
            }))
        })
        .await
    }

    /// The Resource's accepted Control Head.
    pub async fn head(&self, resource: ResourceId) -> Result<Option<Head>, StoreError> {
        self.call(move |conn| head(conn, &resource)).await
    }

    /// The stored Control Records with sequence in `from..=to`, by
    /// sequence then record ID; competing records appear side by side.
    pub async fn control_records(
        &self,
        resource: ResourceId,
        from: u64,
        to: u64,
    ) -> Result<Vec<StoredControlRecord>, StoreError> {
        let (from, to) = (i64_of(from)?, i64_of(to.min(i64::MAX as u64))?);
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT record_id, seq, previous_id, issuer, control_type, bytes FROM control_records
                 WHERE resource_id = ?1 AND seq BETWEEN ?2 AND ?3 ORDER BY seq, record_id",
            )?;
            let rows = stmt.query_map(params![resource.as_bytes().as_slice(), from, to], |row| {
                Ok(StoredControlRecord {
                    id: ControlRecordId::from_bytes(*id32(row.get(0)?).as_bytes()),
                    seq: row.get::<_, i64>(1)? as u64,
                    previous: row
                        .get::<_, Option<Vec<u8>>>(2)?
                        .map(|b| ControlRecordId::from_bytes(*id32(b).as_bytes())),
                    issuer: PrincipalId::from_bytes(*id32(row.get(3)?).as_bytes()),
                    control_type: row.get::<_, i64>(4)? as u64,
                    bytes: row.get(5)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    /// Store a Data Unit of a hosted Resource. A unit with the same
    /// (resource, actor, sequence) and another ID is stored too: it is
    /// equivocation evidence ([`Store::data_units_at`]).
    pub async fn put_data_unit(&self, bytes: Vec<u8>) -> Result<Put, StoreError> {
        let unit = ReceivedDataUnit::parse(&bytes).map_err(StoreError::Malformed)?;
        let h = unit.header().clone();
        let id = unit.id();
        let (seq, epoch) = (i64_of(h.sequence)?, i64_of(h.data_epoch)?);
        self.call(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_resource(&tx, &h.resource_id)?;
            let n = tx.execute(
                "INSERT OR IGNORE INTO data_units (unit_id, resource_id, actor, seq, epoch, previous_id, control_head, bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id.as_bytes().as_slice(),
                    h.resource_id.as_bytes().as_slice(),
                    h.actor.as_bytes().as_slice(),
                    seq,
                    epoch,
                    h.previous.map(|p| p.as_bytes().to_vec()),
                    h.control_head.as_bytes().as_slice(),
                    bytes
                ],
            )?;
            tx.commit()?;
            Ok(if n == 1 { Put::Inserted } else { Put::Duplicate })
        })
        .await
    }

    /// The IDs of every stored unit for (resource, actor, sequence): more
    /// than one is equivocation (WIRE-01 §26.2).
    pub async fn data_units_at(
        &self,
        resource: ResourceId,
        actor: PrincipalId,
        seq: u64,
    ) -> Result<Vec<Hash32>, StoreError> {
        let seq = i64_of(seq)?;
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT unit_id FROM data_units WHERE resource_id = ?1 AND actor = ?2 AND seq = ?3 ORDER BY unit_id",
            )?;
            let rows = stmt.query_map(params![resource.as_bytes().as_slice(), actor.as_bytes().as_slice(), seq], |row| {
                Ok(id32(row.get(0)?))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    /// A stored Data Unit's exact bytes.
    pub async fn data_unit(&self, id: Hash32) -> Result<Option<Vec<u8>>, StoreError> {
        self.call(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT bytes FROM data_units WHERE unit_id = ?1",
                    [id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?)
        })
        .await
    }

    /// Store a Key Package of a hosted Resource. Several packages for one
    /// (resource, epoch, recipient) are all kept (WIRE-01 §25.2).
    pub async fn put_key_package(&self, bytes: Vec<u8>) -> Result<Put, StoreError> {
        let package = ReceivedKeyPackage::parse(&bytes).map_err(StoreError::Malformed)?;
        let h = package.header().clone();
        let id = package.id();
        let epoch = i64_of(h.data_epoch)?;
        self.call(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_resource(&tx, &h.resource_id)?;
            let n = tx.execute(
                "INSERT OR IGNORE INTO key_packages (package_id, resource_id, epoch, recipient, sender, control_head, bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id.as_bytes().as_slice(),
                    h.resource_id.as_bytes().as_slice(),
                    epoch,
                    h.recipient.as_bytes().as_slice(),
                    h.sender.as_bytes().as_slice(),
                    h.control_head.as_bytes().as_slice(),
                    bytes
                ],
            )?;
            tx.commit()?;
            Ok(if n == 1 { Put::Inserted } else { Put::Duplicate })
        })
        .await
    }

    /// Every stored package for (resource, epoch, recipient), by ID.
    pub async fn key_packages_for(
        &self,
        resource: ResourceId,
        epoch: u64,
        recipient: PrincipalId,
    ) -> Result<Vec<StoredObject>, StoreError> {
        let epoch = i64_of(epoch)?;
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT package_id, bytes FROM key_packages WHERE resource_id = ?1 AND epoch = ?2 AND recipient = ?3 ORDER BY package_id",
            )?;
            let rows = stmt.query_map(params![resource.as_bytes().as_slice(), epoch, recipient.as_bytes().as_slice()], |row| {
                Ok(StoredObject {
                    id: id32(row.get(0)?),
                    bytes: row.get(1)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    /// Store a Snapshot of a hosted Resource.
    pub async fn put_snapshot(&self, bytes: Vec<u8>) -> Result<Put, StoreError> {
        let snapshot = ReceivedSnapshot::parse(&bytes).map_err(StoreError::Malformed)?;
        let h = snapshot.header().clone();
        let id = snapshot.id();
        let (epoch, seq) = (i64_of(h.data_epoch)?, i64_of(h.sequence)?);
        self.call(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_resource(&tx, &h.resource_id)?;
            let n = tx.execute(
                "INSERT OR IGNORE INTO snapshots (snapshot_id, resource_id, epoch, publisher, seq, control_head, bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id.as_bytes().as_slice(),
                    h.resource_id.as_bytes().as_slice(),
                    epoch,
                    h.publisher.as_bytes().as_slice(),
                    seq,
                    h.control_head.as_bytes().as_slice(),
                    bytes
                ],
            )?;
            tx.commit()?;
            Ok(if n == 1 { Put::Inserted } else { Put::Duplicate })
        })
        .await
    }

    /// A stored Snapshot's exact bytes.
    pub async fn snapshot(&self, id: Hash32) -> Result<Option<Vec<u8>>, StoreError> {
        self.call(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT bytes FROM snapshots WHERE snapshot_id = ?1",
                    [id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?)
        })
        .await
    }

    /// The Snapshots of a Resource, newest epoch first, then by publisher
    /// and descending Snapshot Sequence: the selection order for
    /// SNAPSHOT_GET without an ID (LFCP-051 decides the policy).
    pub async fn snapshots(&self, resource: ResourceId) -> Result<Vec<StoredObject>, StoreError> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT snapshot_id, bytes FROM snapshots WHERE resource_id = ?1 ORDER BY epoch DESC, publisher, seq DESC",
            )?;
            let rows = stmt.query_map([resource.as_bytes().as_slice()], |row| {
                Ok(StoredObject {
                    id: id32(row.get(0)?),
                    bytes: row.get(1)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // Closing the channel ends the thread after the queued jobs; the
        // connection closes when the thread returns.
        drop(self.jobs.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn open_connection(path: &Path) -> Result<Connection, StoreError> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    schema::migrate(&mut conn)?;
    Ok(conn)
}

fn require_resource(conn: &Connection, resource: &ResourceId) -> Result<(), StoreError> {
    let known: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM resources WHERE resource_id = ?1",
            [resource.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    known.map(|_| ()).ok_or(StoreError::UnknownResource)
}

fn head(conn: &Connection, resource: &ResourceId) -> Result<Option<Head>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT record_id, seq FROM control_head WHERE resource_id = ?1",
            [resource.as_bytes().as_slice()],
            |row| {
                Ok(Head {
                    id: ControlRecordId::from_bytes(*id32(row.get(0)?).as_bytes()),
                    seq: row.get::<_, i64>(1)? as u64,
                })
            },
        )
        .optional()?)
}

fn insert_control(
    conn: &Connection,
    header: &lfcp::wire::control::ControlRecordHeader,
    id: ControlRecordId,
    control_type: u64,
    bytes: &[u8],
) -> Result<Put, StoreError> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO control_records (record_id, resource_id, seq, previous_id, issuer, control_type, bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id.as_bytes().as_slice(),
            header.resource_id.as_bytes().as_slice(),
            i64_of(header.sequence)?,
            header.previous.map(|p| p.as_bytes().to_vec()),
            header.issuer.as_bytes().as_slice(),
            i64_of(control_type)?,
            bytes
        ],
    )?;
    Ok(if n == 1 {
        Put::Inserted
    } else {
        Put::Duplicate
    })
}
