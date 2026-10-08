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
        let path = state_dir.join(DATABASE_FILE);
        // Owner-only (security review L5): SQLite gives the -wal and -shm
        // files the database file's mode, so the database is created at
        // 0600 before SQLite opens it; files of an older server are
        // tightened.
        let io = |e: std::io::Error| StoreError::Sqlite(e.to_string());
        crate::private::create_dir(state_dir).map_err(io)?;
        crate::private::create_file(&path).map_err(io)?;
        for suffix in ["", "-wal", "-shm"] {
            let mut file = path.clone().into_os_string();
            file.push(suffix);
            crate::private::restrict(Path::new(&file)).map_err(io)?;
        }
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
        let mut puts = self.put_data_units(vec![bytes]).await?;
        Ok(puts.pop().expect("one unit, one result"))
    }

    /// Store Data Units of hosted Resources in one transaction: all of
    /// them or, on any failure, none (WIRE-01 §51). One [`Put`] per unit,
    /// in order.
    pub async fn put_data_units(&self, units: Vec<Vec<u8>>) -> Result<Vec<Put>, StoreError> {
        let mut rows = Vec::with_capacity(units.len());
        for bytes in units {
            let unit = ReceivedDataUnit::parse(&bytes).map_err(StoreError::Malformed)?;
            let h = unit.header().clone();
            let (seq, epoch) = (i64_of(h.sequence)?, i64_of(h.data_epoch)?);
            rows.push((unit.id(), h, seq, epoch, bytes));
        }
        self.call(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut puts = Vec::with_capacity(rows.len());
            for (id, h, seq, epoch, bytes) in rows {
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
                puts.push(if n == 1 { Put::Inserted } else { Put::Duplicate });
            }
            tx.commit()?;
            Ok(puts)
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

    /// The actor and sequence of the stored Data Unit `id` of `resource`,
    /// equivocation evidence included (WIRE-01 §51.1).
    pub async fn data_unit_position(
        &self,
        resource: ResourceId,
        id: Hash32,
    ) -> Result<Option<(PrincipalId, u64)>, StoreError> {
        self.call(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT actor, seq FROM data_units WHERE resource_id = ?1 AND unit_id = ?2",
                    params![resource.as_bytes().as_slice(), id.as_bytes().as_slice()],
                    |row| {
                        Ok((
                            PrincipalId::from_bytes(*id32(row.get(0)?).as_bytes()),
                            row.get::<_, i64>(1)? as u64,
                        ))
                    },
                )
                .optional()?)
        })
        .await
    }

    /// Whether a Data Unit of `actor` is stored at a sequence `s` with
    /// `low < s < high` (WIRE-01 §51.1).
    pub async fn data_unit_between(
        &self,
        resource: ResourceId,
        actor: PrincipalId,
        low: u64,
        high: u64,
    ) -> Result<bool, StoreError> {
        let (low, high) = (i64_of(low)?, i64_of(high.min(i64::MAX as u64))?);
        self.call(move |conn| {
            Ok(conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM data_units
                 WHERE resource_id = ?1 AND actor = ?2 AND seq > ?3 AND seq < ?4)",
                params![
                    resource.as_bytes().as_slice(),
                    actor.as_bytes().as_slice(),
                    low,
                    high
                ],
                |row| row.get::<_, bool>(0),
            )?)
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

    /// The stored Data Units of `actor` with sequence in `start..=end`, by
    /// sequence then unit ID: equivocating units appear side by side
    /// (WIRE-01 §49, §26.2).
    pub async fn data_units_in(
        &self,
        resource: ResourceId,
        actor: PrincipalId,
        start: u64,
        end: u64,
    ) -> Result<Vec<StoredObject>, StoreError> {
        let (start, end) = (i64_of(start)?, i64_of(end.min(i64::MAX as u64))?);
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT unit_id, bytes FROM data_units
                 WHERE resource_id = ?1 AND actor = ?2 AND seq BETWEEN ?3 AND ?4 ORDER BY seq, unit_id",
            )?;
            let rows = stmt.query_map(
                params![resource.as_bytes().as_slice(), actor.as_bytes().as_slice(), start, end],
                |row| {
                    Ok(StoredObject {
                        id: id32(row.get(0)?),
                        bytes: row.get(1)?,
                    })
                },
            )?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    /// Every stored (actor, sequence) of a Resource's Data Units, in
    /// order, each once: the server's Have (WIRE-01 §28, §42).
    pub async fn data_sequences(
        &self,
        resource: ResourceId,
    ) -> Result<Vec<(PrincipalId, u64)>, StoreError> {
        self.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT actor, seq FROM data_units WHERE resource_id = ?1 ORDER BY actor, seq",
            )?;
            let rows = stmt.query_map([resource.as_bytes().as_slice()], |row| {
                Ok((
                    PrincipalId::from_bytes(*id32(row.get(0)?).as_bytes()),
                    row.get::<_, i64>(1)? as u64,
                ))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
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

/// What the setup code check found ([`Store::pair_admin`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pairing {
    /// The code matched: it is destroyed and the Principal is an admin.
    Paired,
    /// The code did not match; `remaining` attempts are left (0: the code
    /// is destroyed).
    WrongCode {
        /// Attempts left.
        remaining: u32,
    },
    /// The code expired; it is destroyed.
    Expired,
    /// There is no setup code (never created, used, or destroyed).
    NoCode,
}

/// The sizes of one hosted Resource, for the admin API: counts and bytes,
/// never contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSize {
    /// The Resource.
    pub resource_id: ResourceId,
    /// The accepted Control Head's sequence.
    pub control_head_seq: u64,
    /// Stored Control Records (fork evidence included).
    pub control_records: u64,
    /// Stored Data Units (equivocation evidence included).
    pub data_units: u64,
    /// Stored Key Packages.
    pub key_packages: u64,
    /// Stored Snapshots.
    pub snapshots: u64,
    /// The total size of every stored object's bytes.
    pub bytes: u64,
}

/// What a Resource's quota check needs (POST-003): its stored bytes, its
/// hosting Principal's Resources and bytes, and the store's total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// The Principal that hosted the Resource here.
    pub host: PrincipalId,
    /// The Resource's stored bytes.
    pub resource_bytes: u64,
    /// The Resources `host` hosts here.
    pub host_resources: u64,
    /// The stored bytes of those Resources.
    pub host_bytes: u64,
    /// The stored bytes of every Resource.
    pub total_bytes: u64,
}

/// A Principal's quota override (admin API, POST-003); `None` keeps the
/// configured default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuotaOverride {
    /// Resources it may host.
    pub resources: Option<u64>,
    /// Stored bytes across its Resources.
    pub bytes: Option<u64>,
    /// Stored bytes of each of its Resources.
    pub resource_bytes: Option<u64>,
}

/// Failed setup code attempts after which the code is destroyed.
pub const SETUP_ATTEMPTS: u32 = 5;

impl Store {
    /// Replace the setup code with one whose hash is `code_hash`, valid
    /// until `expires_at` (Unix seconds).
    pub async fn set_setup_code(
        &self,
        code_hash: [u8; 32],
        expires_at: i64,
    ) -> Result<(), StoreError> {
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO admin_setup (id, code_hash, expires_at, failures) VALUES (1, ?1, ?2, 0)
                 ON CONFLICT (id) DO UPDATE SET code_hash = ?1, expires_at = ?2, failures = 0",
                params![code_hash.as_slice(), expires_at],
            )?;
            Ok(())
        })
        .await
    }

    /// Check a setup code and, if it matches and has not expired, destroy
    /// it and pair `principal` as an administrator, in one transaction:
    /// a code pairs at most once. A wrong code counts an attempt; after
    /// [`SETUP_ATTEMPTS`] the code is destroyed.
    pub async fn pair_admin(
        &self,
        code_hash: [u8; 32],
        principal: PrincipalId,
        descriptor: Vec<u8>,
        now: i64,
    ) -> Result<Pairing, StoreError> {
        self.call(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row: Option<(Vec<u8>, i64, i64)> = tx
                .query_row(
                    "SELECT code_hash, expires_at, failures FROM admin_setup WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((stored, expires_at, failures)) = row else {
                return Ok(Pairing::NoCode);
            };
            let outcome = if now >= expires_at {
                tx.execute("DELETE FROM admin_setup", [])?;
                Pairing::Expired
            } else if stored != code_hash {
                let failures = failures as u32 + 1;
                if failures >= SETUP_ATTEMPTS {
                    tx.execute("DELETE FROM admin_setup", [])?;
                } else {
                    tx.execute("UPDATE admin_setup SET failures = ?1", [failures])?;
                }
                Pairing::WrongCode {
                    remaining: SETUP_ATTEMPTS.saturating_sub(failures),
                }
            } else {
                tx.execute("DELETE FROM admin_setup", [])?;
                tx.execute(
                    "INSERT OR IGNORE INTO admins (principal, descriptor, paired_at) VALUES (?1, ?2, ?3)",
                    params![principal.as_bytes().as_slice(), descriptor, now],
                )?;
                Pairing::Paired
            };
            tx.commit()?;
            Ok(outcome)
        })
        .await
    }

    /// The paired administrators.
    pub async fn admins(&self) -> Result<Vec<PrincipalId>, StoreError> {
        self.call(|conn| {
            let mut stmt = conn.prepare("SELECT principal FROM admins ORDER BY principal")?;
            let rows = stmt.query_map([], |row| {
                Ok(PrincipalId::from_bytes(*id32(row.get(0)?).as_bytes()))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    /// A server setting.
    pub async fn setting(&self, key: &'static str) -> Result<Option<String>, StoreError> {
        self.call(move |conn| {
            Ok(conn
                .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                    row.get(0)
                })
                .optional()?)
        })
        .await
    }

    /// Set a server setting.
    pub async fn set_setting(&self, key: &'static str, value: String) -> Result<(), StoreError> {
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = ?2",
                params![key, value],
            )?;
            Ok(())
        })
        .await
    }

    /// Every hosted Resource's sizes.
    pub async fn resource_sizes(&self) -> Result<Vec<ResourceSize>, StoreError> {
        self.call(|conn| {
            let mut stmt = conn.prepare(
                "SELECT r.resource_id, h.seq,
                   (SELECT COUNT(*) FROM control_records c WHERE c.resource_id = r.resource_id),
                   (SELECT COUNT(*) FROM data_units d WHERE d.resource_id = r.resource_id),
                   (SELECT COUNT(*) FROM key_packages k WHERE k.resource_id = r.resource_id),
                   (SELECT COUNT(*) FROM snapshots s WHERE s.resource_id = r.resource_id),
                   (SELECT COALESCE(SUM(length(bytes)), 0) FROM control_records c WHERE c.resource_id = r.resource_id)
                 + (SELECT COALESCE(SUM(length(bytes)), 0) FROM data_units d WHERE d.resource_id = r.resource_id)
                 + (SELECT COALESCE(SUM(length(bytes)), 0) FROM key_packages k WHERE k.resource_id = r.resource_id)
                 + (SELECT COALESCE(SUM(length(bytes)), 0) FROM snapshots s WHERE s.resource_id = r.resource_id)
                 FROM resources r JOIN control_head h ON h.resource_id = r.resource_id
                 ORDER BY r.resource_id",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(ResourceSize {
                    resource_id: ResourceId::from_bytes(*id32(row.get(0)?).as_bytes()),
                    control_head_seq: row.get::<_, i64>(1)? as u64,
                    control_records: row.get::<_, i64>(2)? as u64,
                    data_units: row.get::<_, i64>(3)? as u64,
                    key_packages: row.get::<_, i64>(4)? as u64,
                    snapshots: row.get::<_, i64>(5)? as u64,
                    bytes: row.get::<_, i64>(6)? as u64,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }
}

impl Store {
    /// The quota figures of a hosted Resource; `None` if it is not hosted.
    pub async fn usage(&self, resource: ResourceId) -> Result<Option<Usage>, StoreError> {
        self.call(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT h.host, u.bytes,
                       (SELECT COUNT(*) FROM hosting h2 WHERE h2.host = h.host),
                       (SELECT COALESCE(SUM(u2.bytes), 0) FROM hosting h2
                          JOIN resource_usage u2 ON u2.resource_id = h2.resource_id
                          WHERE h2.host = h.host),
                       (SELECT COALESCE(SUM(bytes), 0) FROM resource_usage)
                     FROM hosting h JOIN resource_usage u ON u.resource_id = h.resource_id
                     WHERE h.resource_id = ?1",
                    [resource.as_bytes().as_slice()],
                    |row| {
                        Ok(Usage {
                            host: PrincipalId::from_bytes(*id32(row.get(0)?).as_bytes()),
                            resource_bytes: row.get::<_, i64>(1)? as u64,
                            host_resources: row.get::<_, i64>(2)? as u64,
                            host_bytes: row.get::<_, i64>(3)? as u64,
                            total_bytes: row.get::<_, i64>(4)? as u64,
                        })
                    },
                )
                .optional()?)
        })
        .await
    }

    /// The Resources `principal` hosts here and their stored bytes.
    pub async fn principal_usage(&self, principal: PrincipalId) -> Result<(u64, u64), StoreError> {
        self.call(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(u.bytes), 0) FROM hosting h
                   JOIN resource_usage u ON u.resource_id = h.resource_id WHERE h.host = ?1",
                [principal.as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
            )?)
        })
        .await
    }

    /// The stored bytes of every Resource.
    pub async fn total_bytes(&self) -> Result<u64, StoreError> {
        self.call(|conn| {
            Ok(conn.query_row(
                "SELECT COALESCE(SUM(bytes), 0) FROM resource_usage",
                [],
                |row| row.get::<_, i64>(0),
            )? as u64)
        })
        .await
    }

    /// Every quota override.
    pub async fn quota_overrides(&self) -> Result<Vec<(PrincipalId, QuotaOverride)>, StoreError> {
        self.call(|conn| {
            let mut stmt = conn.prepare(
                "SELECT principal, resources, bytes, resource_bytes FROM quota_overrides ORDER BY principal",
            )?;
            let rows = stmt.query_map([], |row| {
                let n = |i: usize| row.get::<_, Option<i64>>(i).map(|v| v.map(|v| v as u64));
                Ok((
                    PrincipalId::from_bytes(*id32(row.get(0)?).as_bytes()),
                    QuotaOverride {
                        resources: n(1)?,
                        bytes: n(2)?,
                        resource_bytes: n(3)?,
                    },
                ))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    /// Set `principal`'s quota override.
    pub async fn set_quota_override(
        &self,
        principal: PrincipalId,
        quota: QuotaOverride,
    ) -> Result<(), StoreError> {
        let n = |v: Option<u64>| v.map(i64_of).transpose();
        let (resources, bytes, resource_bytes) = (
            n(quota.resources)?,
            n(quota.bytes)?,
            n(quota.resource_bytes)?,
        );
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO quota_overrides (principal, resources, bytes, resource_bytes) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (principal) DO UPDATE SET resources = ?2, bytes = ?3, resource_bytes = ?4",
                params![principal.as_bytes().as_slice(), resources, bytes, resource_bytes],
            )?;
            Ok(())
        })
        .await
    }

    /// Remove `principal`'s quota override; whether there was one.
    pub async fn delete_quota_override(&self, principal: PrincipalId) -> Result<bool, StoreError> {
        self.call(move |conn| {
            Ok(conn.execute(
                "DELETE FROM quota_overrides WHERE principal = ?1",
                [principal.as_bytes().as_slice()],
            )? == 1)
        })
        .await
    }
}

/// The objects a GET reply lists, in reply order (WIRE-01 §45, §49, §52):
/// read a page at a time ([`Store::plan_page`], [`Store::read_page`]), so a
/// reply never holds a whole Resource in memory (security review H6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// Control Records with sequence in `from..=to`, by sequence then
    /// record ID.
    Control {
        /// The Resource.
        resource: ResourceId,
        /// The first sequence.
        from: u64,
        /// The last sequence.
        to: u64,
    },
    /// Data Units of each `(actor, start, end)` range in turn, by sequence
    /// then unit ID. Ranges must not overlap, or a unit is listed twice.
    Data {
        /// The Resource.
        resource: ResourceId,
        /// The ranges, in reply order.
        ranges: Vec<(PrincipalId, u64, u64)>,
    },
    /// Key Packages for `recipient` at each epoch in turn, by package ID.
    /// Epochs must be distinct.
    KeyPackages {
        /// The Resource.
        resource: ResourceId,
        /// The recipient.
        recipient: PrincipalId,
        /// The epochs, in reply order.
        epochs: Vec<u64>,
    },
}

/// A row's position in its segment: (sequence or epoch, object ID).
type Key = (i64, Vec<u8>);

/// Where a [`Listing`] continues: after `key` in segment `segment` (a
/// Data range or a Key Package epoch; Control has one).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cursor {
    segment: usize,
    key: Option<Key>,
}

/// The next page of a [`Listing`], sized but not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePlan {
    /// The objects that fit.
    pub count: usize,
    /// Their total [`page_cost`].
    pub cost: usize,
    /// Whether objects follow them.
    pub more: bool,
}

/// A page of a [`Listing`]'s objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The exact bytes of each object, in order.
    pub objects: Vec<Vec<u8>>,
    /// Their total [`page_cost`].
    pub cost: usize,
    /// Where the listing continues.
    pub next: Cursor,
}

/// An object's cost in a page: its size plus a CBOR byte-string header
/// (at most 9 bytes).
pub fn page_cost(len: usize) -> usize {
    len + 9
}

impl Listing {
    fn segments(&self) -> usize {
        match self {
            Listing::Control { .. } => 1,
            Listing::Data { ranges, .. } => ranges.len(),
            Listing::KeyPackages { epochs, .. } => epochs.len(),
        }
    }

    /// Visit segment `segment`'s rows after `after` in order, with their
    /// key and size and, if `bytes`, their bytes, while `visit` returns
    /// true.
    fn scan(
        &self,
        conn: &Connection,
        segment: usize,
        after: &Key,
        bytes: bool,
        visit: &mut dyn FnMut(Key, usize, Option<Vec<u8>>) -> bool,
    ) -> Result<(), StoreError> {
        let column = if bytes { ", bytes" } else { "" };
        let (sql, binds): (String, Vec<rusqlite::types::Value>) = match self {
            Listing::Control { resource, from, to } => (
                format!(
                    "SELECT seq, record_id, length(bytes){column} FROM control_records
                     WHERE resource_id = ?1 AND seq BETWEEN ?2 AND ?3 AND (seq, record_id) > (?4, ?5)
                     ORDER BY seq, record_id"
                ),
                vec![
                    resource.as_bytes().to_vec().into(),
                    i64_of(*from)?.into(),
                    i64_of((*to).min(i64::MAX as u64))?.into(),
                ],
            ),
            Listing::Data { resource, ranges } => {
                let (_, start, end) = ranges[segment];
                (
                    format!(
                        "SELECT seq, unit_id, length(bytes){column} FROM data_units
                         WHERE resource_id = ?1 AND actor = ?6 AND seq BETWEEN ?2 AND ?3 AND (seq, unit_id) > (?4, ?5)
                         ORDER BY seq, unit_id"
                    ),
                    vec![
                        resource.as_bytes().to_vec().into(),
                        i64_of(start)?.into(),
                        i64_of(end.min(i64::MAX as u64))?.into(),
                    ],
                )
            }
            Listing::KeyPackages {
                resource, epochs, ..
            } => {
                let epoch = i64_of(epochs[segment])?;
                (
                    format!(
                        "SELECT epoch, package_id, length(bytes){column} FROM key_packages
                         WHERE resource_id = ?1 AND recipient = ?6 AND epoch BETWEEN ?2 AND ?3 AND (epoch, package_id) > (?4, ?5)
                         ORDER BY package_id"
                    ),
                    vec![
                        resource.as_bytes().to_vec().into(),
                        epoch.into(),
                        epoch.into(),
                    ],
                )
            }
        };
        let mut binds = binds;
        binds.push(after.0.into());
        binds.push(after.1.clone().into());
        match self {
            Listing::Data { ranges, .. } => {
                binds.push(ranges[segment].0.as_bytes().to_vec().into())
            }
            Listing::KeyPackages { recipient, .. } => {
                binds.push(recipient.as_bytes().to_vec().into())
            }
            Listing::Control { .. } => {}
        }
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(binds))?;
        while let Some(row) = rows.next()? {
            let key = (row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?);
            let len = row.get::<_, i64>(2)? as usize;
            let object = if bytes { Some(row.get(3)?) } else { None };
            if !visit(key, len, object) {
                break;
            }
        }
        Ok(())
    }

    /// Walk the listing from `cursor`: each object's key, size and, if
    /// `bytes`, bytes, while `visit` returns true. Returns the cursor after
    /// the last object visited with true.
    fn walk(
        &self,
        conn: &Connection,
        cursor: &Cursor,
        bytes: bool,
        visit: &mut dyn FnMut(usize, Option<Vec<u8>>) -> bool,
    ) -> Result<Cursor, StoreError> {
        let start = (i64::MIN, Vec::new());
        let mut position = cursor.clone();
        let mut stopped = false;
        while position.segment < self.segments() {
            let after = position.key.clone().unwrap_or_else(|| start.clone());
            let segment = position.segment;
            self.scan(conn, segment, &after, bytes, &mut |key, len, object| {
                if visit(len, object) {
                    position.key = Some(key);
                    true
                } else {
                    stopped = true;
                    false
                }
            })?;
            if stopped {
                break;
            }
            position = Cursor {
                segment: segment + 1,
                key: None,
            };
        }
        Ok(position)
    }
}

/// Whether an object of `cost` joins a page holding `count` objects of
/// `size`: the first always does, later ones while the page stays within
/// `budget`.
fn fits(count: usize, size: usize, cost: usize, budget: usize) -> bool {
    count == 0 || size + cost <= budget
}

impl Store {
    /// Size the next page of `listing` from `cursor`: the objects whose
    /// [`page_cost`]s fit `budget` (at least one, if any is left). Reads
    /// sizes only, never the objects.
    pub async fn plan_page(
        &self,
        listing: Listing,
        cursor: Cursor,
        budget: usize,
    ) -> Result<PagePlan, StoreError> {
        self.call(move |conn| {
            let mut plan = PagePlan {
                count: 0,
                cost: 0,
                more: false,
            };
            listing.walk(conn, &cursor, false, &mut |len, _| {
                let cost = page_cost(len);
                if fits(plan.count, plan.cost, cost, budget) {
                    plan.count += 1;
                    plan.cost += cost;
                    true
                } else {
                    plan.more = true;
                    false
                }
            })?;
            Ok(plan)
        })
        .await
    }

    /// Read at most `count` objects of `listing` from `cursor`, of at most
    /// `budget` total [`page_cost`] (objects stored since the plan can
    /// only make the page shorter).
    pub async fn read_page(
        &self,
        listing: Listing,
        cursor: Cursor,
        count: usize,
        budget: usize,
    ) -> Result<Page, StoreError> {
        self.call(move |conn| {
            let mut objects = Vec::new();
            let mut cost = 0;
            let next = listing.walk(conn, &cursor, true, &mut |len, object| {
                let object_cost = page_cost(len);
                if objects.len() < count && cost + object_cost <= budget {
                    cost += object_cost;
                    objects.push(object.expect("bytes were read"));
                    true
                } else {
                    false
                }
            })?;
            Ok(Page {
                objects,
                cost,
                next,
            })
        })
        .await
    }
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
