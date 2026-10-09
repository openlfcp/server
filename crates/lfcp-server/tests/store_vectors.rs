//! The store against LFCP-TEST-VECTORS-01 at the spec.lock pin: every
//! published object type round-trips byte for byte with its derived index
//! values, forks and equivocation are representable, Key Package
//! alternatives are kept, and no plaintext reaches the database.

mod support;

use std::sync::Arc;

use lfcp::base::{ControlRecordId, Hash32, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::ReceivedControlRecord;
use lfcp::wire::data_unit::ReceivedDataUnit;
use lfcp::wire::key_package::{KeyPackage, ReceivedKeyPackage};
use lfcp::wire::keys::Dek;
use lfcp::wire::snapshot::ReceivedSnapshot;
use lfcp_server::store::{schema, CasOutcome, Hosting, Put, Store, StoreError, DATABASE_FILE};
use serde_json::Value as Json;
use support::spec::Spec;

const CHAIN: [&str; 11] = [
    "C0_genesis",
    "C1_grant_bob",
    "C2_invite_grant",
    "C3_invite_claim_carol",
    "C4_owner_transfer_commit",
    "C5_route_update",
    "C6_key_epoch_1",
    "C7_grant_carol_delegator",
    "C8_grant_owner_delegated",
    "C9_grant_invite_grandchild",
    "C10_revoke_grandchild",
];
const UNITS: [&str; 4] = [
    "D1_bob_epoch0_seq1",
    "D2_bob_epoch0_seq2",
    "D3_bob_epoch0_seq3_stale",
    "D4_carol_epoch1_seq1",
];
const PACKAGES: [&str; 3] = ["KP0_bob_epoch0", "KPI_invite_epoch0", "KPC_carol_epoch1"];
const SNAPSHOTS: [&str; 2] = ["SNAPSHOT-01", "SNAPSHOT-02"];

struct Vectors(Json);

impl Vectors {
    fn load() -> Vectors {
        Vectors(Spec::open().read_json("test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json"))
    }
    fn case(&self, id: &str) -> &Json {
        self.0["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("{id}"))
    }
    fn hex(&self, id: &str, part: &str, field: &str) -> Vec<u8> {
        lfcp::base::from_hex(
            self.case(id)[part][field]["hex"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}.{field}")),
        )
        .unwrap()
    }
    fn cose(&self, id: &str) -> Vec<u8> {
        self.hex(id, "expected", "cose_sign1")
    }
    fn principal(&self, name: &str) -> PrincipalKeys {
        let inputs = &self.case(&format!("principal_{name}"))["inputs"];
        let h = |f: &str| -> [u8; 32] {
            lfcp::base::from_hex(inputs[f]["hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        PrincipalKeys::from_secrets(&h("ed25519_seed"), h("x25519_private"))
    }
    fn resource(&self) -> ResourceId {
        ResourceId::from_slice(
            &lfcp::base::from_hex(
                self.0["fixtures"]["resource"]["id"]["hex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lfcp-store-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn host_principal(v: &Vectors) -> Hosting {
    Hosting {
        host: *v.principal("owner").descriptor().id(),
        durability: 2,
    }
}

/// A store holding the whole published chain C0–C10, committed in order.
async fn chain_store(v: &Vectors, dir: &std::path::Path) -> Store {
    let store = Store::open(dir).unwrap();
    assert_eq!(
        store
            .host_resource(v.cose("C0_genesis"), host_principal(v))
            .await
            .unwrap(),
        Put::Inserted
    );
    for pair in CHAIN.windows(2) {
        let expected =
            ControlRecordId::from_slice(&v.hex(pair[0], "expected", "record_id")).unwrap();
        let outcome = store
            .commit_control_record(v.cose(pair[1]), expected)
            .await
            .unwrap();
        assert_eq!(outcome, CasOutcome::Committed(Put::Inserted), "{}", pair[1]);
    }
    store
}

#[tokio::test(flavor = "multi_thread")]
async fn control_chain_round_trips_with_derived_indexes() {
    let v = Vectors::load();
    let dir = temp_dir("chain");
    let store = chain_store(&v, &dir).await;
    let resource = v.resource();

    let info = store.resource(resource).await.unwrap().expect("hosted");
    assert_eq!(
        info.genesis.as_bytes().as_slice(),
        v.hex("C0_genesis", "expected", "record_id")
    );
    assert_eq!(info.head.seq, 10);
    assert_eq!(
        info.head.id.as_bytes().as_slice(),
        v.hex("C10_revoke_grandchild", "expected", "record_id")
    );
    assert_eq!(info.hosting, host_principal(&v));

    let stored = store.control_records(resource, 0, u64::MAX).await.unwrap();
    assert_eq!(stored.len(), 11);
    for (record, id) in stored.iter().zip(CHAIN) {
        assert_eq!(record.bytes, v.cose(id), "{id}: exact bytes");
        // Index values equal what sdk-rs reads from the exact bytes.
        let parsed = ReceivedControlRecord::parse(&record.bytes).unwrap();
        assert_eq!(record.id, parsed.id(), "{id}");
        assert_eq!(
            record.id.as_bytes().as_slice(),
            v.hex(id, "expected", "record_id"),
            "{id}"
        );
        assert_eq!(record.seq, parsed.header().sequence, "{id}");
        assert_eq!(record.previous, parsed.header().previous, "{id}");
        assert_eq!(record.issuer, parsed.header().issuer, "{id}");
        assert_eq!(record.control_type, parsed.body().control_type(), "{id}");
    }

    // Re-hosting the same Genesis and re-committing are duplicates.
    assert_eq!(
        store
            .host_resource(v.cose("C0_genesis"), host_principal(&v))
            .await
            .unwrap(),
        Put::Duplicate
    );
    // A competing Genesis for the Resource is refused.
    let competing = v.hex("genesis_competing_root", "inputs", "cose_sign1");
    assert!(matches!(
        store.host_resource(competing, host_principal(&v)).await,
        Err(StoreError::GenesisConflict { .. })
    ));
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn head_compare_and_set() {
    let v = Vectors::load();
    let dir = temp_dir("cas");
    let store = Store::open(&dir).unwrap();
    store
        .host_resource(v.cose("C0_genesis"), host_principal(&v))
        .await
        .unwrap();
    let c0 = ControlRecordId::from_slice(&v.hex("C0_genesis", "expected", "record_id")).unwrap();
    let c1 = ControlRecordId::from_slice(&v.hex("C1_grant_bob", "expected", "record_id")).unwrap();

    // C2 does not continue C0.
    assert_eq!(
        store
            .commit_control_record(v.cose("C2_invite_grant"), c0)
            .await
            .unwrap(),
        CasOutcome::NotSuccessor
    );
    assert_eq!(
        store
            .commit_control_record(v.cose("C1_grant_bob"), c0)
            .await
            .unwrap(),
        CasOutcome::Committed(Put::Inserted)
    );
    // A stale expected head: nothing changes, the current head is reported.
    let stale = store
        .commit_control_record(v.cose("C2_invite_grant"), c0)
        .await
        .unwrap();
    assert!(
        matches!(stale, CasOutcome::HeadMismatch { current } if current.id == c1 && current.seq == 1)
    );
    assert_eq!(
        store.control_records(v.resource(), 2, 2).await.unwrap(),
        vec![],
        "nothing stored on mismatch"
    );
    // A Genesis cannot be committed as a successor, nor stored as a record.
    assert_eq!(
        store.commit_control_record(v.cose("C0_genesis"), c1).await,
        Err(StoreError::WrongRecordType)
    );
    assert_eq!(
        store.put_control_record(v.cose("C0_genesis")).await,
        Err(StoreError::WrongRecordType)
    );
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_control_records_are_kept_as_evidence() {
    let v = Vectors::load();
    let dir = temp_dir("fork");
    let store = chain_store(&v, &dir).await;
    let fork = v.hex("control_fork_C6", "inputs", "cose_sign1");
    assert_eq!(
        store.put_control_record(fork.clone()).await.unwrap(),
        Put::Inserted
    );
    let at6 = store.control_records(v.resource(), 6, 6).await.unwrap();
    assert_eq!(at6.len(), 2, "C6 and its competitor");
    assert!(at6.iter().any(|r| r.bytes == fork));
    assert!(at6.iter().any(|r| r.bytes == v.cose("C6_key_epoch_1")));
    // Storing the competitor does not move the head.
    assert_eq!(store.head(v.resource()).await.unwrap().unwrap().seq, 10);
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn data_units_round_trip_and_equivocation_is_storable() {
    let v = Vectors::load();
    let dir = temp_dir("units");
    let store = chain_store(&v, &dir).await;
    for id in UNITS {
        assert_eq!(
            store.put_data_unit(v.cose(id)).await.unwrap(),
            Put::Inserted,
            "{id}"
        );
        assert_eq!(
            store.put_data_unit(v.cose(id)).await.unwrap(),
            Put::Duplicate,
            "{id}"
        );
        let unit_id = Hash32::from_slice(&v.hex(id, "expected", "unit_id")).unwrap();
        assert_eq!(
            store.data_unit(unit_id).await.unwrap(),
            Some(v.cose(id)),
            "{id}: exact bytes"
        );
        let h = ReceivedDataUnit::parse(&v.cose(id))
            .unwrap()
            .header()
            .clone();
        assert_eq!(
            store
                .data_units_at(h.resource_id, h.actor, h.sequence)
                .await
                .unwrap(),
            vec![unit_id],
            "{id}: (resource, actor, seq) index"
        );
    }
    // actor_equivocation: another unit for (BOB, 2) is stored next to D2.
    let conflicting = v.hex("actor_equivocation", "inputs", "conflicting_D2_cose");
    assert_eq!(
        store.put_data_unit(conflicting.clone()).await.unwrap(),
        Put::Inserted
    );
    let h = ReceivedDataUnit::parse(&conflicting)
        .unwrap()
        .header()
        .clone();
    let at = store
        .data_units_at(h.resource_id, h.actor, h.sequence)
        .await
        .unwrap();
    assert_eq!(at.len(), 2, "equivocation evidence");
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn key_packages_keep_alternatives() {
    let v = Vectors::load();
    let dir = temp_dir("packages");
    let store = chain_store(&v, &dir).await;
    for id in PACKAGES {
        assert_eq!(
            store.put_key_package(v.cose(id)).await.unwrap(),
            Put::Inserted,
            "{id}"
        );
        let h = ReceivedKeyPackage::parse(&v.cose(id))
            .unwrap()
            .header()
            .clone();
        let stored = store
            .key_packages_for(h.resource_id, h.data_epoch, h.recipient)
            .await
            .unwrap();
        assert_eq!(stored.len(), 1, "{id}");
        assert_eq!(stored[0].bytes, v.cose(id), "{id}: exact bytes");
        assert_eq!(
            stored[0].id.as_bytes().as_slice(),
            v.hex(id, "expected", "package_id"),
            "{id}"
        );
    }
    // A second valid package for KP0's (resource, epoch 0, BOB), freshly
    // sealed by the same sender: both are kept (WIRE-01 §25.2).
    let kp0 = ReceivedKeyPackage::parse(&v.cose("KP0_bob_epoch0"))
        .unwrap()
        .header()
        .clone();
    let dek = Dek::from_bytes(
        lfcp::base::from_hex(v.0["fixtures"]["resource"]["dek0"]["hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let bob = v.principal("bob");
    let sender = v.principal("owner");
    assert_eq!(&kp0.sender, sender.descriptor().id());
    let alternative = KeyPackage::seal(
        kp0.resource_id,
        0,
        kp0.control_head,
        &dek,
        bob.descriptor(),
        &sender,
    )
    .unwrap();
    assert_eq!(
        store
            .put_key_package(alternative.signed_object().bytes().to_vec())
            .await
            .unwrap(),
        Put::Inserted
    );
    let both = store
        .key_packages_for(kp0.resource_id, 0, kp0.recipient)
        .await
        .unwrap();
    assert_eq!(both.len(), 2);
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshots_round_trip() {
    let v = Vectors::load();
    let dir = temp_dir("snapshots");
    let store = chain_store(&v, &dir).await;
    for id in SNAPSHOTS {
        assert_eq!(
            store.put_snapshot(v.cose(id)).await.unwrap(),
            Put::Inserted,
            "{id}"
        );
        let snapshot_id = Hash32::from_slice(&v.hex(id, "expected", "snapshot_id")).unwrap();
        assert_eq!(
            ReceivedSnapshot::parse(&v.cose(id)).unwrap().id(),
            snapshot_id,
            "{id}"
        );
        assert_eq!(
            store.snapshot(snapshot_id).await.unwrap(),
            Some(v.cose(id)),
            "{id}: exact bytes"
        );
    }
    // SNAPSHOT-02 (sequence 2) comes before SNAPSHOT-01 for the same
    // publisher and epoch.
    let listed: Vec<Vec<u8>> = store
        .snapshots(v.resource())
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.bytes)
        .collect();
    assert_eq!(listed, vec![v.cose("SNAPSHOT-02"), v.cose("SNAPSHOT-01")]);
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn objects_need_a_hosted_resource_and_valid_bytes() {
    let v = Vectors::load();
    let dir = temp_dir("unknown");
    let store = Store::open(&dir).unwrap();
    assert_eq!(
        store.put_data_unit(v.cose("D1_bob_epoch0_seq1")).await,
        Err(StoreError::UnknownResource)
    );
    assert_eq!(
        store.put_control_record(v.cose("C1_grant_bob")).await,
        Err(StoreError::UnknownResource)
    );
    assert!(matches!(
        store.put_data_unit(vec![0x80]).await,
        Err(StoreError::Malformed(_))
    ));
    assert!(matches!(
        store
            .put_data_unit(v.hex("tagged_cose_D1", "inputs", "cose_sign1"))
            .await,
        Err(StoreError::Malformed(_))
    ));
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn no_plaintext_and_no_application_schema() {
    let v = Vectors::load();
    let dir = temp_dir("opaque");
    let store = chain_store(&v, &dir).await;
    for id in UNITS {
        store.put_data_unit(v.cose(id)).await.unwrap();
    }
    for id in SNAPSHOTS {
        store.put_snapshot(v.cose(id)).await.unwrap();
    }
    for id in PACKAGES {
        store.put_key_package(v.cose(id)).await.unwrap();
    }
    let path = store.path().to_path_buf();
    drop(store);

    // The plaintexts of D1–D4 and the Snapshots appear nowhere in the
    // database or its WAL: only ciphertext is stored.
    let mut files = Vec::new();
    for name in [DATABASE_FILE.to_owned(), format!("{DATABASE_FILE}-wal")] {
        if let Ok(bytes) = std::fs::read(dir.join(name)) {
            files.extend(bytes);
        }
    }
    for id in UNITS.iter().chain(SNAPSHOTS.iter()) {
        let plaintext = v.case(id)["inputs"]["plaintext_utf8"].as_str().unwrap();
        assert!(
            !files
                .windows(plaintext.len())
                .any(|w| w == plaintext.as_bytes()),
            "{id}: plaintext stored"
        );
        let ciphertext = v.hex(id, "expected", "ciphertext");
        assert!(
            files.windows(ciphertext.len()).any(|w| w == ciphertext),
            "{id}: ciphertext is stored"
        );
    }

    // No table or column for application data.
    let mut names = Vec::new();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let mut tables = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap();
        for table in tables.query_map([], |r| r.get::<_, String>(0)).unwrap() {
            let table = table.unwrap();
            let mut columns = conn
                .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .unwrap();
            names.extend(
                columns
                    .query_map([], |r| r.get::<_, String>(0))
                    .unwrap()
                    .map(Result::unwrap),
            );
            names.push(table);
        }
    }
    for name in &names {
        for forbidden in [
            "task",
            "title",
            "status",
            "plaintext",
            "automerge",
            "markdown",
            "json",
        ] {
            assert!(
                !name.contains(forbidden),
                "{name} looks like application data"
            );
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_writers_are_serialized() {
    let v = Arc::new(Vectors::load());
    let dir = temp_dir("concurrent");
    let store = Arc::new(chain_store(&v, &dir).await);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        for id in UNITS {
            let (store, bytes) = (store.clone(), v.cose(id));
            tasks.push(tokio::spawn(async move {
                store.put_data_unit(bytes).await.unwrap()
            }));
        }
    }
    let mut inserted = 0;
    for task in tasks {
        if task.await.unwrap() == Put::Inserted {
            inserted += 1;
        }
    }
    assert_eq!(inserted, UNITS.len(), "each unit inserted exactly once");

    // Concurrent compare-and-set from one expected head: one wins.
    let dir2 = temp_dir("concurrent-cas");
    let store2 = Arc::new(Store::open(&dir2).unwrap());
    store2
        .host_resource(v.cose("C0_genesis"), host_principal(&v))
        .await
        .unwrap();
    let c0 = ControlRecordId::from_slice(&v.hex("C0_genesis", "expected", "record_id")).unwrap();
    let racers: Vec<_> = (0..8)
        .map(|_| {
            let (store, bytes) = (store2.clone(), v.cose("C1_grant_bob"));
            tokio::spawn(async move { store.commit_control_record(bytes, c0).await.unwrap() })
        })
        .collect();
    let mut wins = 0;
    for racer in racers {
        match racer.await.unwrap() {
            CasOutcome::Committed(Put::Inserted) => wins += 1,
            CasOutcome::HeadMismatch { current } => assert_eq!(current.seq, 1),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(wins, 1);
    drop((store, store2));
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&dir2).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn reopening_keeps_everything_and_migrations_run_once() {
    let v = Vectors::load();
    let dir = temp_dir("reopen");
    {
        let store = chain_store(&v, &dir).await;
        assert_eq!(
            store.schema_version().await.unwrap(),
            schema::latest_version()
        );
        store
            .put_data_unit(v.cose("D1_bob_epoch0_seq1"))
            .await
            .unwrap();
        // Dropped without any explicit close or checkpoint.
    }
    let store = Store::open(&dir).unwrap();
    assert_eq!(
        store.schema_version().await.unwrap(),
        schema::latest_version()
    );
    assert_eq!(store.head(v.resource()).await.unwrap().unwrap().seq, 10);
    let d1 = Hash32::from_slice(&v.hex("D1_bob_epoch0_seq1", "expected", "unit_id")).unwrap();
    assert_eq!(
        store.data_unit(d1).await.unwrap(),
        Some(v.cose("D1_bob_epoch0_seq1"))
    );
    let path = store.path().to_path_buf();
    drop(store);

    let conn = rusqlite::Connection::open(&path).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let check: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(check, "ok");
    drop(conn);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// LFCP-02-116: a store written by a newer server (schema version above
/// every migration this code knows) is refused with a clear error, and
/// none of its files changes; once the version is one this code knows
/// again, it opens.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_of_a_newer_server_is_refused_unchanged() {
    let v = Vectors::load();
    let dir = temp_dir("newer-schema");
    let path = {
        let store = chain_store(&v, &dir).await;
        store.path().to_path_buf()
    };
    let newer = schema::latest_version() + 1;
    let set_version = |version: u32| {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE schema_version SET version = ?1", [version])
            .unwrap();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
    };
    set_version(newer);
    let files = || {
        let mut all: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            // The store's files; the server binary also keeps its identity here.
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(DATABASE_FILE)
            })
            .map(|p| {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read(&p).unwrap())
            })
            .collect();
        all.sort();
        all
    };
    let before = files();

    match Store::open(&dir) {
        Err(StoreError::NewerSchema { found, supported }) => {
            assert_eq!(found, newer);
            assert_eq!(supported, schema::latest_version());
        }
        Err(other) => panic!("another error: {other}"),
        Ok(_) => panic!("a store of a newer server was opened"),
    }
    let message = StoreError::NewerSchema {
        found: newer,
        supported: schema::latest_version(),
    }
    .to_string();
    assert!(
        message.contains(&format!("schema version {newer}")),
        "{message}"
    );
    assert!(message.contains("left unchanged"), "{message}");
    assert_eq!(files(), before, "the refused store's files changed");

    // The server binary exits with the error and leaves the files too.
    let config = dir.with_extension("toml");
    std::fs::write(
        &config,
        format!(
            "bind = \"127.0.0.1:0\"\nstate_dir = \"{}\"\npublic_urls = [\"wss://sync-a.example.test/v1/ws\"]\n",
            dir.display()
        ),
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_lfcp-server"))
        .args(["--config", config.to_str().unwrap()])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "the server started: {printed}");
    assert!(
        printed.contains("newer than this server supports"),
        "{printed}"
    );
    assert_eq!(
        files(),
        before,
        "the server binary changed the store's files"
    );
    std::fs::remove_file(&config).unwrap();

    set_version(schema::latest_version());
    let store = Store::open(&dir).unwrap();
    assert_eq!(store.head(v.resource()).await.unwrap().unwrap().seq, 10);
    drop(store);

    // The newer version only in the WAL (a server stopped without a
    // checkpoint): refused as well.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.query_row("PRAGMA wal_autocheckpoint = 0", [], |_| Ok(()))
        .unwrap();
    conn.execute("UPDATE schema_version SET version = ?1", [newer])
        .unwrap();
    assert!(matches!(
        Store::open(&dir),
        Err(StoreError::NewerSchema { found, .. }) if found == newer
    ));
    drop(conn);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn migrating_an_empty_database_is_deterministic() {
    let schema_of = |name: &str| {
        let dir = temp_dir(name);
        std::fs::create_dir_all(&dir).unwrap();
        let mut conn = rusqlite::Connection::open(dir.join(DATABASE_FILE)).unwrap();
        assert_eq!(schema::version(&conn).unwrap(), 0);
        assert_eq!(
            schema::migrate(&mut conn).unwrap(),
            schema::latest_version()
        );
        assert_eq!(
            schema::migrate(&mut conn).unwrap(),
            schema::latest_version(),
            "idempotent"
        );
        let sql: Vec<String> = conn
            .prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        drop(conn);
        std::fs::remove_dir_all(&dir).unwrap();
        sql
    };
    assert_eq!(schema_of("migrate-a"), schema_of("migrate-b"));
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_bytes_are_accounted_and_backfilled() {
    use lfcp_server::store::QuotaOverride;
    let v = Vectors::load();
    let dir = temp_dir("usage");
    let store = chain_store(&v, &dir).await;
    let resource = v.resource();
    let owner = *v.principal("owner").descriptor().id();
    for id in UNITS {
        store.put_data_unit(v.cose(id)).await.unwrap();
    }
    for id in SNAPSHOTS {
        store.put_snapshot(v.cose(id)).await.unwrap();
    }
    for id in PACKAGES {
        store.put_key_package(v.cose(id)).await.unwrap();
    }
    // Duplicates add nothing.
    store.put_data_unit(v.cose(UNITS[0])).await.unwrap();
    store.put_snapshot(v.cose(SNAPSHOTS[0])).await.unwrap();
    let sizes = store.resource_sizes().await.unwrap();
    let bytes = sizes[0].bytes;
    assert!(bytes > 0);
    let usage = store.usage(resource).await.unwrap().expect("hosted");
    assert_eq!(usage.host, owner);
    assert_eq!(usage.resource_bytes, bytes);
    assert_eq!((usage.host_resources, usage.host_bytes), (1, bytes));
    assert_eq!(usage.total_bytes, bytes);
    assert_eq!(store.principal_usage(owner).await.unwrap(), (1, bytes));
    assert_eq!(
        store
            .principal_usage(lfcp::base::PrincipalId::from_bytes([9; 32]))
            .await
            .unwrap(),
        (0, 0)
    );
    assert_eq!(store.total_bytes().await.unwrap(), bytes);
    assert_eq!(
        store.usage(ResourceId::from_bytes([9; 32])).await.unwrap(),
        None
    );

    // Overrides round-trip.
    let quota = QuotaOverride {
        resources: Some(3),
        bytes: None,
        resource_bytes: Some(1 << 30),
    };
    store.set_quota_override(owner, quota).await.unwrap();
    assert_eq!(store.quota_overrides().await.unwrap(), vec![(owner, quota)]);
    assert!(store.delete_quota_override(owner).await.unwrap());
    assert!(!store.delete_quota_override(owner).await.unwrap());
    let path = store.path().to_path_buf();
    drop(store);

    // A database from before migration 3 is backfilled when it opens.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "DROP TRIGGER resource_usage_on_host; DROP TRIGGER resource_usage_on_control;
         DROP TRIGGER resource_usage_on_data; DROP TRIGGER resource_usage_on_key_package;
         DROP TRIGGER resource_usage_on_snapshot; DROP INDEX hosting_by_host;
         DROP TABLE resource_usage; DROP TABLE quota_overrides;
         UPDATE schema_version SET version = 2;",
    )
    .unwrap();
    drop(conn);
    let store = Store::open(&dir).unwrap();
    assert_eq!(
        store.schema_version().await.unwrap(),
        schema::latest_version()
    );
    assert_eq!(store.total_bytes().await.unwrap(), bytes);
    assert_eq!(
        store.usage(resource).await.unwrap().unwrap().resource_bytes,
        bytes
    );
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}
