//! A damaged database (fuzzing finding S1, `fuzz/repro/S1-store-open`): an
//! ID column holds a blob of another length, which the schema's
//! `CHECK (length(...) = 32)` catches only when a row is written. The store
//! opens; reading the row is `StoreError::Corrupt`, not a panic of the
//! store thread, and the store keeps answering.

use std::path::PathBuf;

use lfcp::base::ResourceId;
use lfcp_server::store::{Store, StoreError, DATABASE_FILE};

/// The reproducer, in the fuzz target's format:
/// `[flags][db len u32 LE][db bytes][wal bytes]`, flag bit 0 for the WAL.
fn reproducer_dir(name: &str) -> PathBuf {
    let input = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/repro/S1-store-open"),
    )
    .expect("the S1 reproducer");
    let flags = input[0];
    let len = u32::from_le_bytes([input[1], input[2], input[3], input[4]]) as usize;
    let rest = &input[5..];
    let (db, wal) = rest.split_at(len.min(rest.len()));
    let dir = std::env::temp_dir().join(format!("lfcp-store-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(DATABASE_FILE);
    std::fs::write(&path, db).unwrap();
    if flags & 1 != 0 {
        let mut w = path.into_os_string();
        w.push("-wal");
        std::fs::write(&w, wal).unwrap();
    }
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_id_is_corrupt_not_a_panic() {
    let dir = reproducer_dir("s1");
    let store = Store::open(&dir).expect("the damaged store opens");
    let resource = ResourceId::from_bytes([0x42; 32]);
    match store.control_records(resource, 0, 16).await {
        Err(StoreError::Corrupt(what)) => assert!(what.contains("not 32"), "{what}"),
        other => panic!("expected Corrupt, got {other:?}"),
    }
    // The store thread is alive: every read answers, none is Closed.
    assert!(store.schema_version().await.is_ok());
    let answers = [
        store.resource(resource).await.err(),
        store.head(resource).await.err(),
        store.data_sequences(resource).await.err(),
        store.snapshots(resource).await.err(),
        store.admins().await.err(),
        store.resource_sizes().await.err(),
        store.usage(resource).await.err(),
        store.quota_overrides().await.err(),
    ];
    for e in answers.into_iter().flatten() {
        assert!(
            !matches!(e, StoreError::Closed),
            "the store thread stopped: {e}"
        );
    }
    let message = StoreError::Corrupt("an ID of 31 bytes, not 32".into()).to_string();
    assert!(
        message.contains("restore server.sqlite3 from a backup"),
        "{message}"
    );
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}
