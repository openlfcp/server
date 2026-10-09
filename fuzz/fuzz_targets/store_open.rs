//! The store opened on a corrupted or truncated database
//! (`server.sqlite3`, optionally with a `-wal` file): `Store::open` returns
//! an error or a store, never panics; an opened store answers every read
//! with a value or an error, never panics, and closes.
//!
//! Input: `[flags][db len u32 LE][db bytes][wal bytes]`. Flag bit 0: write
//! the WAL file too.

#![no_main]

use lfcp_server::store::Store;
use lfcp_server_fuzz::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let flags = data[0];
    let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
    let rest = &data[5..];
    let (db, wal) = rest.split_at(len.min(rest.len()));
    let dir = fresh_dir();
    std::fs::create_dir_all(&dir).expect("a directory");
    let path = dir.join(lfcp_server::store::DATABASE_FILE);
    std::fs::write(&path, db).expect("the database file");
    if flags & 1 != 0 {
        let mut w = path.clone().into_os_string();
        w.push("-wal");
        std::fs::write(&w, wal).expect("the WAL file");
    }
    if let Ok(store) = Store::open(&dir) {
        runtime().block_on(async {
            let r = resource();
            let _ = store.schema_version().await;
            let _ = store.resource(r).await;
            let _ = store.head(r).await;
            let _ = store.control_records(r, 0, 16).await;
            let _ = store.data_sequences(r).await;
            let _ = store.snapshots(r).await;
            let _ = store.admins().await;
            let _ = store.resource_sizes().await;
            let _ = store.usage(r).await;
            let _ = store.total_bytes().await;
            let _ = store.quota_overrides().await;
            let _ = store.setting("server_name").await;
        });
        drop(store);
    }
    let _ = std::fs::remove_dir_all(&dir);
});
