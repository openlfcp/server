//! Restart durability of the real server process (LFCP-054): the
//! `lfcp-server` binary is spawned on a state directory, driven over the
//! LFCP protocol, then killed with SIGKILL (and, separately, stopped with
//! SIGTERM). A new process on the same directory must still hold every
//! acknowledged object (durability level 2: committed with WAL and
//! `synchronous = FULL`, so up to what SQLite and fsync guarantee), keep
//! its server ID, refuse stale and replayed state changes, and serve a
//! catch-up that converges without duplicates.

#![cfg(unix)]

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lfcp_server::store::{Store, DATABASE_FILE};
use support::durability::{populate, second_package, verify_after_restart, SNAPSHOTS, UNITS};
use support::lfcp::state_dir;
use support::vectors::{Vectors, CHAIN};

/// A running `lfcp-server` process.
struct Process {
    child: Child,
    addr: SocketAddr,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn healthy(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect(addr) else {
        return false;
    };
    let _ = stream.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    reply.starts_with("HTTP/1.1 200")
}

/// Spawn the binary on `state` with both published coordinator URLs.
fn spawn(state: &Path) -> Process {
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let config = state.with_extension("toml");
    std::fs::write(
        &config,
        format!(
            "bind = \"{addr}\"\nstate_dir = \"{}\"\nlog_level = \"warn\"\npublic_urls = [\"wss://sync-a.example.test/v1/ws\", \"wss://sync-b.example.test/v1/ws\"]\n",
            state.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_lfcp-server"))
        .args(["--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !healthy(addr) {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "server did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Process { child, addr }
}

impl Process {
    /// SIGKILL: no shutdown path runs.
    fn kill(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }

    /// SIGTERM: the graceful path.
    fn terminate(mut self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let exit = self.child.wait().unwrap();
        assert!(exit.success(), "graceful exit: {exit:?}");
    }
}

/// After the last process stopped: no duplicate rows, no plaintext.
async fn inspect_store(v: &Vectors, state: &Path) {
    let store = Store::open(state).unwrap();
    let records = store
        .control_records(v.resource(), 0, u64::MAX)
        .await
        .unwrap();
    assert_eq!(records.len(), CHAIN.len(), "one row per Control Record");
    let bob = *v.principal("bob").descriptor().id();
    assert_eq!(
        store
            .data_units_at(v.resource(), bob, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .data_units_at(v.resource(), bob, 2)
            .await
            .unwrap()
            .len(),
        2,
        "D2 and its equivocating twin, once each"
    );
    assert_eq!(
        store
            .key_packages_for(v.resource(), 0, bob)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(store.snapshots(v.resource()).await.unwrap().len(), 2);
    drop(store);

    let mut bytes = Vec::new();
    for entry in std::fs::read_dir(state).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(DATABASE_FILE)
        {
            bytes.extend(std::fs::read(&path).unwrap());
        }
    }
    for case in UNITS.iter().chain(SNAPSHOTS.iter()) {
        let plaintext = v.case(case)["inputs"]["plaintext_utf8"].as_str().unwrap();
        assert!(
            !bytes
                .windows(plaintext.len())
                .any(|w| w == plaintext.as_bytes()),
            "{case}: plaintext stored"
        );
    }
}

fn fresh(name: &str) -> PathBuf {
    let dir = state_dir(name);
    let _ = std::fs::remove_file(dir.with_extension("toml"));
    dir
}

fn cleanup(dir: &Path) {
    std::fs::remove_dir_all(dir).unwrap();
    let _ = std::fs::remove_file(dir.with_extension("toml"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_killed_server_keeps_every_acknowledged_object() {
    let v = Vectors::load();
    let dir = fresh("kill");
    let first = spawn(&dir);
    let second_kp = second_package(&v);
    let server_id = populate(&v, first.addr, &second_kp).await;
    // SIGKILL right after the last ACK: no shutdown path, no flush.
    first.kill();

    let second = spawn(&dir);
    verify_after_restart(&v, second.addr, server_id, &second_kp).await;
    second.kill();
    inspect_store(&v, &dir).await;
    cleanup(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gracefully_stopped_server_keeps_its_state() {
    let v = Vectors::load();
    let dir = fresh("term");
    let first = spawn(&dir);
    let second_kp = second_package(&v);
    let server_id = populate(&v, first.addr, &second_kp).await;
    first.terminate();

    let second = spawn(&dir);
    verify_after_restart(&v, second.addr, server_id, &second_kp).await;
    second.terminate();
    inspect_store(&v, &dir).await;
    cleanup(&dir);
}

#[test]
fn the_health_check_mode_reports_the_server_state() {
    let dir = fresh("health-check");
    let process = spawn(&dir);
    let config = dir.with_extension("toml");
    let check = || {
        Command::new(env!("CARGO_BIN_EXE_lfcp-server"))
            .args(["--health-check", "--config", config.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    };
    assert!(check(), "healthy while running");
    process.kill();
    assert!(!check(), "unhealthy once killed");
    cleanup(&dir);
}
