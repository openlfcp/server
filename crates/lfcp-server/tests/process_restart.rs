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
    spawn_with_output(state, Stdio::null, "warn")
}

/// [`spawn`], with stdout and stderr going where `output` says.
fn spawn_with_output(state: &Path, output: impl Fn() -> Stdio, log_level: &str) -> Process {
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let config = state.with_extension("toml");
    std::fs::write(
        &config,
        format!(
            "bind = \"{addr}\"\nstate_dir = \"{}\"\nlog_level = \"{log_level}\"\npublic_urls = [\"wss://sync-a.example.test/v1/ws\", \"wss://sync-b.example.test/v1/ws\"]\n",
            state.display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_lfcp-server"))
        .args(["--config", config.to_str().unwrap()])
        .stdout(output())
        .stderr(output())
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

/// LFCP-046: the setup code is printed once, at the first start, and
/// appears nowhere else in the output, through pairing, an admin session
/// and a restart.
#[tokio::test(flavor = "multi_thread")]
async fn the_setup_code_is_printed_once_and_never_logged() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let v = Vectors::load();
    let dir = fresh("setup-code");
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.with_extension("log");
    let file = std::fs::File::create(&log).unwrap();
    let output = || Stdio::from(file.try_clone().unwrap());

    let first = spawn_with_output(&dir, output, "debug");
    let started = Instant::now();
    let code = loop {
        let text = std::fs::read_to_string(&log).unwrap();
        if let Some(rest) = text.split("Admin pairing code:").nth(1) {
            break rest.split_whitespace().next().unwrap().to_owned();
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no code printed"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(code.len(), 9);

    async fn http(addr: SocketAddr, method: &str, path: &str, body: String) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        reply
    }
    let challenge = |reply: String| {
        let body = reply.split_once("\r\n\r\n").unwrap().1.to_owned();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        json["challenge"].as_str().unwrap().to_owned()
    };
    let server_id = {
        let reply = http(first.addr, "GET", "/setup", String::new()).await;
        let body = reply.split_once("\r\n\r\n").unwrap().1.to_owned();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        lfcp::base::from_hex(json["server_id"].as_str().unwrap()).unwrap()
    };
    let carol = v.principal("carol");
    let proof = |purpose: &str, challenge: &str| {
        use lfcp::cbor::Value;
        let transcript = lfcp::cbor::encode(&Value::Array(vec![
            Value::text("LFCP-ADMIN-v1"),
            Value::text(purpose),
            Value::bytes(server_id.clone()),
            Value::bytes(lfcp::base::from_hex(challenge).unwrap()),
        ]))
        .unwrap();
        serde_json::json!({
            "principal": lfcp::base::to_hex(&carol.descriptor().encode()),
            "challenge": challenge,
            "proof": lfcp::base::to_hex(lfcp::cose::sign(&transcript, &carol).unwrap().bytes()),
        })
    };
    // A wrong code, then the right one, then an admin session.
    for (attempt, expected) in [("ZZZZ-ZZZZ", "403"), (code.as_str(), "200")] {
        let c = challenge(http(first.addr, "POST", "/admin/challenge", String::new()).await);
        let mut body = proof("pair", &c);
        body["code"] = serde_json::json!(attempt);
        let reply = http(first.addr, "POST", "/setup/pair", body.to_string()).await;
        assert_eq!(&reply[9..12], expected);
    }
    let c = challenge(http(first.addr, "POST", "/admin/challenge", String::new()).await);
    let reply = http(
        first.addr,
        "POST",
        "/admin/session",
        proof("session", &c).to_string(),
    )
    .await;
    assert_eq!(&reply[9..12], "200");
    let token = {
        let body = reply.split_once("\r\n\r\n").unwrap().1.to_owned();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        json["token"].as_str().unwrap().to_owned()
    };
    first.terminate();

    // A paired server prints no code.
    let second = spawn_with_output(&dir, output, "debug");
    second.terminate();

    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        text.matches(code.as_str()).count(),
        1,
        "printed exactly once"
    );
    assert!(!text.contains(&code.replace('-', "")));
    assert_eq!(text.matches("Admin pairing code:").count(), 1);
    assert!(!text.contains(&token), "the session token is never logged");
    assert!(text.contains("server administrator paired"));
    std::fs::remove_file(&log).unwrap();
    cleanup(&dir);
}
