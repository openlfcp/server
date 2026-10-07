//! Restart durability of the real server process (LFCP-054): the
//! `lfcp-server` binary is spawned on a state directory, driven over the
//! LFCP protocol, then killed with SIGKILL (and, separately, stopped with
//! SIGTERM). A new process on the same directory must still hold every
//! acknowledged object (durability level 2: committed with WAL and
//! `synchronous = FULL`, so up to what SQLite and fsync guarantee), keep
//! its server ID, refuse stale and replayed state changes, and serve a
//! catch-up that converges without duplicates.
//!
//! No server outlives its test. Each spawned process is a [`Process`]
//! guard: dropped (a test that returns or panics), it kills and waits for
//! the server. A test process that is itself killed (SIGKILL, a gate
//! timeout, Ctrl-C) runs no destructor. A watchdog covers that case: a
//! small `sh` reaper whose stdin is a pipe that only the test process
//! holds. When that process dies, the kernel closes the pipe, `read` gets
//! EOF, and the reaper kills the server and removes its state, config and
//! log. This is test code only: the server has no test flag.

#![cfg(unix)]

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lfcp_server::store::{Store, DATABASE_FILE};
use support::durability::{populate, second_package, verify_after_restart, SNAPSHOTS, UNITS};
use support::lfcp::state_dir;
use support::vectors::{Vectors, CHAIN};

/// A running `lfcp-server` process: killed and waited for when dropped,
/// and by its reaper if the test process dies first (see the module docs).
struct Process {
    child: Child,
    reaper: Child,
    addr: SocketAddr,
}

/// A state directory: it, its config, log and pid file are removed when
/// dropped (also on panic).
struct StateDir(PathBuf);

impl Deref for StateDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for StateDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        for extension in ["toml", "log", "pid"] {
            let _ = std::fs::remove_file(self.0.with_extension(extension));
        }
    }
}

/// What the reaper removes after killing the server: the state directory,
/// its config and log, and the test's own directory when the state is
/// inside one.
fn leftovers(state: &Path) -> Vec<PathBuf> {
    let mut paths = vec![
        state.to_owned(),
        state.with_extension("toml"),
        state.with_extension("log"),
        state.with_extension("pid"),
    ];
    if let Some(parent) = state.parent() {
        if parent
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("lfcp-session-"))
        {
            paths.push(parent.to_owned());
        }
    }
    paths
}

/// The watchdog for `pid`: waits for EOF on its stdin, which only this
/// process holds, then kills `pid` and removes `paths`.
fn reaper(pid: u32, paths: &[PathBuf]) -> Child {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"read _line; kill -9 "$1" 2>/dev/null; shift; rm -rf -- "$@""#)
        .arg("lfcp-server-reaper")
        .arg(pid.to_string())
        .args(paths)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
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
    // stdin null: the server must not hold the reaper's pipe, or the pipe
    // would never reach EOF.
    let child = Command::new(env!("CARGO_BIN_EXE_lfcp-server"))
        .args(["--config", config.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(output())
        .stderr(output())
        .spawn()
        .unwrap();
    let reaper = reaper(child.id(), &leftovers(state));
    // The guard exists before the wait, so a server that never turns
    // healthy is killed too.
    let process = Process {
        child,
        reaper,
        addr,
    };
    let started = Instant::now();
    while !healthy(addr) {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "server did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    process
}

impl Drop for Process {
    fn drop(&mut self) {
        // The reaper first: closing its pipe would otherwise make it kill
        // a process this guard has already waited for, and remove a state
        // directory the next server of the test reuses.
        let _ = self.reaper.kill();
        let _ = self.reaper.wait();
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
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

fn fresh(name: &str) -> StateDir {
    let dir = StateDir(state_dir(name));
    let _ = std::fs::remove_file(dir.with_extension("toml"));
    dir
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
}

/// LFCP-046, security review M6: the setup code goes only to a 0600 file
/// in the state directory, never to stdout or the log (which `docker logs`
/// keeps), through pairing, an admin session and a restart. Pairing
/// removes the file.
#[tokio::test(flavor = "multi_thread")]
async fn the_setup_code_is_written_to_a_private_file_and_never_logged() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let v = Vectors::load();
    let dir = fresh("setup-code");
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.with_extension("log");
    let file = std::fs::File::create(&log).unwrap();
    let output = || Stdio::from(file.try_clone().unwrap());

    let first = spawn_with_output(&dir, output, "debug");
    let started = Instant::now();
    let setup_file = dir.join(lfcp_server::admin::SETUP_CODE_FILE);
    loop {
        let text = std::fs::read_to_string(&log).unwrap();
        if text.contains("pairing code written to") {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no pairing code announced"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let code = std::fs::read_to_string(&setup_file)
        .unwrap()
        .trim_end()
        .to_owned();
    assert_eq!(code.len(), 9);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&setup_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let announced = std::fs::read_to_string(&log).unwrap();
    assert!(announced.contains(&format!("pairing code written to {}", setup_file.display())));

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
    assert!(!setup_file.exists(), "pairing removes the code file");
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

    // A paired server creates no code.
    let second = spawn_with_output(&dir, output, "debug");
    second.terminate();
    assert!(!setup_file.exists());

    let text = std::fs::read_to_string(&log).unwrap();
    assert!(
        !text.contains(code.as_str()),
        "the code is never in the output"
    );
    assert!(!text.contains(&code.replace('-', "")));
    assert_eq!(text.matches("pairing code written to").count(), 1);
    assert!(!text.contains(&token), "the session token is never logged");
    assert!(text.contains("server administrator paired"));
}

/// Security review L5: the state directories the server creates are 0700,
/// and its files (server ID, setup code, database with its WAL and shared
/// memory) are 0600. A restart tightens database files an older server
/// left at the umask default, and keeps an existing directory's mode.
#[test]
fn state_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let set = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    let root = fresh("owner-only");
    std::fs::create_dir_all(&root).unwrap();
    set(&root, 0o755);
    let state = root.join("state");
    let database = state.join(DATABASE_FILE);
    let files = [
        state.join("server-id"),
        state.join(lfcp_server::admin::SETUP_CODE_FILE),
        database.clone(),
        state.join(format!("{DATABASE_FILE}-wal")),
        state.join(format!("{DATABASE_FILE}-shm")),
    ];

    let process = spawn(&state);
    assert_eq!(mode(&state), 0o700);
    assert_eq!(mode(&root), 0o755, "an existing directory keeps its mode");
    for file in &files {
        assert_eq!(mode(file), 0o600, "{}", file.display());
    }
    // SIGKILL leaves the WAL and shared-memory files in place.
    process.kill();

    for file in &files[2..] {
        set(file, 0o644);
    }
    set(&state, 0o755);
    let process = spawn(&state);
    for file in &files {
        assert_eq!(mode(file), 0o600, "{}", file.display());
    }
    assert_eq!(mode(&state), 0o755, "an existing directory keeps its mode");
    process.terminate();
}

/// The parent role of [`a_killed_test_process_takes_its_server_with_it`]:
/// a test process that starts a server, writes the server's pid and waits
/// to be killed. A no-op unless that test runs it.
#[test]
fn orphan_parent_role() {
    let Some(state) = std::env::var_os("LFCP_ORPHAN_STATE") else {
        return;
    };
    let state = PathBuf::from(state);
    let process = spawn(&state);
    std::fs::write(state.with_extension("pid"), process.child.id().to_string()).unwrap();
    std::thread::sleep(Duration::from_secs(120));
}

/// A test process killed with SIGKILL runs no destructor, yet its server
/// exits: the reaper sees its pipe close, kills the server and removes the
/// state, config and pid file.
#[test]
fn a_killed_test_process_takes_its_server_with_it() {
    let dir = fresh("orphan");
    let pid_file = dir.with_extension("pid");
    let mut parent = Command::new(std::env::current_exe().unwrap())
        .args(["orphan_parent_role", "--exact", "--test-threads=1"])
        .env("LFCP_ORPHAN_STATE", &*dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let pid = loop {
        if let Ok(pid) = std::fs::read_to_string(&pid_file) {
            if !pid.is_empty() {
                break pid;
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the parent did not start its server"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let alive = || {
        Command::new("kill")
            .args(["-0", &pid])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    assert!(alive());
    parent.kill().unwrap(); // SIGKILL: no destructor runs in the parent
    parent.wait().unwrap();
    let killed = Instant::now();
    while alive() || dir.exists() {
        assert!(
            killed.elapsed() < Duration::from_secs(5),
            "server {pid} outlived its test process"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!dir.with_extension("toml").exists());
}
