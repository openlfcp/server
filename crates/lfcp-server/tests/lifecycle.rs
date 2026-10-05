//! The process lifecycle: bind, health, one identity for every connection,
//! graceful shutdown.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use lfcp_server::config::Config;
use lfcp_server::http::HEALTH_BODY;
use lfcp_server::identity::{FileIdentity, ServerIdentity};
use lfcp_server::server::Server;
use lfcp_server::store::Store;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lfcp-server-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// One HTTP/1.1 request with `Connection: close`; returns the raw response.
fn request(addr: SocketAddr, method: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}

async fn started(
    state: &std::path::Path,
) -> (
    SocketAddr,
    Arc<FileIdentity>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        state_dir: state.to_path_buf(),
        ..Config::default()
    };
    let identity = Arc::new(FileIdentity::load_or_create(&config.state_dir).unwrap());
    let store = Arc::new(Store::open(&config.state_dir).unwrap());
    let server = Server::bind(config, identity.clone(), store).await.unwrap();
    assert_eq!(server.server_id(), identity.server_id());
    let addr = server.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(server.run(lfcp_server::ws::PingOnly, async {
        let _ = stopped.await;
    }));
    (addr, identity, stop, task)
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_health_and_shuts_down_gracefully() {
    let state = temp_dir("health");
    let (addr, identity, stop, task) = started(&state).await;

    let response = tokio::task::spawn_blocking(move || request(addr, "GET", "/health"))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        response.ends_with(&format!("\r\n\r\n{HEALTH_BODY}")),
        "{response}"
    );
    // The health response carries no identifiers or data.
    assert!(!response.contains(&identity.server_id().to_hex()));

    let response = tokio::task::spawn_blocking(move || request(addr, "GET", "/other"))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");

    // An idle keep-alive connection must not hold the shutdown up.
    let idle = TcpStream::connect(addr).unwrap();

    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("shut down in time")
        .unwrap();
    assert!(TcpStream::connect(addr).is_err(), "no longer listening");
    drop(idle);
    std::fs::remove_dir_all(&state).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_id_survives_restarts_and_is_shared_by_connections() {
    let state = temp_dir("restart");
    let (addr, first, stop, task) = started(&state).await;
    for _ in 0..3 {
        let response = tokio::task::spawn_blocking(move || request(addr, "GET", "/health"))
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
    }
    stop.send(()).unwrap();
    task.await.unwrap();

    // A second process start on the same state directory: the same ID.
    let (_, second, stop, task) = started(&state).await;
    assert_eq!(first.server_id(), second.server_id());
    stop.send(()).unwrap();
    task.await.unwrap();
    std::fs::remove_dir_all(&state).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_busy_address_fails_to_bind() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let state = temp_dir("busy");
    let config = Config {
        bind: taken.local_addr().unwrap(),
        state_dir: state.clone(),
        ..Config::default()
    };
    let identity = Arc::new(FileIdentity::load_or_create(&state).unwrap());
    let store = Arc::new(Store::open(&state).unwrap());
    assert!(Server::bind(config, identity, store).await.is_err());
    std::fs::remove_dir_all(&state).unwrap();
}
