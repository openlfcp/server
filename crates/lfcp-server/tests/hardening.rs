//! Limits on unauthenticated peers (security review M2, M5): the HTTP
//! header-read timeout, the handshake deadline, the pre-READY message
//! count and size caps, and the connection cap.

mod support;

use std::time::{Duration, Instant};

use lfcp::principal::PrincipalKeys;
use lfcp::wire::message::Body;
use support::lfcp::{code, start, state_dir, Client, Options};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const MALFORMED_MESSAGE: u64 = 2;
const RATE_LIMITED: u64 = 17;
const MESSAGE_TOO_LARGE: u64 = 19;

fn keys() -> PrincipalKeys {
    PrincipalKeys::from_secrets(&[1; 32], [2; 32])
}

fn quick() -> Options {
    Options {
        handshake_timeout_ms: Some(1_000),
        ..Options::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_not_ready_in_time_is_closed_even_while_pinging() {
    let dir = state_dir("hardening-deadline");
    let server = start(&dir, quick()).await;
    let mut client = Client::connect(server.addr).await;
    let opened = Instant::now();
    // PING is allowed before READY (G-SM4) and answered, but does not
    // extend the deadline.
    for i in 0..3u8 {
        client.request(Body::Ping([i; 8])).await;
        assert!(matches!(client.recv().await.body, Body::Pong(_)));
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(client.close_code().await, Some(CloseCode::Policy));
    let after = opened.elapsed();
    assert!(after >= Duration::from_millis(900), "{after:?}");
    assert!(after < Duration::from_secs(3), "{after:?}");

    // A session that reached READY is not subject to it.
    let mut ready = Client::connect(server.addr).await;
    ready.handshake(&keys()).await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    ready.request(Body::Ping([9; 8])).await;
    assert!(matches!(ready.recv().await.body, Body::Pong(_)));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn too_many_messages_before_ready_close_the_connection() {
    let dir = state_dir("hardening-count");
    let server = start(&dir, Options::default()).await;
    let mut client = Client::connect(server.addr).await;
    for i in 0..16u8 {
        client.request(Body::Ping([i; 8])).await;
        assert!(matches!(client.recv().await.body, Body::Pong(_)));
    }
    client.request(Body::Ping([16; 8])).await;
    assert_eq!(code(&client.recv().await), RATE_LIMITED);
    assert_eq!(client.close_code().await, Some(CloseCode::Policy));

    // After READY the count no longer applies.
    let mut ready = Client::connect(server.addr).await;
    ready.handshake(&keys()).await;
    for i in 0..32u8 {
        ready.request(Body::Ping([i; 8])).await;
        assert!(matches!(ready.recv().await.body, Body::Pong(_)));
    }

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_message_before_ready_is_refused_undecoded() {
    let dir = state_dir("hardening-size");
    let server = start(&dir, Options::default()).await;
    let large = vec![0xa1; 64 * 1024 + 1];
    let mut client = Client::connect(server.addr).await;
    client.send_bytes(large.clone()).await;
    assert_eq!(code(&client.recv().await), MESSAGE_TOO_LARGE);
    assert_eq!(client.close_code().await, Some(CloseCode::Size));

    // After READY the configured maximum applies: the same bytes are
    // decoded (and are malformed), and the connection stays open.
    let mut ready = Client::connect(server.addr).await;
    ready.handshake(&keys()).await;
    ready.send_bytes(large).await;
    assert_eq!(code(&ready.recv().await), MALFORMED_MESSAGE);
    ready.request(Body::Ping([1; 8])).await;
    assert!(matches!(ready.recv().await.body, Body::Pong(_)));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn incomplete_request_headers_time_out() {
    let dir = state_dir("hardening-headers");
    let server = start(&dir, quick()).await;
    let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let started = Instant::now();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "the server closed the connection");
    let after = started.elapsed();
    assert!(after >= Duration::from_millis(900), "{after:?}");

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A plain HTTP GET on a new connection; the whole answer.
async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer))
        .await
        .expect("answered in time")
        .unwrap();
    String::from_utf8(answer).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_past_the_cap_get_503_until_one_closes() {
    let dir = state_dir("hardening-connections");
    let server = start(
        &dir,
        Options {
            max_connections: Some(2),
            ..Options::default()
        },
    )
    .await;
    // Two WebSocket connections hold both places, after the upgrade too.
    let mut first = Client::connect(server.addr).await;
    first.handshake(&keys()).await;
    let mut second = Client::connect(server.addr).await;
    second.handshake(&keys()).await;
    let refused = http_get(server.addr, "/health").await;
    assert!(refused.starts_with("HTTP/1.1 503 "), "{refused}");
    assert!(refused.contains("retry-after: 5"), "{refused}");

    // The open sessions are unaffected.
    second.request(Body::Ping([1; 8])).await;
    assert!(matches!(second.recv().await.body, Body::Pong(_)));

    // Closing one frees its place.
    drop(first);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let answer = http_get(server.addr, "/health").await;
        if answer.starts_with("HTTP/1.1 200 ") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the place was not freed: {answer}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
