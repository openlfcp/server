//! Memory bounds on authenticated and admin peers (POST-004, security
//! review H6): the admin request body read timeout.

mod support;

use std::time::{Duration, Instant};

use support::lfcp::{start, state_dir, Options};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_admin_body_is_closed_after_the_timeout() {
    let dir = state_dir("memory-admin-body");
    let server = start(
        &dir,
        Options {
            configure: Some(|config| config.admin_body_timeout_ms = 1_000),
            ..Options::default()
        },
    )
    .await;
    let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    // Headers in time, then a body that never completes.
    stream
        .write_all(
            b"POST /admin/challenge HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"a\":",
        )
        .await
        .unwrap();
    let sent = Instant::now();
    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await;
    let after = sent.elapsed();
    assert!(read.is_ok(), "the server must close the connection");
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 408"), "{answer}");
    assert!(after >= Duration::from_millis(900), "{after:?}");
    assert!(after < Duration::from_secs(3), "{after:?}");

    // A body sent in time is still read.
    let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    stream
        .write_all(b"POST /admin/challenge HTTP/1.1\r\nhost: x\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
        .await
        .unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200"));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
