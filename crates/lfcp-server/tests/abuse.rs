//! Abuse limits over real connections (POST-003): each limit is crossed
//! and gets its documented refusal, and the client IP comes from a proxy
//! header only when the TCP peer is a trusted proxy.

mod support;

use std::time::{Duration, Instant};

use lfcp::principal::PrincipalKeys;
use lfcp_server::limits::AbuseLimits;
use support::lfcp::{start, state_dir, Client, Options, Refused};

fn keys() -> PrincipalKeys {
    PrincipalKeys::from_secrets(&[1; 32], [2; 32])
}

fn with(abuse: AbuseLimits) -> Options {
    Options {
        abuse: Some(abuse),
        ..Options::default()
    }
}

fn xff(value: &str) -> [(&str, &str); 1] {
    [("x-forwarded-for", value)]
}

/// Retry `connect` until it succeeds: a closed connection frees its place
/// when the server notices.
async fn eventually(addr: std::net::SocketAddr, headers: &[(&str, &str)]) -> Client {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match Client::try_connect(addr, headers).await {
            Ok(client) => return client,
            Err(refused) => assert!(Instant::now() < deadline, "still refused: {refused:?}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn too_many_connections() -> Refused {
    Refused {
        status: 429,
        retry_after: Some("5".into()),
        body: "too many connections from this address\n".into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn open_websockets_per_ip_are_capped_and_untrusted_headers_ignored() {
    let dir = state_dir("abuse-per-ip");
    let server = start(
        &dir,
        with(AbuseLimits {
            max_connections_per_ip: 2,
            connections_per_ip_per_minute: 0,
            ..AbuseLimits::default()
        }),
    )
    .await;
    // No proxy is trusted: a forged X-Forwarded-For does not make the
    // loopback peer a new client.
    let mut first = Client::try_connect(server.addr, &xff("203.0.113.1"))
        .await
        .unwrap();
    first.handshake(&keys()).await;
    let _second = Client::try_connect(server.addr, &xff("203.0.113.2"))
        .await
        .unwrap();
    let refused = Client::try_connect(server.addr, &xff("203.0.113.3"))
        .await
        .err()
        .expect("the third connection from 127.0.0.1");
    assert_eq!(refused, too_many_connections());
    // The open sessions are unaffected; closing one frees its place.
    first.request(lfcp::wire::message::Body::Ping([1; 8])).await;
    assert!(matches!(
        first.recv().await.body,
        lfcp::wire::message::Body::Pong(_)
    ));
    drop(first);
    let _third = eventually(server.addr, &[]).await;

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trusted_proxy_reports_the_client_ip() {
    let dir = state_dir("abuse-proxy");
    let server = start(
        &dir,
        with(AbuseLimits {
            max_connections_per_ip: 1,
            connections_per_ip_per_minute: 0,
            trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
            ..AbuseLimits::default()
        }),
    )
    .await;
    // Each reported client gets its own place.
    let _a = Client::try_connect(server.addr, &xff("203.0.113.1"))
        .await
        .unwrap();
    let _b = Client::try_connect(server.addr, &xff("203.0.113.2"))
        .await
        .unwrap();
    // The rightmost untrusted entry counts, not a forged one on its left.
    let refused = Client::try_connect(server.addr, &xff("198.51.100.9, 203.0.113.1"))
        .await
        .err()
        .expect("203.0.113.1 already holds its place");
    assert_eq!(refused, too_many_connections());
    // Without the header the proxy is the client.
    let _c = Client::try_connect(server.addr, &[]).await.unwrap();
    assert!(Client::try_connect(server.addr, &[]).await.is_err());

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn new_websockets_per_ip_are_rate_limited() {
    let dir = state_dir("abuse-connect-rate");
    let server = start(
        &dir,
        with(AbuseLimits {
            connections_per_ip_per_minute: 3,
            ..AbuseLimits::default()
        }),
    )
    .await;
    for _ in 0..3 {
        drop(Client::connect(server.addr).await);
    }
    let refused = Client::try_connect(server.addr, &[])
        .await
        .err()
        .expect("the fourth new connection in a minute");
    assert_eq!(
        refused,
        Refused {
            status: 429,
            retry_after: Some("20".into()),
            body: "too many new connections from this address\n".into(),
        }
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
