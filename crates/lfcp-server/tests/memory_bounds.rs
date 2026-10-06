//! Memory bounds on authenticated and admin peers (POST-004, security
//! review H6): outbound bytes per connection and server-wide, a peer that
//! stops reading, control replies while GET pages fill the server-wide
//! budget, and the admin request body read timeout. Small caps and
//! Resources: these tests show the bounds hold; they are not load tests.

mod support;

use std::time::{Duration, Instant};

use lfcp::base::Hash32;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::data_unit::{DataUnit, DataUnitHeader};
use lfcp::wire::keys::Dek;
use lfcp::wire::message::{Body, DataRange};
use lfcp_server::config::Config;
use lfcp_server::store::Hosting;
use support::lfcp::{start, state_dir, Client, Options, Running};
use support::vectors::Vectors;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The published chain through C10 (bob may read and write, epoch 1).
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

/// Scaled down: 256 KiB messages, a 1 MiB connection cap, 4 MiB in all.
const MESSAGE: usize = 256 * 1024;
const CONNECTION_CAP: usize = 1024 * 1024;
const TOTAL_CAP: usize = 4 * 1024 * 1024;

fn small_budgets(config: &mut Config) {
    config.max_message_bytes = MESSAGE;
    config.max_outbound_bytes = CONNECTION_CAP;
    config.max_total_outbound_bytes = TOTAL_CAP;
    config.write_timeout_ms = 1_000;
}

/// A server hosting the published Resource with `units` Data Units of
/// `size` bytes by bob, stored directly (the store checks structure only).
async fn large_resource(
    v: &Vectors,
    name: &str,
    units: u64,
    size: usize,
) -> (Running, std::path::PathBuf) {
    resource_with(v, name, units, size, Some(small_budgets)).await
}

/// [`large_resource`] with another configuration change.
async fn resource_with(
    v: &Vectors,
    name: &str,
    units: u64,
    size: usize,
    configure: Option<fn(&mut Config)>,
) -> (Running, std::path::PathBuf) {
    let dir = state_dir(name);
    let server = start(
        &dir,
        Options {
            configure,
            ..Options::default()
        },
    )
    .await;
    let store = &server.store;
    store
        .host_resource(
            v.cose(CHAIN[0]),
            Hosting {
                host: *v.principal("owner").descriptor().id(),
                durability: 2,
            },
        )
        .await
        .unwrap();
    for i in 1..CHAIN.len() {
        store
            .commit_control_record(v.cose(CHAIN[i]), v.record_id(CHAIN[i - 1]))
            .await
            .unwrap();
    }
    let bob = v.principal("bob");
    let head = Hash32::from_bytes(*v.record_id(CHAIN[10]).as_bytes());
    let payload = vec![7u8; size];
    let mut batch = Vec::new();
    for sequence in 1..=units {
        let unit = DataUnit::seal(
            DataUnitHeader {
                resource_id: v.resource(),
                data_epoch: 1,
                actor: *bob.descriptor().id(),
                sequence,
                previous: None,
                control_head: head,
            },
            &payload,
            &Dek::from_bytes([1; 32]),
            &bob,
        )
        .unwrap();
        batch.push(unit.signed_object().bytes().to_vec());
        if batch.len() == 256 {
            store
                .put_data_units(std::mem::take(&mut batch))
                .await
                .unwrap();
        }
    }
    store.put_data_units(batch).await.unwrap();
    (server, dir)
}

fn get_all(v: &Vectors, keys: &PrincipalKeys) -> Body {
    Body::DataGet {
        resource_id: v.resource(),
        ranges: vec![DataRange {
            principal: *keys.descriptor().id(),
            start: 1,
            end: u64::MAX,
        }],
    }
}

/// Wait until `check` holds, for at most `limit`.
async fn eventually(limit: Duration, check: impl Fn() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    check()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_stops_reading_is_closed_and_its_memory_freed() {
    let v = Vectors::load();
    // 8 MiB of units: more than the socket buffers and the caps.
    let (server, dir) = large_resource(&v, "memory-stalled", 512, 16 * 1024).await;
    let bob = v.principal("bob");
    let mut stalled = Client::connect(server.addr).await;
    stalled.handshake(&bob).await;
    let asked = Instant::now();
    stalled.request(get_all(&v, &bob)).await;
    // The client never reads. The server fills its budget, then its writer
    // times out (write_timeout_ms = 1000) and the connection is dropped.
    assert!(
        eventually(Duration::from_secs(10), || server.outbound.used() == 0
            && asked.elapsed() > Duration::from_millis(1_000))
        .await,
        "{} bytes still held",
        server.outbound.used()
    );
    assert!(
        server.outbound.peak() <= CONNECTION_CAP,
        "{}",
        server.outbound.peak()
    );
    assert!(server.outbound.connection_peak() <= CONNECTION_CAP);
    assert!(
        server.outbound.connection_peak() > CONNECTION_CAP / 2,
        "the cap was reached"
    );
    // What the socket had taken is still readable, then the stream ends.
    let mut frames = 0u64;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stalled.next_frame()).await {
            Ok(Some(_)) => frames += 1,
            Ok(None) => break,
            Err(_) => panic!("the server did not close the connection"),
        }
    }
    assert!(
        frames < 512 * 16 * 1024 / MESSAGE as u64,
        "{frames} batches: not all of them"
    );

    // The server still serves others.
    let mut other = Client::connect(server.addr).await;
    other.handshake(&bob).await;
    other.request(Body::Ping([1; 8])).await;
    assert!(matches!(other.recv().await.body, Body::Pong(_)));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Read every DATA_BATCH answering `request` until `units` units arrived;
/// returns the batches' objects.
async fn read_batches(client: &mut Client, request: [u8; 16], units: usize) -> Vec<Vec<Vec<u8>>> {
    read_batches_of(client, request, units, MESSAGE).await
}

/// [`read_batches`] of messages up to `limit` bytes.
async fn read_batches_of(
    client: &mut Client,
    request: [u8; 16],
    units: usize,
    limit: usize,
) -> Vec<Vec<Vec<u8>>> {
    let mut batches = Vec::new();
    let mut seen = 0;
    while seen < units {
        let bytes = client.next_frame().await.expect("the reply continues");
        assert!(bytes.len() <= limit, "a batch of {} bytes", bytes.len());
        let message = lfcp::wire::message::Message::decode(&bytes, &Default::default()).unwrap();
        assert_eq!(message.correlation_id, Some(request));
        let Body::DataBatch { units, .. } = message.body else {
            panic!("expected DATA_BATCH, got {:?}", message.body);
        };
        seen += units.len();
        batches.push(units);
    }
    assert_eq!(seen, units);
    batches
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_resource_is_served_within_the_byte_caps() {
    let v = Vectors::load();
    // 8 MiB of units: 32 × the message size, 8 × the connection cap,
    // 2 × the server-wide cap.
    let units = 512u64;
    let (server, dir) = large_resource(&v, "memory-large", units, 16 * 1024).await;
    let bob = v.principal("bob");
    let actor = *bob.descriptor().id();

    // Six readers at once: more than the server-wide budget would allow
    // at their own caps.
    let mut readers = Vec::new();
    for _ in 0..6 {
        let addr = server.addr;
        let get = Body::DataGet {
            resource_id: v.resource(),
            // Three ranges, so pages cross from one to the next.
            ranges: vec![
                DataRange {
                    principal: actor,
                    start: 1,
                    end: 200,
                },
                DataRange {
                    principal: actor,
                    start: 201,
                    end: 201,
                },
                DataRange {
                    principal: actor,
                    start: 202,
                    end: u64::MAX,
                },
            ],
        };
        let bob = v.principal("bob");
        readers.push(tokio::spawn(async move {
            let mut client = Client::connect(addr).await;
            client.handshake(&bob).await;
            let request = client.request(get).await;
            read_batches(&mut client, request, units as usize).await
        }));
    }
    let budget = MESSAGE - 1024;
    let cost = |batch: &[Vec<u8>]| batch.iter().map(|u| u.len() + 9).sum::<usize>();
    for reader in readers {
        let batches = reader.await.unwrap();
        let all: Vec<&Vec<u8>> = batches.iter().flatten().collect();
        let sequences: Vec<u64> = all
            .iter()
            .map(|u| {
                lfcp::wire::data_unit::ReceivedDataUnit::parse(u)
                    .unwrap()
                    .header()
                    .sequence
            })
            .collect();
        assert_eq!(
            sequences,
            (1..=units).collect::<Vec<_>>(),
            "every unit once, in order"
        );
        // The batches are the greedy cut of the whole reply, as before
        // paging: each within the budget, and none could take the next
        // batch's first unit.
        for pair in batches.windows(2) {
            assert!(cost(&pair[0]) <= budget);
            assert!(cost(&pair[0]) + pair[1][0].len() + 9 > budget);
        }
    }
    assert!(
        server.outbound.connection_peak() <= CONNECTION_CAP,
        "a connection held {} bytes",
        server.outbound.connection_peak()
    );
    assert!(
        server.outbound.peak() <= TOTAL_CAP,
        "all connections held {} bytes",
        server.outbound.peak()
    );
    assert!(
        server.outbound.peak() > CONNECTION_CAP,
        "the readers overlapped"
    );
    assert!(eventually(Duration::from_secs(5), || server.outbound.used() == 0).await);

    // An empty listing still gets one, empty, batch.
    let mut client = Client::connect(server.addr).await;
    client.handshake(&bob).await;
    let request = client
        .request(Body::DataGet {
            resource_id: v.resource(),
            ranges: vec![DataRange {
                principal: actor,
                start: units + 1,
                end: units + 9,
            }],
        })
        .await;
    let reply = client.recv().await;
    assert_eq!(reply.correlation_id, Some(request));
    assert!(matches!(reply.body, Body::DataBatch { units, .. } if units.is_empty()));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Small caps with a long write timeout: stalled readers keep their
/// bytes.
fn tiny_budgets(config: &mut Config) {
    config.max_message_bytes = 64 * 1024;
    config.max_outbound_bytes = 128 * 1024;
    config.max_total_outbound_bytes = 512 * 1024;
    config.write_timeout_ms = 10_000;
}

/// GET pages of readers that stopped reading fill the server-wide budget.
/// Another session's handshake and replies are control traffic: they never
/// queue behind those pages, and get through at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_handshake_gets_through_while_get_pages_fill_the_global_budget() {
    let v = Vectors::load();
    let (server, dir) =
        resource_with(&v, "memory-control", 256, 16 * 1024, Some(tiny_budgets)).await;
    let bob = v.principal("bob");
    let mut stalled = Vec::new();
    for _ in 0..16 {
        let mut client = Client::connect(server.addr).await;
        client.handshake(&bob).await;
        client.request(get_all(&v, &bob)).await;
        stalled.push(client);
    }
    // Pages waiting on the server-wide budget: it is full for bulk
    // replies.
    assert!(
        eventually(Duration::from_secs(5), || server.outbound.waiting() > 0).await,
        "pages wait on the global budget: {} used",
        server.outbound.used()
    );
    let started = Instant::now();
    let mut client = Client::connect(server.addr).await;
    client.handshake(&bob).await;
    client.request(Body::Ping([1; 8])).await;
    assert!(matches!(client.recv().await.body, Body::Pong(_)));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(server.outbound.waiting() > 0, "the pages still wait");
    assert!(server.outbound.peak() <= 512 * 1024);
    drop(stalled);

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

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
