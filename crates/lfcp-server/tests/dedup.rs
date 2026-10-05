//! Exact replay versus actor equivocation over real TCP (LFCP-052): replay
//! is harmless deduplication with a stable ACK and one row, for every
//! object class and across a restart; equivocation is detected, kept as
//! evidence and never fanned out; malformed bytes never become evidence.

mod support;

use lfcp::base::Hash32;
use lfcp::wire::message::{AckBody, Body, DataRange};
use support::lfcp::{code, start, state_dir, Client, Options, Running};
use support::vectors::{host_chain, Vectors};

const INVALID_SIGNATURE: u64 = 7;
const ACTOR_EQUIVOCATION: u64 = 16;

async fn client(server: &Running, v: &Vectors, name: &str) -> Client {
    let mut client = Client::connect(server.addr).await;
    client.handshake(&v.principal(name)).await;
    client
}

async fn put(client: &mut Client, body: Body) -> Body {
    let id = client.request(body).await;
    let reply = client.recv().await;
    assert_eq!(reply.correlation_id, Some(id));
    reply.body
}

fn data_put(v: &Vectors, units: &[&str]) -> Body {
    Body::DataPut {
        resource_id: v.resource(),
        units: units.iter().map(|u| v.cose(u)).collect(),
    }
}

fn id(v: &Vectors, case: &str, field: &str) -> Hash32 {
    Hash32::from_bytes(v.hex(case, "expected", field).try_into().unwrap())
}

fn ack(request_type: u64, ids: Vec<Hash32>) -> Body {
    Body::Ack(AckBody {
        request_type,
        object_ids: Some(ids),
        durable: Some(true),
    })
}

/// The next message is the PONG to a fresh PING: nothing was pushed.
async fn nothing_pending(client: &mut Client) {
    client.request(Body::Ping([5; 8])).await;
    assert_eq!(client.recv().await.body, Body::Pong([5; 8]));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_object_class_replays_to_one_row_and_a_stable_ack() {
    let v = Vectors::load();
    let dir = state_dir("dedup-classes");
    let server = start(&dir, Options::default()).await;
    host_chain(&server.store, &v, 10).await;
    let bob_id = *v.principal("bob").descriptor().id();
    let mut bob = client(&server, &v, "bob").await;
    let mut owner = client(&server, &v, "owner").await;

    // Data Units.
    let units = ["D1_bob_epoch0_seq1", "D2_bob_epoch0_seq2"];
    let wanted = ack(33, units.iter().map(|u| id(&v, u, "unit_id")).collect());
    for _ in 0..3 {
        assert_eq!(put(&mut bob, data_put(&v, &units)).await, wanted);
    }
    for seq in [1, 2] {
        let rows = server
            .store
            .data_units_at(v.resource(), bob_id, seq)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "one row for seq {seq}");
    }

    // Key Packages.
    let kp = Body::KeyPackagePut {
        resource_id: v.resource(),
        packages: vec![v.cose("KP0_bob_epoch0")],
    };
    let wanted = ack(42, vec![id(&v, "KP0_bob_epoch0", "package_id")]);
    for _ in 0..3 {
        assert_eq!(put(&mut owner, kp.clone()).await, wanted);
    }
    let rows = server
        .store
        .key_packages_for(v.resource(), 0, bob_id)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "one Key Package row");

    // Snapshots.
    let snapshot = Body::SnapshotPut {
        resource_id: v.resource(),
        snapshot: v.cose("SNAPSHOT-01"),
    };
    let wanted = ack(52, vec![id(&v, "SNAPSHOT-01", "snapshot_id")]);
    for _ in 0..3 {
        assert_eq!(put(&mut bob, snapshot.clone()).await, wanted);
    }
    assert_eq!(server.store.snapshots(v.resource()).await.unwrap().len(), 1);

    // Control Records: a repeated CONTROL_PUT of a committed record
    // (control.rs covers the ACK); here, one stored row.
    let at3 = server
        .store
        .control_records(v.resource(), 3, 3)
        .await
        .unwrap();
    assert_eq!(at3.len(), 1);

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_conflicting_bytes_never_become_evidence() {
    let v = Vectors::load();
    let dir = state_dir("dedup-malformed");
    let server = start(&dir, Options::default()).await;
    host_chain(&server.store, &v, 10).await;
    let mut bob = client(&server, &v, "bob").await;
    put(
        &mut bob,
        data_put(&v, &["D1_bob_epoch0_seq1", "D2_bob_epoch0_seq2"]),
    )
    .await;

    // D2 with a broken signature: the same claimed actor and sequence.
    let mut forged = v.cose("D2_bob_epoch0_seq2");
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let reply = put(
        &mut bob,
        Body::DataPut {
            resource_id: v.resource(),
            units: vec![forged],
        },
    )
    .await;
    assert!(
        matches!(&reply, Body::Nack(e) if e.code == INVALID_SIGNATURE),
        "{reply:?}"
    );
    let rows = server
        .store
        .data_units_at(v.resource(), *v.principal("bob").descriptor().id(), 2)
        .await
        .unwrap();
    assert_eq!(rows, vec![id(&v, "D2_bob_epoch0_seq2", "unit_id")]);

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn fan_out_reaches_each_subscriber_once_and_never_carries_equivocation() {
    let v = Vectors::load();
    let dir = state_dir("dedup-fanout");
    let server = start(&dir, Options::default()).await;
    host_chain(&server.store, &v, 10).await;
    let open = Body::ResourceOpen {
        resource_id: v.resource(),
        control_heads: vec![],
        have: vec![],
        grant_ids: None,
        flags: Some(0b001),
    };
    let mut subscribers = Vec::new();
    for name in ["carol", "carol", "bob"] {
        let mut subscriber = client(&server, &v, name).await;
        subscriber.request(open.clone()).await;
        assert!(matches!(
            subscriber.recv().await.body,
            Body::ResourceOpened { .. }
        ));
        subscribers.push(subscriber);
    }
    let mut writer = client(&server, &v, "bob").await;
    let units = ["D1_bob_epoch0_seq1", "D2_bob_epoch0_seq2"];
    // The same units arrive twice: each subscriber gets them once.
    for _ in 0..2 {
        assert!(matches!(
            put(&mut writer, data_put(&v, &units)).await,
            Body::Ack(_)
        ));
    }
    for subscriber in &mut subscribers {
        assert_eq!(
            subscriber.recv().await.body,
            Body::DataBatch {
                resource_id: v.resource(),
                units: units.iter().map(|u| v.cose(u)).collect(),
            }
        );
        nothing_pending(subscriber).await;
    }

    // §26.2: an equivocating D2 is stored as evidence and reported to its
    // writer; subscribers get nothing, and DATA_GET serves both.
    let conflicting = v.hex("actor_equivocation", "inputs", "conflicting_D2_cose");
    let reply = put(
        &mut writer,
        Body::DataPut {
            resource_id: v.resource(),
            units: vec![conflicting.clone()],
        },
    )
    .await;
    assert!(matches!(&reply, Body::Nack(e) if e.code == ACTOR_EQUIVOCATION));
    for subscriber in &mut subscribers {
        nothing_pending(subscriber).await;
    }
    let reader = &mut subscribers[0];
    reader
        .request(Body::DataGet {
            resource_id: v.resource(),
            ranges: vec![DataRange {
                principal: *v.principal("bob").descriptor().id(),
                start: 2,
                end: 2,
            }],
        })
        .await;
    let Body::DataBatch { units: served, .. } = reader.recv().await.body else {
        panic!("expected DATA_BATCH")
    };
    assert_eq!(served.len(), 2);
    assert!(served.contains(&conflicting) && served.contains(&v.cose("D2_bob_epoch0_seq2")));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_and_equivocation_are_recognized_after_a_restart() {
    let v = Vectors::load();
    let dir = state_dir("dedup-restart");
    let server = start(&dir, Options::default()).await;
    host_chain(&server.store, &v, 10).await;
    let mut bob = client(&server, &v, "bob").await;
    let units = ["D1_bob_epoch0_seq1", "D2_bob_epoch0_seq2"];
    let first = put(&mut bob, data_put(&v, &units)).await;
    server.stop().await;

    let server = start(&dir, Options::default()).await;
    let mut bob = client(&server, &v, "bob").await;
    assert_eq!(
        put(&mut bob, data_put(&v, &units)).await,
        first,
        "stable ACK"
    );
    let rows = server
        .store
        .data_units_at(v.resource(), *v.principal("bob").descriptor().id(), 2)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let conflicting = v.hex("actor_equivocation", "inputs", "conflicting_D2_cose");
    let reply = put(
        &mut bob,
        Body::DataPut {
            resource_id: v.resource(),
            units: vec![conflicting],
        },
    )
    .await;
    assert_eq!(
        code(&lfcp::wire::message::Message::new([0; 16], reply)),
        ACTOR_EQUIVOCATION
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
