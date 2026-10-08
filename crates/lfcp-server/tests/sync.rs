//! Catch-up and anti-entropy against the server over real TCP (LFCP-051):
//! a client drives DATA_HAVE → DATA_GET → DATA_BATCH with the sdk-rs Have
//! primitives (`difference`, `split_requests`, `missing_after`) until the
//! Haves agree, across holes, several actors, more than 256 ranges,
//! split batches, a reconnect, a Snapshot-first start and lost pushes.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use lfcp::base::{DataUnitId, Hash32};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::data_unit::{DataUnit, DataUnitHeader, ReceivedDataUnit};
use lfcp::wire::frontier::{ActorHave, Frontier};
use lfcp::wire::have::{difference, missing_after, split_requests, HaveVector, MAX_RANGES_PER_GET};
use lfcp::wire::key_package::{KeyPackage, ReceivedKeyPackage};
use lfcp::wire::keys::Dek;
use lfcp::wire::message::{Body, DataRange};
use lfcp::wire::snapshot::{ReceivedSnapshot, Snapshot, SnapshotHeader};
use lfcp_server::config::MIN_MESSAGE_BYTES;
use support::lfcp::{start, state_dir, Client, Options, Running};
use support::vectors::{host_chain, Vectors};

fn head(v: &Vectors, name: &str) -> Hash32 {
    Hash32::from_bytes(*v.record_id(name).as_bytes())
}

/// `count` units of `keys` from sequence 1, chained, at Control Head
/// `at`, in epoch 0.
fn units(v: &Vectors, keys: &PrincipalKeys, count: u64, at: &str) -> Vec<Vec<u8>> {
    let mut previous: Option<DataUnitId> = None;
    (1..=count)
        .map(|sequence| {
            let unit = DataUnit::seal(
                DataUnitHeader {
                    resource_id: v.resource(),
                    data_epoch: 0,
                    actor: *keys.descriptor().id(),
                    sequence,
                    previous,
                    control_head: head(v, at),
                },
                format!("unit {sequence} {}", "x".repeat(1000)).as_bytes(),
                &Dek::from_bytes([9; 32]),
                keys,
            )
            .unwrap();
            previous = Some(unit.id());
            unit.signed_object().bytes().to_vec()
        })
        .collect()
}

fn header(bytes: &[u8]) -> DataUnitHeader {
    ReceivedDataUnit::parse(bytes).unwrap().header().clone()
}

/// A client replica: the units it holds and their Have.
#[derive(Default)]
struct Replica {
    units: BTreeMap<([u8; 32], u64), Vec<u8>>,
    have: HaveVector,
}

impl Replica {
    fn insert(&mut self, bytes: Vec<u8>) {
        let h = header(&bytes);
        self.have.insert(&h.actor, h.sequence).unwrap();
        self.units.insert((*h.actor.as_bytes(), h.sequence), bytes);
    }
}

async fn put_all(v: &Vectors, client: &mut Client, units: &[Vec<u8>]) {
    for chunk in units.chunks(40) {
        client
            .request(Body::DataPut {
                resource_id: v.resource(),
                units: chunk.to_vec(),
            })
            .await;
        assert!(matches!(client.recv().await.body, Body::Ack(_)));
    }
}

async fn server_have(v: &Vectors, client: &mut Client, ours: &HaveVector) -> HaveVector {
    let id = client
        .request(Body::DataHave {
            resource_id: v.resource(),
            have: ours.to_wire(),
        })
        .await;
    let reply = client.recv().await;
    assert_eq!(reply.correlation_id, Some(id));
    match reply.body {
        Body::DataHave { have, .. } => HaveVector::from_wire(&have).unwrap(),
        other => panic!("expected DATA_HAVE, got {other:?}"),
    }
}

/// One DATA_GET, answered by as many DATA_BATCHes as it takes to cover the
/// requested sequences. Returns the number of batches.
async fn get(
    v: &Vectors,
    client: &mut Client,
    ranges: Vec<DataRange>,
    replica: &mut Replica,
) -> usize {
    let mut wanted: BTreeSet<([u8; 32], u64)> = ranges
        .iter()
        .flat_map(|r| (r.start..=r.end).map(move |s| (*r.principal.as_bytes(), s)))
        .collect();
    let id = client
        .request(Body::DataGet {
            resource_id: v.resource(),
            ranges,
        })
        .await;
    let mut batches = 0;
    while !wanted.is_empty() {
        let reply = client.recv().await;
        assert_eq!(reply.correlation_id, Some(id));
        let Body::DataBatch { units, .. } = reply.body else {
            panic!("expected DATA_BATCH, got {:?}", reply.body)
        };
        batches += 1;
        for unit in units {
            let h = header(&unit);
            assert!(
                wanted.remove(&(*h.actor.as_bytes(), h.sequence)),
                "only requested units"
            );
            replica.insert(unit);
        }
    }
    batches
}

/// Anti-entropy until the Haves agree. Returns (GET requests, batches).
async fn catch_up(v: &Vectors, client: &mut Client, replica: &mut Replica) -> (usize, usize) {
    let (mut gets, mut batches) = (0, 0);
    loop {
        let theirs = server_have(v, client, &replica.have).await;
        let missing = difference(&replica.have, &theirs).request;
        if missing.is_empty() {
            assert_eq!(replica.have, theirs, "converged");
            return (gets, batches);
        }
        for request in split_requests(&missing) {
            assert!(request.len() <= MAX_RANGES_PER_GET);
            gets += 1;
            batches += get(v, client, request, replica).await;
        }
    }
}

async fn reader(server: &Running, keys: &PrincipalKeys) -> Client {
    let mut client = Client::connect(server.addr).await;
    client.handshake(keys).await;
    client
}

/// BOB's units 1–520 and 530–600 (a hole at 521–529) at C5, and OWNER's
/// 1–40 at C1 (an older head, where OWNER was the owner).
async fn populated(
    v: &Vectors,
    name: &str,
) -> (Running, std::path::PathBuf, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let dir = state_dir(name);
    let options = Options {
        max_message_bytes: Some(MIN_MESSAGE_BYTES),
        ..Options::default()
    };
    let server = start(&dir, options).await;
    host_chain(&server.store, v, 5).await;
    let bob = units(v, &v.principal("bob"), 600, "C5_route_update");
    let owner = units(v, &v.principal("owner"), 40, "C1_grant_bob");
    let mut writer = reader(&server, &v.principal("bob")).await;
    put_all(v, &mut writer, &bob[..520]).await;
    put_all(v, &mut writer, &owner).await;
    // Unit 530 names 529, which the server lacks: a DATA_PUT of it is
    // refused (WIRE-01 §51.1), so the units after the hole are seeded into
    // the store, as a server that lost 521–529 would hold them.
    server
        .store
        .put_data_units(bob[529..].to_vec())
        .await
        .unwrap();
    (server, dir, bob, owner)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_client_with_holes_catches_up_and_a_repeat_is_a_no_op() {
    let v = Vectors::load();
    let (server, dir, bob, owner) = populated(&v, "sync-holes").await;
    let bob_id = *v.principal("bob").descriptor().id();

    // The server's Have keeps its hole: contiguous 520, then 530–600.
    let mut client = reader(&server, &v.principal("bob")).await;
    let theirs = server_have(&v, &mut client, &HaveVector::new()).await;
    let wire = theirs.to_wire();
    let bob_entry = wire.iter().find(|e| e.principal == bob_id).unwrap();
    assert_eq!(bob_entry.contiguous, 520);
    assert_eq!(bob_entry.extra, Some(vec![(530, 600)]));

    // A client holding BOB's even units up to 520: 260 singleton gaps plus
    // 530–600, and all of OWNER (a missing actor).
    let mut replica = Replica::default();
    for (i, unit) in bob.iter().enumerate().take(520) {
        if (i + 1) % 2 == 0 {
            replica.insert(unit.clone());
        }
    }
    let first = difference(&replica.have, &theirs).request;
    assert!(first.len() > MAX_RANGES_PER_GET, "{} ranges", first.len());
    // Ranges the client holds beyond the hole are never asked for.
    assert!(first
        .iter()
        .all(|r| r.principal != bob_id || r.end < 521 || r.start > 529));

    // The first request, then a disconnect, then the rest on a new
    // connection.
    let request = split_requests(&first).remove(0);
    let first_batches = get(&v, &mut client, request, &mut replica).await;
    assert!(
        first_batches > 1,
        "the 64 KiB limit splits replies: {first_batches}"
    );
    drop(client);
    let mut client = reader(&server, &v.principal("bob")).await;
    let (gets, _) = catch_up(&v, &mut client, &mut replica).await;
    assert!(gets >= 1);

    // Everything the server has, byte for byte; nothing from the hole.
    for (i, unit) in bob.iter().enumerate() {
        let held = replica.units.get(&(*bob_id.as_bytes(), i as u64 + 1));
        if (520..529).contains(&i) {
            assert!(held.is_none());
        } else {
            assert_eq!(held, Some(unit));
        }
    }
    let owner_id = *v.principal("owner").descriptor().id();
    for (i, unit) in owner.iter().enumerate() {
        assert_eq!(
            replica.units.get(&(*owner_id.as_bytes(), i as u64 + 1)),
            Some(unit)
        );
    }

    // Repeated catch-up: no request at all.
    assert_eq!(catch_up(&v, &mut client, &mut replica).await, (0, 0));

    // The hole fills (late units arrive), and anti-entropy fetches only it.
    let mut writer = reader(&server, &v.principal("bob")).await;
    put_all(&v, &mut writer, &bob[520..529]).await;
    let theirs = server_have(&v, &mut client, &replica.have).await;
    let missing = difference(&replica.have, &theirs).request;
    assert_eq!(
        missing,
        vec![DataRange {
            principal: bob_id,
            start: 521,
            end: 529
        }]
    );
    catch_up(&v, &mut client, &mut replica).await;

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_snapshot_first_client_fetches_only_what_follows_the_frontier() {
    // §66 steps 3–4.
    let v = Vectors::load();
    let (server, dir, _, _) = populated(&v, "sync-snapshot").await;
    let bob = v.principal("bob");
    let bob_id = *bob.descriptor().id();
    // BOB publishes a Snapshot covering his units 1–300.
    let snapshot = Snapshot::seal(
        SnapshotHeader {
            resource_id: v.resource(),
            data_epoch: 0,
            publisher: bob_id,
            sequence: 1,
            control_head: head(&v, "C5_route_update"),
            frontier: Frontier::new(vec![ActorHave {
                principal: bob_id,
                contiguous: 300,
                extra: vec![],
            }])
            .unwrap(),
        },
        b"state at 300",
        &Dek::from_bytes([9; 32]),
        &bob,
    )
    .unwrap();
    let mut client = reader(&server, &bob).await;
    client
        .request(Body::SnapshotPut {
            resource_id: v.resource(),
            snapshot: snapshot.signed_object().bytes().to_vec(),
        })
        .await;
    assert!(matches!(client.recv().await.body, Body::Ack(_)));

    // A fresh client: SNAPSHOT_GET (preferred), then only the ranges after
    // its frontier.
    let mut fresh = reader(&server, &bob).await;
    fresh
        .request(Body::SnapshotGet {
            resource_id: v.resource(),
            snapshot_id: None,
        })
        .await;
    let Body::Snapshot { snapshot, .. } = fresh.recv().await.body else {
        panic!("expected SNAPSHOT")
    };
    let frontier = ReceivedSnapshot::parse(&snapshot)
        .unwrap()
        .header()
        .frontier
        .clone();
    let mut replica = Replica::default();
    let theirs = server_have(&v, &mut fresh, &replica.have).await;
    let after = missing_after(&frontier, &replica.have, &theirs);
    assert!(after.iter().all(|r| r.principal != bob_id || r.start > 300));
    for request in split_requests(&after) {
        get(&v, &mut fresh, request, &mut replica).await;
    }
    assert!(replica
        .units
        .keys()
        .all(|(a, s)| *a != *bob_id.as_bytes() || *s > 300));
    assert_eq!(
        replica
            .units
            .keys()
            .filter(|(a, _)| *a == *bob_id.as_bytes())
            .count(),
        591 - 300,
        "BOB 301–520 and 530–600"
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn anti_entropy_recovers_pushes_lost_while_disconnected() {
    // §69: push is an optimization; DATA_HAVE converges.
    let v = Vectors::load();
    let dir = state_dir("sync-lost-push");
    let server = start(&dir, Options::default()).await;
    host_chain(&server.store, &v, 5).await;
    let bob = v.principal("bob");
    let all = units(&v, &bob, 30, "C5_route_update");
    let open = Body::ResourceOpen {
        resource_id: v.resource(),
        control_heads: vec![],
        have: vec![],
        grant_ids: None,
        flags: Some(0b001),
    };

    let mut writer = reader(&server, &bob).await;
    let mut subscriber = reader(&server, &v.principal("carol")).await;
    let mut replica = Replica::default();
    subscriber.request(open.clone()).await;
    subscriber.recv().await;
    put_all(&v, &mut writer, &all[..10]).await;
    let Body::DataBatch { units: pushed, .. } = subscriber.recv().await.body else {
        panic!("expected a push")
    };
    for unit in pushed {
        replica.insert(unit);
    }
    // Offline while 11–30 are written: those pushes are lost.
    drop(subscriber);
    put_all(&v, &mut writer, &all[10..]).await;

    let mut subscriber = reader(&server, &v.principal("carol")).await;
    subscriber.request(open).await;
    subscriber.recv().await;
    let (gets, _) = catch_up(&v, &mut subscriber, &mut replica).await;
    assert_eq!(gets, 1);
    assert_eq!(replica.units.len(), 30);

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn control_catch_up_and_every_key_package_of_a_tuple() {
    let v = Vectors::load();
    let dir = state_dir("sync-control-keys");
    let server = start(&dir, Options::default()).await;
    host_chain(&server.store, &v, 10).await;
    let mut bob = reader(&server, &v.principal("bob")).await;

    // Control: a client at C5 asks for 6..=10 after CONTROL_HAVE.
    bob.request(Body::ControlHave {
        resource_id: v.resource(),
        control_heads: vec![lfcp::wire::message::ControlHead {
            sequence: 5,
            id: v.record_id("C5_route_update"),
        }],
    })
    .await;
    let Body::ControlHave { control_heads, .. } = bob.recv().await.body else {
        panic!("expected CONTROL_HAVE")
    };
    assert_eq!(control_heads.len(), 1);
    assert_eq!(control_heads[0].sequence, 10);
    bob.request(Body::ControlGet {
        resource_id: v.resource(),
        start: 6,
        end: 10,
    })
    .await;
    let Body::ControlBatch { records, .. } = bob.recv().await.body else {
        panic!("expected CONTROL_BATCH")
    };
    let published: Vec<Vec<u8>> = support::vectors::CHAIN[6..=10]
        .iter()
        .map(|c| v.cose(c))
        .collect();
    assert_eq!(records, published);

    // Two valid packages for (epoch 0, BOB): KP0 and another by OWNER.
    let owner = v.principal("owner");
    let second = KeyPackage::seal(
        v.resource(),
        0,
        head(&v, "C1_grant_bob"),
        &Dek::from_bytes([4; 32]),
        v.principal("bob").descriptor(),
        &owner,
    )
    .unwrap();
    let packages = vec![
        v.cose("KP0_bob_epoch0"),
        second.signed_object().bytes().to_vec(),
    ];
    let mut owner_client = reader(&server, &owner).await;
    owner_client
        .request(Body::KeyPackagePut {
            resource_id: v.resource(),
            packages: packages.clone(),
        })
        .await;
    assert!(matches!(owner_client.recv().await.body, Body::Ack(_)));
    bob.request(Body::KeyPackageGet {
        resource_id: v.resource(),
        recipient: *v.principal("bob").descriptor().id(),
        epochs: vec![0],
    })
    .await;
    let Body::KeyPackageBatch { packages: got, .. } = bob.recv().await.body else {
        panic!("expected KEY_PACKAGE_BATCH")
    };
    let ids = |list: &[Vec<u8>]| -> BTreeSet<[u8; 32]> {
        list.iter()
            .map(|p| *ReceivedKeyPackage::parse(p).unwrap().id().as_bytes())
            .collect()
    };
    assert_eq!(ids(&got), ids(&packages), "both kept and served");

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
