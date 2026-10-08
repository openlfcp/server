//! Ingest validation over real TCP WebSocket connections (LFCP-050):
//! DATA_PUT, KEY_PACKAGE_PUT and SNAPSHOT_PUT against LFCP-TEST-VECTORS-01,
//! the read paths, live Data pushes, subscription revalidation, ingest
//! policy, and opacity of the stored objects.

mod support;

use std::sync::Arc;

use lfcp::base::{ControlRecordId, Hash32, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::{CapabilityGrantBody, CapabilityRevokeBody, ControlBody};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use lfcp::wire::data_unit::{DataUnit, DataUnitHeader, ReceivedDataUnit};
use lfcp::wire::frontier::{ActorHave, Frontier};
use lfcp::wire::key_package::{KeyPackage, ReceivedKeyPackage};
use lfcp::wire::keys::Dek;
use lfcp::wire::message::{AckBody, Body, DataRange, Message, WireActorHave};
use lfcp::wire::snapshot::{ReceivedSnapshot, Snapshot, SnapshotHeader};
use lfcp_server::ingest::{IngestPolicy, ObjectKind, Refusal};
use lfcp_server::store::{Hosting, DATABASE_FILE};
use support::lfcp::{code, start, state_dir, Client, Options, Running, Script};
use support::vectors::Vectors;

const MALFORMED_MESSAGE: u64 = 2;
const AUTHORIZATION_FAILED: u64 = 4;
const MISSING_DEPENDENCY: u64 = 15;
const ACTOR_EQUIVOCATION: u64 = 16;
const QUOTA_EXCEEDED: u64 = 18;
const STALE_DATA_EPOCH: u64 = 14;

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

const SYNC_A: &str = "wss://sync-a.example.test/v1/ws";
const SYNC_B: &str = "wss://sync-b.example.test/v1/ws";

/// A server whose store holds the published chain through `CHAIN[last]`.
async fn chain_server(
    v: &Vectors,
    name: &str,
    last: usize,
    options: Options,
) -> (Running, std::path::PathBuf) {
    let dir = state_dir(name);
    let server = start(&dir, options).await;
    server
        .store
        .host_resource(
            v.cose(CHAIN[0]),
            Hosting {
                host: *v.principal("owner").descriptor().id(),
                durability: 2,
            },
        )
        .await
        .unwrap();
    for i in 1..=last {
        server
            .store
            .commit_control_record(v.cose(CHAIN[i]), v.record_id(CHAIN[i - 1]))
            .await
            .unwrap();
    }
    (server, dir)
}

async fn client(server: &Running, keys: &PrincipalKeys) -> Client {
    let mut client = Client::connect(server.addr).await;
    client.handshake(keys).await;
    client
}

fn data_put(v: &Vectors, units: Vec<Vec<u8>>) -> Body {
    Body::DataPut {
        resource_id: v.resource(),
        units,
    }
}

fn ack(request_type: u64, ids: Vec<Hash32>) -> Body {
    Body::Ack(AckBody {
        request_type,
        object_ids: Some(ids),
        durable: Some(true),
    })
}

fn id_of(v: &Vectors, case: &str, field: &str) -> Hash32 {
    Hash32::from_bytes(v.hex(case, "expected", field).try_into().unwrap())
}

fn head_hash(id: ControlRecordId) -> Hash32 {
    Hash32::from_bytes(*id.as_bytes())
}

/// A request's reply code, checking the correlation.
async fn reply_code(client: &mut Client, body: Body) -> u64 {
    let id = client.request(body).await;
    let reply = client.recv().await;
    assert_eq!(reply.correlation_id, Some(id));
    code(&reply)
}

#[tokio::test(flavor = "multi_thread")]
async fn published_data_units_are_accepted_and_acknowledged() {
    let v = Vectors::load();
    let script = Arc::new(Script::default());
    let options = Options {
        random: script.clone(),
        ..Options::default()
    };
    let (server, dir) = chain_server(&v, "data-put", 10, options).await;
    let mut bob = client(&server, &v.principal("bob")).await;

    // The published DATA_PUT(D1, D2) gets the published ACK, byte for byte.
    let ack_bytes = v.message("ACK_DATA_PUT_D1_D2");
    script.push(
        Message::decode(&ack_bytes, &Default::default())
            .unwrap()
            .message_id,
    );
    bob.send_bytes(v.message("DATA_PUT_D1_D2")).await;
    assert_eq!(bob.recv_bytes().await, ack_bytes);

    // Idempotent: the same units again get the same ACK body.
    let d1 = id_of(&v, "D1_bob_epoch0_seq1", "unit_id");
    let d2 = id_of(&v, "D2_bob_epoch0_seq2", "unit_id");
    bob.request(data_put(
        &v,
        vec![v.cose("D1_bob_epoch0_seq1"), v.cose("D2_bob_epoch0_seq2")],
    ))
    .await;
    assert_eq!(bob.recv().await.body, ack(33, vec![d1, d2]));

    // D4: CAROL in epoch 1.
    let mut carol = client(&server, &v.principal("carol")).await;
    carol
        .request(data_put(&v, vec![v.cose("D4_carol_epoch1_seq1")]))
        .await;
    assert_eq!(
        carol.recv().await.body,
        ack(33, vec![id_of(&v, "D4_carol_epoch1_seq1", "unit_id")])
    );

    // D3: BOB's offline unit beyond his epoch-0 cutoff (C6 closed epoch 0
    // at his sequence 2).
    assert_eq!(
        reply_code(
            &mut bob,
            data_put(&v, vec![v.cose("D3_bob_epoch0_seq3_stale")])
        )
        .await,
        STALE_DATA_EPOCH
    );
    assert_eq!(v.expected_code("stale_epoch"), Some(STALE_DATA_EPOCH));

    // Exact bytes, stable IDs.
    assert_eq!(
        server.store.data_unit(d1).await.unwrap(),
        Some(v.cose("D1_bob_epoch0_seq1"))
    );
    assert_eq!(
        ReceivedDataUnit::parse(&v.cose("D1_bob_epoch0_seq1"))
            .unwrap()
            .id()
            .as_bytes(),
        d1.as_bytes()
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_data_units_are_refused_with_their_codes() {
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-invalid", 10, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;

    for case in [
        "tampered_D1",
        "invalid_signature_D1",
        "wrong_kid_D1",
        "small_order_r_signature_D1",
        "tagged_cose_D1",
        "noncanonical_payload_D1",
        "actor_seq_zero_D1",
        "stale_epoch_absent_actor",
    ] {
        let wanted = v.expected_code(case).unwrap();
        assert_eq!(
            reply_code(&mut bob, data_put(&v, vec![v.negative(case)])).await,
            wanted,
            "{case}"
        );
    }

    // One bad unit refuses the whole put: D1 is not stored either.
    let d1 = id_of(&v, "D1_bob_epoch0_seq1", "unit_id");
    assert_eq!(
        reply_code(
            &mut bob,
            data_put(
                &v,
                vec![v.cose("D1_bob_epoch0_seq1"), v.negative("tampered_D1")]
            )
        )
        .await,
        v.expected_code("tampered_D1").unwrap()
    );
    assert_eq!(server.store.data_unit(d1).await.unwrap(), None);

    // Another Resource's unit in this Resource's put is malformed.
    let other = ResourceId::from_bytes([0xee; 32]);
    let bob_keys = v.principal("bob");
    let foreign = DataUnit::seal(
        DataUnitHeader {
            resource_id: other,
            data_epoch: 1,
            actor: *bob_keys.descriptor().id(),
            sequence: 9,
            previous: None,
            control_head: head_hash(v.record_id("C6_key_epoch_1")),
        },
        b"x",
        &Dek::from_bytes([1; 32]),
        &bob_keys,
    )
    .unwrap();
    assert_eq!(
        reply_code(
            &mut bob,
            data_put(&v, vec![foreign.signed_object().bytes().to_vec()])
        )
        .await,
        MALFORMED_MESSAGE
    );

    // An unauthorized writer: CAROL at C2, before her claim.
    let carol = v.principal("carol");
    let early = DataUnit::seal(
        DataUnitHeader {
            resource_id: v.resource(),
            data_epoch: 0,
            actor: *carol.descriptor().id(),
            sequence: 1,
            previous: None,
            control_head: head_hash(v.record_id("C2_invite_grant")),
        },
        b"too early",
        &Dek::from_bytes([1; 32]),
        &carol,
    )
    .unwrap();
    assert_eq!(
        reply_code(
            &mut bob,
            data_put(&v, vec![early.signed_object().bytes().to_vec()])
        )
        .await,
        AUTHORIZATION_FAILED
    );

    // A referenced head the server does not have.
    let unknown_head = DataUnit::seal(
        DataUnitHeader {
            resource_id: v.resource(),
            data_epoch: 1,
            actor: *bob_keys.descriptor().id(),
            sequence: 9,
            previous: None,
            control_head: Hash32::from_bytes([7; 32]),
        },
        b"x",
        &Dek::from_bytes([1; 32]),
        &bob_keys,
    )
    .unwrap();
    assert_eq!(
        reply_code(
            &mut bob,
            data_put(&v, vec![unknown_head.signed_object().bytes().to_vec()])
        )
        .await,
        MISSING_DEPENDENCY
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn client_local_failures_are_accepted_by_the_server() {
    // N3: AEAD failures are detectable only with the DEK; §26.2: a broken
    // actor hash chain is reported by the sync engine, not the server.
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-local", 10, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;
    for (i, case) in [
        "aead_failure_D1",
        "noncanonical_aad_D1",
        "actor_seq1_prev_not_null_D1",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(v.expected_code(case), None, "{case} has no wire code");
        let unit = v.negative(case);
        let id = ReceivedDataUnit::parse(&unit).unwrap().id();
        bob.request(data_put(&v, vec![unit])).await;
        let reply = bob.recv().await;
        // Each is a sequence-1 unit of BOB: the first stored is plain, the
        // next ones equivocate with it and are stored as evidence.
        if i == 0 {
            assert!(
                matches!(reply.body, Body::Ack(_)),
                "{case}: {:?}",
                reply.body
            );
        } else {
            assert_eq!(code(&reply), ACTOR_EQUIVOCATION, "{case}");
        }
        assert!(
            server
                .store
                .data_unit(Hash32::from_bytes(*id.as_bytes()))
                .await
                .unwrap()
                .is_some(),
            "{case} stored"
        );
    }
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn equivocation_is_stored_as_evidence_and_reported() {
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-equivocation", 10, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;
    bob.request(data_put(
        &v,
        vec![v.cose("D1_bob_epoch0_seq1"), v.cose("D2_bob_epoch0_seq2")],
    ))
    .await;
    assert!(matches!(bob.recv().await.body, Body::Ack(_)));

    let conflicting = v.hex("actor_equivocation", "inputs", "conflicting_D2_cose");
    assert_eq!(
        reply_code(&mut bob, data_put(&v, vec![conflicting.clone()])).await,
        v.expected_code("actor_equivocation").unwrap()
    );
    let original = v.hex("actor_equivocation", "inputs", "original_D2_id");
    let conflicting_id = v.hex("actor_equivocation", "inputs", "conflicting_D2_id");
    let at2 = server
        .store
        .data_units_at(v.resource(), *v.principal("bob").descriptor().id(), 2)
        .await
        .unwrap();
    let mut both = vec![
        Hash32::from_bytes(original.try_into().unwrap()),
        Hash32::from_bytes(conflicting_id.try_into().unwrap()),
    ];
    both.sort_by_key(|h| *h.as_bytes());
    assert_eq!(at2, both, "both kept");

    // DATA_GET serves both, side by side.
    let id = bob
        .request(Body::DataGet {
            resource_id: v.resource(),
            ranges: vec![DataRange {
                principal: *v.principal("bob").descriptor().id(),
                start: 1,
                end: 2,
            }],
        })
        .await;
    let batch = bob.recv().await;
    assert_eq!(batch.correlation_id, Some(id));
    let Body::DataBatch { units, .. } = batch.body else {
        panic!("expected DATA_BATCH")
    };
    assert_eq!(units.len(), 3);
    assert_eq!(units[0], v.cose("D1_bob_epoch0_seq1"));
    assert!(units.contains(&conflicting) && units.contains(&v.cose("D2_bob_epoch0_seq2")));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_equivocating_data_put_accepts_none_of_its_units() {
    // §51: a DATA_PUT is all-or-nothing; §26.2: the equivocating units are
    // kept as evidence, the request is answered NACK(ACTOR_EQUIVOCATION)
    // without details (§60), and nothing is pushed.
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-all-or-nothing", 10, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;
    let mut watcher = client(&server, &v.principal("owner")).await;
    watcher
        .request(Body::ResourceOpen {
            resource_id: v.resource(),
            control_heads: vec![],
            have: vec![],
            grant_ids: None,
            flags: Some(1),
        })
        .await;
    assert!(matches!(
        watcher.recv().await.body,
        Body::ResourceOpened { .. }
    ));
    let bob_id = *v.principal("bob").descriptor().id();
    let stored = |id: Hash32| {
        let store = server.store.clone();
        async move { store.data_unit(id).await.unwrap().is_some() }
    };
    let id_of =
        |bytes: &[u8]| Hash32::from_bytes(*ReceivedDataUnit::parse(bytes).unwrap().id().as_bytes());

    bob.request(data_put(&v, vec![v.cose("D1_bob_epoch0_seq1")]))
        .await;
    assert!(matches!(bob.recv().await.body, Body::Ack(_)));
    assert!(matches!(watcher.recv().await.body, Body::DataBatch { .. }));

    // D2 is fine, but the request also carries a second sequence 1.
    let d2 = v.cose("D2_bob_epoch0_seq2");
    let twin = v.negative("actor_seq1_prev_not_null_D1");
    let id = bob
        .request(data_put(&v, vec![d2.clone(), twin.clone()]))
        .await;
    let reply = bob.recv().await;
    assert_eq!(reply.correlation_id, Some(id));
    let Body::Nack(nack) = &reply.body else {
        panic!("expected NACK, got {:?}", reply.body)
    };
    assert_eq!(nack.code, ACTOR_EQUIVOCATION);
    assert_eq!(nack.details, None, "Data Plane NACKs carry no details");
    assert!(!stored(id_of(&d2)).await, "D2 not accepted");
    assert!(stored(id_of(&twin)).await, "the twin kept as evidence");

    // Two different units for one slot in the same request: both are
    // evidence, neither is accepted.
    let conflicting = v.hex("actor_equivocation", "inputs", "conflicting_D2_cose");
    assert_eq!(
        reply_code(
            &mut bob,
            data_put(&v, vec![d2.clone(), conflicting.clone()])
        )
        .await,
        ACTOR_EQUIVOCATION
    );
    let at2 = server
        .store
        .data_units_at(v.resource(), bob_id, 2)
        .await
        .unwrap();
    assert_eq!(at2.len(), 2, "both kept as evidence");

    // Nothing of either request reached the subscriber: the PONG to its
    // PING is the next message it sees.
    watcher.request(Body::Ping([5; 8])).await;
    assert!(matches!(watcher.recv().await.body, Body::Pong(_)));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn key_packages_are_validated_and_served_to_their_recipient() {
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-kp", 10, Options::default()).await;
    let mut owner = client(&server, &v.principal("owner")).await;

    // The published KEY_PACKAGE_PUT, then each published package.
    let put = Message::decode(&v.message("KEY_PACKAGE_PUT"), &Default::default()).unwrap();
    let Body::KeyPackagePut { packages, .. } = &put.body else {
        panic!()
    };
    let ids: Vec<Hash32> = packages
        .iter()
        .map(|p| ReceivedKeyPackage::parse(p).unwrap().id())
        .collect();
    owner.send_bytes(v.message("KEY_PACKAGE_PUT")).await;
    let reply = owner.recv().await;
    assert_eq!(reply.correlation_id, Some(put.message_id));
    assert_eq!(reply.body, ack(42, ids));
    for (case, sender) in [
        ("KP0_bob_epoch0", "owner"),
        ("KPI_invite_epoch0", "owner"),
        ("KPC_carol_epoch1", "bob"),
    ] {
        let mut sender = client(&server, &v.principal(sender)).await;
        sender
            .request(Body::KeyPackagePut {
                resource_id: v.resource(),
                packages: vec![v.cose(case)],
            })
            .await;
        assert_eq!(
            sender.recv().await.body,
            ack(42, vec![id_of(&v, case, "package_id")]),
            "{case}"
        );
    }
    assert_eq!(
        reply_code(
            &mut owner,
            Body::KeyPackagePut {
                resource_id: v.resource(),
                packages: vec![v.negative("kp_enc_wrong_size_KP0")],
            }
        )
        .await,
        v.expected_code("kp_enc_wrong_size_KP0").unwrap()
    );

    // An unauthorized distributor: CAROL, who holds no key/distribute.
    let carol = v.principal("carol");
    let rogue = KeyPackage::seal(
        v.resource(),
        1,
        head_hash(v.record_id("C10_revoke_grandchild")),
        &Dek::from_bytes([5; 32]),
        v.principal("bob").descriptor(),
        &carol,
    )
    .unwrap();
    let mut carol_client = client(&server, &carol).await;
    assert_eq!(
        reply_code(
            &mut carol_client,
            Body::KeyPackagePut {
                resource_id: v.resource(),
                packages: vec![rogue.signed_object().bytes().to_vec()],
            }
        )
        .await,
        AUTHORIZATION_FAILED
    );

    // Served only to the recipient (§52): CAROL gets KPC, not BOB's KP0.
    let carol_id = *carol.descriptor().id();
    let id = carol_client
        .request(Body::KeyPackageGet {
            resource_id: v.resource(),
            recipient: carol_id,
            epochs: vec![0, 1],
        })
        .await;
    let batch = carol_client.recv().await;
    assert_eq!(batch.correlation_id, Some(id));
    assert_eq!(
        batch.body,
        Body::KeyPackageBatch {
            resource_id: v.resource(),
            packages: vec![v.cose("KPC_carol_epoch1")],
        }
    );
    assert_eq!(
        reply_code(
            &mut carol_client,
            Body::KeyPackageGet {
                resource_id: v.resource(),
                recipient: *v.principal("bob").descriptor().id(),
                epochs: vec![0],
            }
        )
        .await,
        AUTHORIZATION_FAILED
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Security review H4: DATA_GET ranges and KEY_PACKAGE_GET epochs are
/// counted, deduplicated and merged before anything is loaded.
#[tokio::test(flavor = "multi_thread")]
async fn get_requests_are_capped_and_deduplicated_before_loading() {
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-get-caps", 10, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;
    bob.request(data_put(
        &v,
        vec![v.cose("D1_bob_epoch0_seq1"), v.cose("D2_bob_epoch0_seq2")],
    ))
    .await;
    assert!(matches!(bob.recv().await.body, Body::Ack(_)));
    bob.request(Body::KeyPackagePut {
        resource_id: v.resource(),
        packages: vec![v.cose("KPC_carol_epoch1")],
    })
    .await;
    assert!(matches!(bob.recv().await.body, Body::Ack(_)));

    let actor = *v.principal("bob").descriptor().id();
    let range = |start, end| DataRange {
        principal: actor,
        start,
        end,
    };
    let data_get = |resource_id, ranges| Body::DataGet {
        resource_id,
        ranges,
    };
    // 256 ranges (§49), overlapping and repeated: each unit once.
    let mut ranges = vec![range(1, 2); 254];
    ranges.extend([range(2, 2), range(1, 1)]);
    let id = bob.request(data_get(v.resource(), ranges)).await;
    let batch = bob.recv().await;
    assert_eq!(batch.correlation_id, Some(id));
    let Body::DataBatch { units, .. } = batch.body else {
        panic!("expected DATA_BATCH")
    };
    assert_eq!(
        units,
        vec![v.cose("D1_bob_epoch0_seq1"), v.cose("D2_bob_epoch0_seq2")]
    );
    // 257 ranges are refused, on an unknown Resource too: nothing is
    // looked up first.
    assert_eq!(
        reply_code(&mut bob, data_get(v.resource(), vec![range(1, 1); 257])).await,
        MALFORMED_MESSAGE
    );
    assert_eq!(
        reply_code(
            &mut bob,
            data_get(ResourceId::from_bytes([7; 32]), vec![range(1, 1); 257])
        )
        .await,
        MALFORMED_MESSAGE
    );

    let carol = v.principal("carol");
    let mut carol_client = client(&server, &carol).await;
    let key_get = |resource_id, epochs| Body::KeyPackageGet {
        resource_id,
        recipient: *carol.descriptor().id(),
        epochs,
    };
    // Repeated epochs are looked up once.
    let id = carol_client
        .request(key_get(v.resource(), vec![1; 10_000]))
        .await;
    let batch = carol_client.recv().await;
    assert_eq!(batch.correlation_id, Some(id));
    assert_eq!(
        batch.body,
        Body::KeyPackageBatch {
            resource_id: v.resource(),
            packages: vec![v.cose("KPC_carol_epoch1")],
        }
    );
    // More than 256 distinct epochs are refused before any lookup.
    for resource in [v.resource(), ResourceId::from_bytes([7; 32])] {
        assert_eq!(
            reply_code(&mut carol_client, key_get(resource, (0..257).collect())).await,
            MALFORMED_MESSAGE
        );
    }
    let id = carol_client
        .request(key_get(v.resource(), (0..256).collect()))
        .await;
    assert_eq!(carol_client.recv().await.correlation_id, Some(id));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

fn bob_snapshot(v: &Vectors, epoch: u64, sequence: u64, contiguous: u64) -> Vec<u8> {
    let bob = v.principal("bob");
    let header = SnapshotHeader {
        resource_id: v.resource(),
        data_epoch: epoch,
        publisher: *bob.descriptor().id(),
        sequence,
        control_head: head_hash(v.record_id("C10_revoke_grandchild")),
        frontier: Frontier::new(vec![ActorHave {
            principal: *bob.descriptor().id(),
            contiguous,
            extra: vec![],
        }])
        .unwrap(),
    };
    Snapshot::seal(header, b"snapshot", &Dek::from_bytes([6; 32]), &bob)
        .unwrap()
        .signed_object()
        .bytes()
        .to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshots_are_validated_and_served() {
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-snapshot", 10, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;

    let put = Message::decode(&v.message("SNAPSHOT_PUT"), &Default::default()).unwrap();
    let Body::SnapshotPut { snapshot, .. } = &put.body else {
        panic!()
    };
    let id = ReceivedSnapshot::parse(snapshot).unwrap().id();
    bob.send_bytes(v.message("SNAPSHOT_PUT")).await;
    let reply = bob.recv().await;
    assert_eq!(reply.correlation_id, Some(put.message_id));
    assert_eq!(reply.body, ack(52, vec![id]));
    for case in ["SNAPSHOT-01", "SNAPSHOT-02"] {
        bob.request(Body::SnapshotPut {
            resource_id: v.resource(),
            snapshot: v.cose(case),
        })
        .await;
        assert_eq!(
            bob.recv().await.body,
            ack(52, vec![id_of(&v, case, "snapshot_id")]),
            "{case}"
        );
    }

    // Published negatives: malformed frontiers and sequence 0.
    let negatives = [
        "have_empty_extra_list",
        "have_range_reversed",
        "have_range_not_above_contiguous",
        "have_range_at_contiguous_plus_one",
        "have_ranges_unsorted",
        "have_ranges_overlapping",
        "have_ranges_adjacent",
        "frontier_duplicate_principal",
        "frontier_unsorted",
        "snapshot_sequence_zero",
        // §29 (G-EP4), baseline.4: epoch 0 at C5 covering BOB 1..3.
        "snapshot_beyond_cutoff",
    ];
    for case in negatives {
        let wanted = v.expected_code(case).unwrap_or(MALFORMED_MESSAGE);
        assert_eq!(
            reply_code(
                &mut bob,
                Body::SnapshotPut {
                    resource_id: v.resource(),
                    snapshot: v.negative(case),
                }
            )
            .await,
            wanted,
            "{case}"
        );
    }

    // G-EP4: epoch 0 closed at BOB's sequence 2 (C6). A frontier within it
    // is accepted; one beyond it is stale.
    bob.request(Body::SnapshotPut {
        resource_id: v.resource(),
        snapshot: bob_snapshot(&v, 0, 1, 2),
    })
    .await;
    assert!(matches!(bob.recv().await.body, Body::Ack(_)));
    assert_eq!(
        reply_code(
            &mut bob,
            Body::SnapshotPut {
                resource_id: v.resource(),
                snapshot: bob_snapshot(&v, 0, 2, 3),
            }
        )
        .await,
        STALE_DATA_EPOCH
    );

    // An unauthorized publisher: the INVITE principal holds no
    // snapshot/publish.
    let invite = v.principal("invite");
    let header = SnapshotHeader {
        resource_id: v.resource(),
        data_epoch: 1,
        publisher: *invite.descriptor().id(),
        sequence: 1,
        control_head: head_hash(v.record_id("C10_revoke_grandchild")),
        frontier: Frontier::new(vec![]).unwrap(),
    };
    let rogue = Snapshot::seal(header, b"x", &Dek::from_bytes([6; 32]), &invite).unwrap();
    assert_eq!(
        reply_code(
            &mut bob,
            Body::SnapshotPut {
                resource_id: v.resource(),
                snapshot: rogue.signed_object().bytes().to_vec(),
            }
        )
        .await,
        AUTHORIZATION_FAILED
    );

    // SNAPSHOT_GET: the published request names SNAPSHOT-01.
    let get = Message::decode(&v.message("SNAPSHOT_GET"), &Default::default()).unwrap();
    bob.send_bytes(v.message("SNAPSHOT_GET")).await;
    let reply = bob.recv().await;
    assert_eq!(reply.correlation_id, Some(get.message_id));
    let Body::Snapshot { snapshot, .. } = reply.body else {
        panic!("expected SNAPSHOT")
    };
    let Body::SnapshotGet {
        snapshot_id: Some(wanted),
        ..
    } = get.body
    else {
        panic!()
    };
    assert_eq!(ReceivedSnapshot::parse(&snapshot).unwrap().id(), wanted);
    // Without an ID: the preferred latest; an unknown ID: missing.
    bob.request(Body::SnapshotGet {
        resource_id: v.resource(),
        snapshot_id: None,
    })
    .await;
    assert!(matches!(bob.recv().await.body, Body::Snapshot { .. }));
    assert_eq!(
        reply_code(
            &mut bob,
            Body::SnapshotGet {
                resource_id: v.resource(),
                snapshot_id: Some(Hash32::from_bytes([1; 32])),
            }
        )
        .await,
        MISSING_DEPENDENCY
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn data_reads_need_read_authority() {
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-read", 10, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;
    bob.request(data_put(
        &v,
        vec![v.cose("D1_bob_epoch0_seq1"), v.cose("D2_bob_epoch0_seq2")],
    ))
    .await;
    bob.recv().await;

    // DATA_HAVE answers the server's Have.
    let id = bob
        .request(Body::DataHave {
            resource_id: v.resource(),
            have: vec![],
        })
        .await;
    let reply = bob.recv().await;
    assert_eq!(reply.correlation_id, Some(id));
    assert_eq!(
        reply.body,
        Body::DataHave {
            resource_id: v.resource(),
            have: vec![WireActorHave {
                principal: *v.principal("bob").descriptor().id(),
                contiguous: 2,
                extra: None,
            }],
        }
    );
    // A reversed range is malformed (G-MSG6), whether the codec or the
    // server catches it.
    bob.send_bytes(v.hex("data_have_reversed_range", "inputs", "message_cbor"))
        .await;
    assert_eq!(code(&bob.recv().await), MALFORMED_MESSAGE);
    assert_eq!(
        reply_code(
            &mut bob,
            Body::DataGet {
                resource_id: v.resource(),
                ranges: vec![DataRange {
                    principal: *v.principal("bob").descriptor().id(),
                    start: 2,
                    end: 1,
                }],
            }
        )
        .await,
        MALFORMED_MESSAGE
    );

    // A stranger reads nothing.
    let stranger = PrincipalKeys::from_secrets(&[77; 32], [78; 32]);
    let mut outsider = client(&server, &stranger).await;
    for body in [
        Body::DataHave {
            resource_id: v.resource(),
            have: vec![],
        },
        Body::DataGet {
            resource_id: v.resource(),
            ranges: vec![DataRange {
                principal: *v.principal("bob").descriptor().id(),
                start: 1,
                end: 2,
            }],
        },
        Body::SnapshotGet {
            resource_id: v.resource(),
            snapshot_id: None,
        },
        Body::KeyPackageGet {
            resource_id: v.resource(),
            recipient: *stranger.descriptor().id(),
            epochs: vec![0],
        },
    ] {
        assert_eq!(reply_code(&mut outsider, body).await, AUTHORIZATION_FAILED);
    }

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Refuses Data Units beyond one per put.
struct OneUnitAtATime;

impl IngestPolicy for OneUnitAtATime {
    fn admit(
        &self,
        _: &ResourceId,
        kind: ObjectKind,
        count: usize,
        _: usize,
    ) -> Result<(), Refusal> {
        if kind == ObjectKind::DataUnit && count > 1 {
            Err(Refusal::Quota)
        } else {
            Ok(())
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ingest_policy_is_a_distinct_failure() {
    let v = Vectors::load();
    let options = Options {
        ingest: Some(Arc::new(OneUnitAtATime)),
        ..Options::default()
    };
    let (server, dir) = chain_server(&v, "data-quota", 10, options).await;
    let mut bob = client(&server, &v.principal("bob")).await;
    let both = vec![v.cose("D1_bob_epoch0_seq1"), v.cose("D2_bob_epoch0_seq2")];
    assert_eq!(
        reply_code(&mut bob, data_put(&v, both)).await,
        QUOTA_EXCEEDED
    );
    // Validation comes first: an invalid unit is still INVALID_SIGNATURE.
    assert_eq!(
        reply_code(&mut bob, data_put(&v, vec![v.negative("tampered_D1")])).await,
        v.expected_code("tampered_D1").unwrap()
    );
    bob.request(data_put(&v, vec![v.cose("D1_bob_epoch0_seq1")]))
        .await;
    assert!(matches!(bob.recv().await.body, Body::Ack(_)));
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_units_are_pushed_to_live_data_subscribers() {
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-push", 10, Options::default()).await;
    let open = |flags| Body::ResourceOpen {
        resource_id: v.resource(),
        control_heads: vec![],
        have: vec![],
        grant_ids: None,
        flags: Some(flags),
    };
    let mut bob = client(&server, &v.principal("bob")).await;
    bob.request(open(0b001)).await;
    bob.recv().await;
    let mut carol = client(&server, &v.principal("carol")).await;
    carol.request(open(0b001)).await;
    carol.recv().await;
    let mut control_only = client(&server, &v.principal("bob")).await;
    control_only.request(open(0b010)).await;
    control_only.recv().await;

    let units = vec![v.cose("D1_bob_epoch0_seq1"), v.cose("D2_bob_epoch0_seq2")];
    bob.request(data_put(&v, units.clone())).await;
    assert!(matches!(bob.recv().await.body, Body::Ack(_)));
    let push = carol.recv().await;
    assert_eq!(push.correlation_id, None);
    assert_eq!(
        push.body,
        Body::DataBatch {
            resource_id: v.resource(),
            units: units.clone(),
        }
    );
    // A duplicate put is not pushed again; the writer and the
    // Control-only subscriber get no pushes.
    bob.request(data_put(&v, units)).await;
    assert!(matches!(bob.recv().await.body, Body::Ack(_)));
    for client in [&mut carol, &mut control_only, &mut bob] {
        client.request(Body::Ping([8; 8])).await;
        assert_eq!(client.recv().await.body, Body::Pong([8; 8]));
    }

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

fn sign(
    v: &Vectors,
    keys: &PrincipalKeys,
    sequence: u64,
    previous: ControlRecordId,
    body: ControlBody,
) -> Vec<u8> {
    ControlRecord::sign(
        ControlRecordHeader {
            resource_id: v.resource(),
            sequence,
            previous: Some(previous),
            issuer: *keys.descriptor().id(),
        },
        body,
        keys,
    )
    .unwrap()
    .signed_object()
    .bytes()
    .to_vec()
}

fn record_id(bytes: &[u8]) -> ControlRecordId {
    ReceivedControlRecord::parse(bytes).unwrap().id()
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribers_that_lose_read_authority_stop_receiving_pushes() {
    let v = Vectors::load();
    let options = Options {
        public_urls: vec![SYNC_A.into(), SYNC_B.into()],
        ..Options::default()
    };
    let (server, dir) = chain_server(&v, "data-revalidate", 8, options).await;
    let bob_keys = v.principal("bob");
    let mut bob = client(&server, &bob_keys).await;
    let mut carol = client(&server, &v.principal("carol")).await;
    carol
        .request(Body::ResourceOpen {
            resource_id: v.resource(),
            control_heads: vec![],
            have: vec![],
            grant_ids: None,
            flags: Some(0b011),
        })
        .await;
    assert!(matches!(
        carol.recv().await.body,
        Body::ResourceOpened { .. }
    ));

    // BOB (owner since C4) commits a grant: CAROL still reads, gets it.
    let stranger = PrincipalKeys::from_secrets(&[61; 32], [62; 32]);
    let grant = |subject: &PrincipalKeys| {
        ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: subject.descriptor().clone(),
            abilities: vec![1],
            delegable: vec![],
            parent: None,
            claim_limit: None,
        })
    };
    let mut head = v.record_id("C8_grant_owner_delegated");
    let mut seq = 8;
    let mut commit = |body: ControlBody| {
        seq += 1;
        let record = sign(&v, &bob_keys, seq, head, body);
        let expected = head;
        head = record_id(&record);
        (expected, record)
    };
    let put = async |client: &mut Client, (expected, record): (ControlRecordId, Vec<u8>)| {
        client
            .request(Body::ControlPut {
                resource_id: v.resource(),
                expected_head: expected,
                record: record.clone(),
            })
            .await;
        assert!(matches!(client.recv().await.body, Body::Ack(_)));
        record
    };
    let first = put(&mut bob, commit(grant(&stranger))).await;
    assert_eq!(
        carol.recv().await.body,
        Body::ControlBatch {
            resource_id: v.resource(),
            records: vec![first],
        }
    );

    // Revoke both of CAROL's read sources: her claim (C3) and C7.
    for grant_id in ["C3_invite_claim_carol", "C7_grant_carol_delegator"] {
        put(
            &mut bob,
            commit(ControlBody::CapabilityRevoke(CapabilityRevokeBody {
                grant: v.record_id(grant_id),
            })),
        )
        .await;
    }
    let last = put(&mut bob, commit(grant(&v.principal("invite")))).await;
    // Pushes stopped: before her PONG she sees at most the first revoke,
    // never the records after she lost read.
    carol.request(Body::Ping([2; 8])).await;
    let mut seen = Vec::new();
    loop {
        let message = carol.recv().await;
        match message.body {
            Body::Pong(_) => break,
            Body::ControlBatch { records, .. } => seen.extend(records),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(seen.len() <= 1, "{} pushes after the revokes", seen.len());
    assert!(!seen.contains(&last));
    // Her next request for the Resource is refused; the session stays.
    assert_eq!(
        reply_code(
            &mut carol,
            Body::ControlGet {
                resource_id: v.resource(),
                start: 0,
                end: 1,
            }
        )
        .await,
        AUTHORIZATION_FAILED
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn ingested_objects_stay_opaque() {
    let v = Vectors::load();
    let (server, dir) = chain_server(&v, "data-opaque", 10, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;
    bob.request(data_put(
        &v,
        vec![v.cose("D1_bob_epoch0_seq1"), v.cose("D2_bob_epoch0_seq2")],
    ))
    .await;
    bob.recv().await;
    bob.request(data_put(&v, vec![v.cose("D3_bob_epoch0_seq3_stale")]))
        .await;
    bob.recv().await;
    let mut carol = client(&server, &v.principal("carol")).await;
    carol
        .request(data_put(&v, vec![v.cose("D4_carol_epoch1_seq1")]))
        .await;
    carol.recv().await;
    for snapshot in ["SNAPSHOT-01", "SNAPSHOT-02"] {
        bob.request(Body::SnapshotPut {
            resource_id: v.resource(),
            snapshot: v.cose(snapshot),
        })
        .await;
        bob.recv().await;
    }
    let mut owner = client(&server, &v.principal("owner")).await;
    owner
        .request(Body::KeyPackagePut {
            resource_id: v.resource(),
            packages: vec![v.cose("KP0_bob_epoch0"), v.cose("KPI_invite_epoch0")],
        })
        .await;
    owner.recv().await;
    server.stop().await;

    // Neither plaintexts nor DEKs appear in the database or its WAL.
    let mut bytes = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
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
    assert!(!bytes.is_empty());
    let mut secrets: Vec<Vec<u8>> = [
        "D1_bob_epoch0_seq1",
        "D2_bob_epoch0_seq2",
        "D3_bob_epoch0_seq3_stale",
        "D4_carol_epoch1_seq1",
        "SNAPSHOT-01",
        "SNAPSHOT-02",
    ]
    .iter()
    .map(|c| {
        v.case(c)["inputs"]["plaintext_utf8"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec()
    })
    .collect();
    for dek in ["dek0", "dek1"] {
        secrets.push(v.resource_fixture(dek));
    }
    for secret in secrets {
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_slice()),
            "a plaintext or DEK reached the database"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

const UNKNOWN_PREVIOUS: u64 = 23;

/// A Snapshot by BOB whose frontier is `frontier_cbor` (a canonical
/// frontier, as the data_put_previous vectors give it).
fn snapshot_with_frontier(v: &Vectors, frontier_cbor: &[u8]) -> Vec<u8> {
    let bob = v.principal("bob");
    let value = lfcp::cbor::decode_strict(frontier_cbor).unwrap();
    let header = SnapshotHeader {
        resource_id: v.resource(),
        data_epoch: 1,
        publisher: *bob.descriptor().id(),
        sequence: 1,
        control_head: head_hash(v.record_id("C10_revoke_grandchild")),
        frontier: Frontier::from_value(&value).unwrap(),
    };
    Snapshot::seal(header, b"snapshot", &Dek::from_bytes([6; 32]), &bob)
        .unwrap()
        .signed_object()
        .bytes()
        .to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_data_put_whose_previous_the_server_lost_is_refused() {
    // WIRE-01 §51.1 (mvp-0.1-baseline.9, ADR 0008 (b)): each
    // data_put_previous vector against a server holding its stored units
    // and Snapshot, through a session of another Principal than the actor.
    let v = Vectors::load();
    let cases: Vec<serde_json::Value> = v.json()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "data_put_previous")
        .cloned()
        .collect();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let (server, _dir) = chain_server(&v, &format!("prev-{id}"), 10, Options::default()).await;
        let inputs = case["inputs"].as_object().unwrap();
        let hex_of = |value: &serde_json::Value| {
            lfcp::base::from_hex(value["hex"].as_str().unwrap()).unwrap()
        };
        let stored: Vec<Vec<u8>> = inputs
            .iter()
            .filter(|(k, _)| k.starts_with("stored_") && k.ends_with("_cose"))
            .map(|(_, value)| hex_of(value))
            .collect();
        if !stored.is_empty() {
            server.store.put_data_units(stored).await.unwrap();
        }
        if let Some(frontier) = inputs.get("stored_snapshot_frontier") {
            let snapshot = snapshot_with_frontier(&v, &hex_of(frontier));
            server.store.put_snapshot(snapshot).await.unwrap();
        }
        let message =
            Message::decode(&hex_of(&inputs["message_cbor"]), &Default::default()).unwrap();
        let Body::DataPut { units, .. } = message.body else {
            panic!("{id}: not a DATA_PUT")
        };
        let mut session = client(&server, &v.principal("bob")).await;
        let request = session.request(data_put(&v, units.clone())).await;
        let reply = session.recv().await;
        assert_eq!(reply.correlation_id, Some(request), "{id}");
        let expected = &case["expected"];
        if expected["valid"] == true {
            assert!(matches!(reply.body, Body::Ack(_)), "{id}: {:?}", reply.body);
            for unit in &units {
                let unit_id = ReceivedDataUnit::parse(unit).unwrap().id();
                let stored = server
                    .store
                    .data_unit(Hash32::from_bytes(*unit_id.as_bytes()))
                    .await
                    .unwrap();
                assert_eq!(stored.as_ref(), Some(unit), "{id}: stored");
            }
        } else {
            let Body::Nack(body) = &reply.body else {
                panic!("{id}: expected a NACK, got {:?}", reply.body)
            };
            assert_eq!(body.code, UNKNOWN_PREVIOUS, "{id}: code");
            let details = body.details.as_ref().and_then(|d| d.as_bytes()).unwrap();
            assert_eq!(
                details,
                hex_of(&expected["error"]["details"]),
                "{id}: details"
            );
            for unit in &units {
                let unit_id = ReceivedDataUnit::parse(unit).unwrap().id();
                if inputs.values().any(|value| {
                    value
                        .get("hex")
                        .is_some_and(|h| h == &lfcp::base::to_hex(unit))
                }) {
                    continue; // stored before the put
                }
                let stored = server
                    .store
                    .data_unit(Hash32::from_bytes(*unit_id.as_bytes()))
                    .await
                    .unwrap();
                assert_eq!(
                    stored, None,
                    "{id}: nothing of a refused DATA_PUT is stored"
                );
            }
        }
    }
}

/// `count` units of BOB from sequence 1, chained, in epoch 0 at C5.
fn bob_chain(v: &Vectors, count: u64) -> Vec<DataUnit> {
    let bob = v.principal("bob");
    let mut previous = None;
    (1..=count)
        .map(|sequence| {
            let unit = DataUnit::seal(
                DataUnitHeader {
                    resource_id: v.resource(),
                    data_epoch: 0,
                    actor: *bob.descriptor().id(),
                    sequence,
                    previous,
                    control_head: head_hash(v.record_id("C5_route_update")),
                },
                format!("unit {sequence}").as_bytes(),
                &Dek::from_bytes([9; 32]),
                &bob,
            )
            .unwrap();
            previous = Some(unit.id());
            unit
        })
        .collect()
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restored_server_refuses_the_next_unit_until_the_lost_one_is_relayed() {
    // ADR 0008, the drill: units 1–3 are backed up, 4 is acknowledged and
    // then lost to a restore. The writer's unit 5 names 4: refused with
    // UNKNOWN_PREVIOUS (WIRE-01 §51.1) instead of wedging readers. Another
    // Principal relays 4 (§68.1, §84); then 5 is accepted.
    let v = Vectors::load();
    let units = bob_chain(&v, 5);
    let bytes = |i: usize| units[i].signed_object().bytes().to_vec();
    let stored = |server: &Running, i: usize| {
        let store = server.store.clone();
        let id = Hash32::from_bytes(*units[i].id().as_bytes());
        async move { store.data_unit(id).await.unwrap().is_some() }
    };
    let (server, dir) = chain_server(&v, "drill", 5, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;
    for i in 0..3 {
        assert_eq!(
            reply_code_or_ack(&mut bob, data_put(&v, vec![bytes(i)])).await,
            None
        );
    }
    server.stop().await;
    let backup = state_dir("drill-backup");
    copy_dir(&dir, &backup);

    let server = start(&dir, Options::default()).await;
    let mut bob = client(&server, &v.principal("bob")).await;
    assert_eq!(
        reply_code_or_ack(&mut bob, data_put(&v, vec![bytes(3)])).await,
        None
    );
    server.stop().await;

    // The restore: the store as it was before unit 4.
    std::fs::remove_dir_all(&dir).unwrap();
    copy_dir(&backup, &dir);
    let server = start(&dir, Options::default()).await;
    assert!(!stored(&server, 3).await, "unit 4 is lost");

    let mut bob = client(&server, &v.principal("bob")).await;
    let id = bob.request(data_put(&v, vec![bytes(4)])).await;
    let reply = bob.recv().await;
    assert_eq!(reply.correlation_id, Some(id));
    let Body::Nack(body) = &reply.body else {
        panic!("expected a NACK, got {:?}", reply.body)
    };
    assert_eq!(body.code, UNKNOWN_PREVIOUS);
    assert_eq!(
        body.details.as_ref().and_then(|d| d.as_bytes()),
        Some(units[3].id().as_bytes().as_slice()),
        "the details name the lost unit"
    );
    assert!(!stored(&server, 4).await, "unit 5 is not stored");

    // CAROL relays BOB's unit 4: the server authorizes the object, not the
    // session that uploads it.
    let mut carol = client(&server, &v.principal("carol")).await;
    assert_eq!(
        reply_code_or_ack(&mut carol, data_put(&v, vec![bytes(3)])).await,
        None
    );
    assert_eq!(
        reply_code_or_ack(&mut bob, data_put(&v, vec![bytes(4)])).await,
        None
    );
    for i in 0..5 {
        assert!(stored(&server, i).await, "unit {}", i + 1);
    }
    server.stop().await;
    let _ = std::fs::remove_dir_all(&backup);
}

/// `None` for an ACK, else the NACK's code.
async fn reply_code_or_ack(client: &mut Client, body: Body) -> Option<u64> {
    let id = client.request(body).await;
    let reply = client.recv().await;
    assert_eq!(reply.correlation_id, Some(id));
    match reply.body {
        Body::Ack(_) => None,
        _ => Some(code(&reply)),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn any_session_may_relay_a_validly_signed_object() {
    // WIRE-01 §84 (mvp-0.1-baseline.9, ADR 0008): the server authorizes the
    // uploaded object, not the session. OWNER's session uploads CAROL's
    // Control Record C10, BOB's Key Package for CAROL and BOB's Snapshot.
    let v = Vectors::load();
    // C5 moves the Control Coordinator to sync-b.
    let options = Options {
        public_urls: vec![SYNC_A.into(), SYNC_B.into()],
        ..Options::default()
    };
    let (server, _dir) = chain_server(&v, "relay", 9, options).await;
    let mut owner = client(&server, &v.principal("owner")).await;
    owner
        .request(Body::ControlPut {
            resource_id: v.resource(),
            expected_head: v.record_id("C9_grant_invite_grandchild"),
            record: v.cose("C10_revoke_grandchild"),
        })
        .await;
    assert_eq!(
        owner.recv().await.body,
        ack(23, vec![head_hash(v.record_id("C10_revoke_grandchild"))]),
        "CAROL's record"
    );
    owner
        .request(Body::KeyPackagePut {
            resource_id: v.resource(),
            packages: vec![v.cose("KPC_carol_epoch1")],
        })
        .await;
    assert_eq!(
        owner.recv().await.body,
        ack(42, vec![id_of(&v, "KPC_carol_epoch1", "package_id")]),
        "BOB's Key Package"
    );
    let snapshot = v.cose("SNAPSHOT-01");
    owner
        .request(Body::SnapshotPut {
            resource_id: v.resource(),
            snapshot: snapshot.clone(),
        })
        .await;
    assert_eq!(
        owner.recv().await.body,
        ack(52, vec![ReceivedSnapshot::parse(&snapshot).unwrap().id()]),
        "BOB's Snapshot"
    );
}
