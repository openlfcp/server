//! Shared sections through the server (LFCP-02-031): Data Units and a
//! Snapshot produced by sdk-rs for a `org.openlfcp.shared-sections.v1`
//! Resource are hosted, acknowledged, stored byte for byte and served like
//! any other, next to a Shared Objects Resource on the same server. The
//! server never reads a Data Profile or a plaintext: these tests build the
//! units with the SDK (a dev-dependency only; the server itself links the
//! protocol core, tests/dependency_policy.rs) and check the plaintext on
//! the client side.

mod support;

use automerge::ActorId;
use lfcp::base::{Hash32, ObjectId, PrincipalId, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::shared_objects::document::{NewTask, SharedObjects};
use lfcp::shared_objects::framing;
use lfcp::shared_sections::{self, NewNode, Received, SectionsDoc, SectionsReplica};
use lfcp::wire::control::body::{ControlBody, Endpoint, GenesisBody};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use lfcp::wire::data_unit::{DataUnit, DataUnitHeader, ReceivedDataUnit};
use lfcp::wire::frontier::{ActorHave, Frontier};
use lfcp::wire::keys::Dek;
use lfcp::wire::message::{AckBody, Body, DataRange};
use lfcp::wire::snapshot::{ReceivedSnapshot, Snapshot, SnapshotHeader};
use lfcp_server::config::MIN_MESSAGE_BYTES;
use support::lfcp::{code, start, state_dir, Client, Options, Running};

const SECTIONS: &str = "org.openlfcp.shared-sections.v1";
const OBJECTS: &str = "org.openlfcp.shared-objects.v1";
const MESSAGE_TOO_LARGE: u64 = 19;
const DATA_PUT: u64 = 33;
const SNAPSHOT_PUT: u64 = 52;

const SECTION: &str = "019a2f85-7b31-7c42-8000-000000000001";

/// A canonical UUIDv7 for test object `n` of kind `k`.
fn uuid(k: u16, n: u32) -> String {
    format!("019a2f85-7b31-7c42-{:04x}-{n:012x}", 0x8000 | k)
}

fn alice() -> PrincipalKeys {
    PrincipalKeys::from_secrets(&[1; 32], [2; 32])
}

fn dek() -> Dek {
    Dek::from_bytes([9; 32])
}

/// The Genesis of `resource`, owned by `owner`, with `profile`.
fn genesis(owner: &PrincipalKeys, resource: ResourceId, profile: &str) -> Vec<u8> {
    let url = "wss://sync.example.test/v1/ws".to_owned();
    ControlRecord::sign(
        ControlRecordHeader {
            resource_id: resource,
            sequence: 0,
            previous: None,
            issuer: *owner.descriptor().id(),
        },
        ControlBody::Genesis(GenesisBody {
            data_profile: profile.into(),
            owner: owner.descriptor().clone(),
            dek_commitment: Hash32::from_bytes([3; 32]),
            endpoints: vec![Endpoint {
                url: url.clone(),
                priority: 0,
                flags: None,
            }],
            coordinator: url,
        }),
        owner,
    )
    .unwrap()
    .signed_object()
    .bytes()
    .to_vec()
}

/// The Control Head a Genesis makes.
fn head(genesis: &[u8]) -> Hash32 {
    Hash32::from_bytes(
        *ReceivedControlRecord::parse(genesis)
            .unwrap()
            .id()
            .as_bytes(),
    )
}

/// Each plaintext as `owner`'s next Data Unit at epoch 0, chained by
/// `previous` (WIRE-01 §51.1).
fn seal_all(
    owner: &PrincipalKeys,
    resource: ResourceId,
    control_head: Hash32,
    plaintexts: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut previous = None;
    plaintexts
        .iter()
        .enumerate()
        .map(|(i, plaintext)| {
            let unit = DataUnit::seal(
                DataUnitHeader {
                    resource_id: resource,
                    data_epoch: 0,
                    actor: *owner.descriptor().id(),
                    sequence: i as u64 + 1,
                    previous,
                    control_head,
                },
                plaintext,
                &dek(),
                owner,
            )
            .unwrap();
            previous = Some(unit.id());
            unit.signed_object().bytes().to_vec()
        })
        .collect()
}

/// The plaintext of a served unit, as a client reads it: signature first.
fn open(bytes: &[u8], author: &PrincipalKeys) -> Vec<u8> {
    ReceivedDataUnit::parse(bytes)
        .unwrap()
        .verify(author.descriptor())
        .unwrap()
        .open(&dek())
        .unwrap()
}

fn unit_id(bytes: &[u8]) -> Hash32 {
    Hash32::from_bytes(*ReceivedDataUnit::parse(bytes).unwrap().id().as_bytes())
}

async fn client(server: &Running, keys: &PrincipalKeys) -> Client {
    let mut client = Client::connect(server.addr).await;
    client.handshake(keys).await;
    client
}

async fn host(client: &mut Client, genesis: Vec<u8>) {
    client
        .request(Body::ResourceHost {
            genesis,
            hosting_credential: None,
        })
        .await;
    let reply = client.recv().await;
    assert!(
        matches!(reply.body, Body::ResourceHosted { durability: 2, .. }),
        "{:?}",
        reply.body
    );
}

/// Puts `units` in DATA_PUTs of at most `per_put` units and checks that
/// every unit is acknowledged as durable.
async fn put_all(client: &mut Client, resource: ResourceId, units: &[Vec<u8>], per_put: usize) {
    for chunk in units.chunks(per_put) {
        client
            .request(Body::DataPut {
                resource_id: resource,
                units: chunk.to_vec(),
            })
            .await;
        let reply = client.recv().await;
        let Body::Ack(AckBody {
            request_type,
            object_ids: Some(mut ids),
            durable,
        }) = reply.body
        else {
            panic!("expected ACK, got {:?}", reply.body)
        };
        assert_eq!(request_type, DATA_PUT);
        assert_eq!(durable, Some(true));
        let mut want: Vec<Hash32> = chunk.iter().map(|u| unit_id(u)).collect();
        ids.sort_by_key(|h| *h.as_bytes());
        want.sort_by_key(|h| *h.as_bytes());
        assert_eq!(ids, want);
    }
}

/// Every unit of `actor` from 1 to `count`, as the server serves them, in
/// the pages it sends (WIRE-01 §49).
async fn get_all(
    client: &mut Client,
    resource: ResourceId,
    actor: PrincipalId,
    count: u64,
) -> Vec<Vec<u8>> {
    client
        .request(Body::DataGet {
            resource_id: resource,
            ranges: vec![DataRange {
                principal: actor,
                start: 1,
                end: count,
            }],
        })
        .await;
    let mut out = Vec::new();
    while (out.len() as u64) < count {
        let Body::DataBatch { units, .. } = client.recv().await.body else {
            panic!("expected DATA_BATCH")
        };
        assert!(!units.is_empty());
        out.extend(units);
    }
    out
}

/// A section of 200 Tasks, each with a paragraph of about 200 characters,
/// written with sdk-rs: one change per intent (SHARED-SECTIONS-PROFILE-01
/// §11), the section ready from its first change.
fn section_import(resource: ResourceId, owner: &PrincipalId) -> (SectionsDoc, Vec<Vec<u8>>) {
    let actor = shared_sections::actor_id(&resource, owner);
    let (mut doc, first) = SectionsDoc::create(actor, SECTION, "Joint launch", owner).unwrap();
    let mut changes = vec![first];
    let mut after: Option<String> = None;
    for i in 1..=200u32 {
        let task = uuid(1, i);
        let title = format!("Задача {i}: prepare the launch");
        changes.push(
            doc.create_node(
                &task,
                NewNode::Task { title: &title },
                SECTION,
                after.as_deref(),
                &uuid(2, i),
                owner,
            )
            .unwrap(),
        );
        let text = format!("Notes {i} 😀 ").repeat(16);
        changes.push(
            doc.create_node(
                &uuid(3, i),
                NewNode::Paragraph { text: &text },
                &task,
                None,
                &uuid(4, i),
                owner,
            )
            .unwrap(),
        );
        after = Some(task);
    }
    let plaintexts = changes
        .iter()
        .map(|c| framing::encode_change(c.raw_bytes()))
        .collect();
    (doc, plaintexts)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_section_resource_is_hosted_stored_and_served_like_any_other() {
    let owner = alice();
    let owner_id = *owner.descriptor().id();
    // The section: 401 changes, one Data Unit each, built before any
    // session opens (the SDK's authoring is slow in a debug build).
    let sections = ResourceId::from_bytes([0x5e; 32]);
    let sections_genesis = genesis(&owner, sections, SECTIONS);
    let started = std::time::Instant::now();
    let (mut author, plaintexts) = section_import(sections, &owner_id);
    let units = seal_all(&owner, sections, head(&sections_genesis), &plaintexts);
    println!("sections: built in {:?}", started.elapsed());

    let dir = state_dir("sections-import");
    let server = start(&dir, Options::default()).await;
    let mut writer = client(&server, &owner).await;

    // Both profiles on one server: the server reads neither.
    let objects = ResourceId::from_bytes([0x50; 32]);
    let objects_genesis = genesis(&owner, objects, OBJECTS);
    host(&mut writer, sections_genesis.clone()).await;
    host(&mut writer, objects_genesis.clone()).await;

    // A Shared Objects Resource with three Tasks.
    let mut tasks = SharedObjects::new(lfcp::shared_objects::identity::actor_id(
        &objects, &owner_id,
    ));
    let mut task_changes = vec![tasks.initialize().unwrap()];
    for i in 1..=3u32 {
        task_changes.push(
            tasks
                .create_task(&NewTask::new(
                    ObjectId::parse(&uuid(5, i)).unwrap(),
                    owner_id,
                    format!("Task {i}"),
                ))
                .unwrap(),
        );
    }
    let task_units = seal_all(
        &owner,
        objects,
        head(&objects_genesis),
        &task_changes
            .iter()
            .map(|c| framing::encode_change(c.raw_bytes()))
            .collect::<Vec<_>>(),
    );
    put_all(&mut writer, objects, &task_units, 64).await;

    let total: usize = units.iter().map(Vec::len).sum();
    let largest = units.iter().map(Vec::len).max().unwrap();
    println!(
        "sections: {} units, {total} bytes, largest {largest} bytes",
        units.len()
    );
    assert_eq!(units.len(), 401);
    // A whole import fits one DATA_PUT under the default 8 MiB message.
    assert!(total < 8 * 1024 * 1024 / 4);
    put_all(&mut writer, sections, &units, units.len()).await;

    // Stored byte for byte: the store holds the signed objects it received.
    for unit in [&units[0], &units[200], &units[400]] {
        assert_eq!(
            server
                .store
                .data_unit(unit_id(unit))
                .await
                .unwrap()
                .as_ref(),
            Some(unit)
        );
    }

    // A Snapshot of the section: an opaque signed object as well.
    let save = author.save();
    assert!(framing::decode_snapshot(&framing::encode_snapshot(&save)).is_ok());
    let snapshot = Snapshot::seal(
        SnapshotHeader {
            resource_id: sections,
            data_epoch: 0,
            publisher: owner_id,
            sequence: 1,
            control_head: head(&sections_genesis),
            frontier: Frontier::new(vec![ActorHave {
                principal: owner_id,
                contiguous: units.len() as u64,
                extra: vec![],
            }])
            .unwrap(),
        },
        &framing::encode_snapshot(&save),
        &dek(),
        &owner,
    )
    .unwrap()
    .signed_object()
    .bytes()
    .to_vec();
    let snapshot_id = ReceivedSnapshot::parse(&snapshot).unwrap().id();
    writer
        .request(Body::SnapshotPut {
            resource_id: sections,
            snapshot: snapshot.clone(),
        })
        .await;
    let reply = writer.recv().await;
    let Body::Ack(AckBody {
        request_type,
        object_ids,
        durable,
    }) = reply.body
    else {
        panic!("expected ACK, got {:?}", reply.body)
    };
    assert_eq!(request_type, SNAPSHOT_PUT);
    assert_eq!(object_ids, Some(vec![snapshot_id]));
    assert_eq!(durable, Some(true));
    assert_eq!(
        server.store.snapshot(snapshot_id).await.unwrap(),
        Some(snapshot)
    );

    // Another session reads them back in pages and replays them through
    // the SDK's section admission: the same tree as the author's.
    let mut reader = client(&server, &owner).await;
    let fetched = get_all(&mut reader, sections, owner_id, units.len() as u64).await;
    assert_eq!(fetched, units);
    let mut replica = SectionsReplica::new(sections, ActorId::from([7u8; 32]));
    for bytes in &fetched {
        let plaintext = open(bytes, &owner);
        assert_eq!(replica.receive(&owner_id, &plaintext), Received::Applied);
    }
    assert!(replica.refused().is_empty());
    assert_eq!(replica.view().effective(), author.effective());

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_is_the_clients_not_the_servers() {
    // A change above SHARED-OBJECTS-PROFILE-01 §11.1 (more than 16,384
    // values in a column) is an ordinary Data Unit to the server, which
    // stores and serves it; the receiving client refuses it before its
    // engine (SHARED-SECTIONS-PROFILE-01 §14.1).
    let dir = state_dir("sections-admission");
    let server = start(&dir, Options::default()).await;
    let owner = alice();
    let owner_id = *owner.descriptor().id();
    let resource = ResourceId::from_bytes([0x5f; 32]);
    let genesis = genesis(&owner, resource, SECTIONS);
    let mut writer = client(&server, &owner).await;
    host(&mut writer, genesis.clone()).await;

    let actor = shared_sections::actor_id(&resource, &owner_id);
    let (mut doc, first) = SectionsDoc::create(actor, SECTION, "Long", &owner_id).unwrap();
    let text = "ж".repeat(16_385);
    let long = doc
        .create_node(
            &uuid(3, 1),
            NewNode::Paragraph { text: &text },
            SECTION,
            None,
            &uuid(4, 1),
            &owner_id,
        )
        .unwrap();
    let plaintexts = [
        framing::encode_change(first.raw_bytes()),
        framing::encode_change(long.raw_bytes()),
    ];
    let units = seal_all(&owner, resource, head(&genesis), &plaintexts);
    put_all(&mut writer, resource, &units, 2).await;

    let mut reader = client(&server, &owner).await;
    let fetched = get_all(&mut reader, resource, owner_id, 2).await;
    assert_eq!(fetched, units);
    let mut replica = SectionsReplica::new(resource, ActorId::from([7u8; 32]));
    let outcomes: Vec<Received> = fetched
        .iter()
        .map(|bytes| {
            let plaintext = open(bytes, &owner);
            replica.receive(&owner_id, &plaintext)
        })
        .collect();
    assert_eq!(outcomes[0], Received::Applied);
    assert!(matches!(outcomes[1], Received::Refused(_)), "{outcomes:?}");

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_above_the_configured_maximum_is_refused_and_not_stored() {
    // WIRE-01 §31: the server's message limit applies to section units as
    // to any other; nothing of the refused message is stored.
    let dir = state_dir("sections-oversize");
    let server = start(
        &dir,
        Options {
            max_message_bytes: Some(MIN_MESSAGE_BYTES),
            ..Options::default()
        },
    )
    .await;
    let owner = alice();
    let owner_id = *owner.descriptor().id();
    let resource = ResourceId::from_bytes([0x60; 32]);
    let genesis = genesis(&owner, resource, SECTIONS);
    let mut writer = client(&server, &owner).await;
    host(&mut writer, genesis.clone()).await;

    let actor = shared_sections::actor_id(&resource, &owner_id);
    let (mut doc, first) = SectionsDoc::create(actor, SECTION, "Big", &owner_id).unwrap();
    // Random-looking text, so the change does not compress below the limit.
    let text: String = (0..40_000u32)
        .map(|i| char::from_u32(0x4e00 + (i.wrapping_mul(2_654_435_761) % 20_000)).unwrap())
        .collect();
    let big = doc
        .create_node(
            &uuid(3, 1),
            NewNode::Paragraph { text: &text },
            SECTION,
            None,
            &uuid(4, 1),
            &owner_id,
        )
        .unwrap();
    let units = seal_all(
        &owner,
        resource,
        head(&genesis),
        &[
            framing::encode_change(first.raw_bytes()),
            framing::encode_change(big.raw_bytes()),
        ],
    );
    assert!(units[1].len() > MIN_MESSAGE_BYTES, "{}", units[1].len());
    put_all(&mut writer, resource, &units[..1], 1).await;
    writer
        .request(Body::DataPut {
            resource_id: resource,
            units: vec![units[1].clone()],
        })
        .await;
    assert_eq!(code(&writer.recv().await), MESSAGE_TOO_LARGE);
    assert_eq!(
        server.store.data_unit(unit_id(&units[1])).await.unwrap(),
        None
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
