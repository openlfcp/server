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
use lfcp::base::{ObjectId, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::shared_objects::document::{NewTask, SharedObjects};
use lfcp::shared_objects::framing;
use lfcp::shared_sections::{self, NewNode, Received, SectionsDoc, SectionsReplica};
use lfcp::wire::frontier::{ActorHave, Frontier};
use lfcp::wire::message::{AckBody, Body};
use lfcp::wire::snapshot::{ReceivedSnapshot, Snapshot, SnapshotHeader};
use lfcp_server::config::MIN_MESSAGE_BYTES;
use support::lfcp::{code, start, state_dir, Client, Options, Running};
use support::sections::{
    alice, dek, genesis, get_all, head, host, open, put_all, seal_all, section_import, unit_id,
    uuid, SECTION, SECTIONS,
};

const OBJECTS: &str = "org.openlfcp.shared-objects.v1";
const MESSAGE_TOO_LARGE: u64 = 19;
const SNAPSHOT_PUT: u64 = 52;

async fn client(server: &Running, keys: &PrincipalKeys) -> Client {
    let mut client = Client::connect(server.addr).await;
    client.handshake(keys).await;
    client
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
    let (mut author, plaintexts) = section_import(sections, &owner_id, 200);
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
