//! Shared sections units built with sdk-rs for the server tests
//! (LFCP-02-031, LFCP-02-032): a Resource's Genesis, a section written by
//! the SDK, its changes sealed as chained Data Units, and the client side
//! of putting, fetching and opening them.

use lfcp::base::{Hash32, PrincipalId, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::shared_objects::framing;
use lfcp::shared_sections::{self, NewNode, SectionsDoc};
use lfcp::wire::control::body::{ControlBody, Endpoint, GenesisBody};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use lfcp::wire::data_unit::{DataUnit, DataUnitHeader, ReceivedDataUnit};
use lfcp::wire::keys::Dek;
use lfcp::wire::message::{AckBody, Body, DataRange};

use super::lfcp::Client;

/// DATA_PUT, the request type its ACK names (WIRE-01 §33).
pub const DATA_PUT: u64 = 33;
pub const SECTIONS: &str = "org.openlfcp.shared-sections.v1";
pub const SECTION: &str = "019a2f85-7b31-7c42-8000-000000000001";

/// A canonical UUIDv7 for test object `n` of kind `k`.
pub fn uuid(k: u16, n: u32) -> String {
    format!("019a2f85-7b31-7c42-{:04x}-{n:012x}", 0x8000 | k)
}

pub fn alice() -> PrincipalKeys {
    PrincipalKeys::from_secrets(&[1; 32], [2; 32])
}

pub fn dek() -> Dek {
    Dek::from_bytes([9; 32])
}

/// The Genesis of `resource`, owned by `owner`, with `profile`.
pub fn genesis(owner: &PrincipalKeys, resource: ResourceId, profile: &str) -> Vec<u8> {
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
pub fn head(genesis: &[u8]) -> Hash32 {
    Hash32::from_bytes(
        *ReceivedControlRecord::parse(genesis)
            .unwrap()
            .id()
            .as_bytes(),
    )
}

/// Each plaintext as `owner`'s next Data Unit at epoch 0, chained by
/// `previous` (WIRE-01 §51.1).
pub fn seal_all(
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
pub fn open(bytes: &[u8], author: &PrincipalKeys) -> Vec<u8> {
    ReceivedDataUnit::parse(bytes)
        .unwrap()
        .verify(author.descriptor())
        .unwrap()
        .open(&dek())
        .unwrap()
}

pub fn unit_id(bytes: &[u8]) -> Hash32 {
    Hash32::from_bytes(*ReceivedDataUnit::parse(bytes).unwrap().id().as_bytes())
}

pub async fn host(client: &mut Client, genesis: Vec<u8>) {
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
pub async fn put_all(client: &mut Client, resource: ResourceId, units: &[Vec<u8>], per_put: usize) {
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
pub async fn get_all(
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

/// A section of `tasks` Tasks, each with a paragraph of about 200 characters,
/// written with sdk-rs: one change per intent (SHARED-SECTIONS-PROFILE-01
/// §11), the section ready from its first change.
pub fn section_import(
    resource: ResourceId,
    owner: &PrincipalId,
    tasks: u32,
) -> (SectionsDoc, Vec<Vec<u8>>) {
    let actor = shared_sections::actor_id(&resource, owner);
    let (mut doc, first) = SectionsDoc::create(actor, SECTION, "Joint launch", owner).unwrap();
    let mut changes = vec![first];
    let mut after: Option<String> = None;
    for i in 1..=tasks {
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
