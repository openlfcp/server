//! The secure ingest checks on a shared sections Resource (LFCP-02-033):
//! hosting `org.openlfcp.shared-sections.v1` changes nothing in what the
//! server checks before it stores a Data Unit.

mod support;

use lfcp::base::ResourceId;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::{CapabilityGrantBody, ControlBody};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use lfcp::wire::message::Body;
use support::lfcp::{code, start, state_dir, Client, Options};
use support::sections::{
    alice, genesis, head, host, put_all, seal_all, section_import, unit_id, SECTIONS,
};

#[tokio::test(flavor = "multi_thread")]
async fn a_section_resource_keeps_the_secure_ingest_checks() {
    // LFCP-02-033: hosting a shared sections Resource changes nothing in
    // what the server checks (WIRE-01 §51, §51.1, §62): the signer's
    // identity and authority, the signature, one unit per actor and sequence, and the
    // `previous` link. Refused units are not stored.
    const AUTHORIZATION_FAILED: u64 = 4;
    const MISSING_DEPENDENCY: u64 = 15;
    const INVALID_SIGNATURE: u64 = 7;
    const ACTOR_EQUIVOCATION: u64 = 16;
    const UNKNOWN_PREVIOUS: u64 = 23;

    let owner = alice();
    let owner_id = *owner.descriptor().id();
    let resource = ResourceId::from_bytes([0x61; 32]);
    let genesis = genesis(&owner, resource, SECTIONS);
    let (_, plaintexts) = section_import(resource, &owner_id, 3);
    let units = seal_all(&owner, resource, head(&genesis), &plaintexts);

    let dir = state_dir("sections-secure");
    // The Genesis names this URL as the coordinator, so the server takes
    // the grant's CONTROL_PUT (WIRE-01 §21).
    let server = start(
        &dir,
        Options {
            public_urls: vec!["wss://sync.example.test/v1/ws".into()],
            ..Options::default()
        },
    )
    .await;
    let mut writer = Client::connect(server.addr).await;
    writer.handshake(&owner).await;
    host(&mut writer, genesis.clone()).await;

    // A unit signed by a Principal the chain does not name: the server
    // cannot check it (MISSING_DEPENDENCY, WIRE-01 §13.1).
    let stranger = PrincipalKeys::from_secrets(&[77; 32], [78; 32]);
    let foreign = seal_all(&stranger, resource, head(&genesis), &plaintexts[..1]).remove(0);
    assert_eq!(
        put_one(&mut writer, resource, foreign.clone()).await,
        MISSING_DEPENDENCY
    );

    // A member granted data/read only (ability 1) writes: AUTHORIZATION_FAILED.
    let reader_keys = PrincipalKeys::from_secrets(&[79; 32], [80; 32]);
    let genesis_id = ReceivedControlRecord::parse(&genesis).unwrap().id();
    let grant = ControlRecord::sign(
        ControlRecordHeader {
            resource_id: resource,
            sequence: 1,
            previous: Some(genesis_id),
            issuer: owner_id,
        },
        ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: reader_keys.descriptor().clone(),
            abilities: vec![1],
            delegable: vec![],
            parent: None,
            claim_limit: None,
        }),
        &owner,
    )
    .unwrap()
    .signed_object()
    .bytes()
    .to_vec();
    writer
        .request(Body::ControlPut {
            resource_id: resource,
            expected_head: genesis_id,
            record: grant.clone(),
        })
        .await;
    let reply = writer.recv().await.body;
    assert!(matches!(reply, Body::Ack(_)), "{reply:?}");
    let read_only = seal_all(&reader_keys, resource, head(&grant), &plaintexts[..1]).remove(0);
    assert_eq!(
        put_one(&mut writer, resource, read_only.clone()).await,
        AUTHORIZATION_FAILED
    );

    // The owner's first unit with its signature altered.
    let mut tampered = units[0].clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert_eq!(
        put_one(&mut writer, resource, tampered.clone()).await,
        INVALID_SIGNATURE
    );

    // The owner's units 1-3, then another unit 2: an equivocation.
    put_all(&mut writer, resource, &units[..3], 3).await;
    let (_, other) = section_import(resource, &owner_id, 1);
    let mut rival_plaintexts = plaintexts[..1].to_vec();
    rival_plaintexts.push(other[2].clone());
    let rival = seal_all(&owner, resource, head(&genesis), &rival_plaintexts).remove(1);
    assert_ne!(unit_id(&rival), unit_id(&units[1]));
    assert_eq!(
        put_one(&mut writer, resource, rival).await,
        ACTOR_EQUIVOCATION
    );

    // Unit 5, whose `previous` (unit 4) the server never received.
    assert_eq!(
        put_one(&mut writer, resource, units[4].clone()).await,
        UNKNOWN_PREVIOUS
    );

    for unit in [&foreign, &read_only, &tampered, &units[4]] {
        assert_eq!(server.store.data_unit(unit_id(unit)).await.unwrap(), None);
    }
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The reply code to a DATA_PUT of `unit` alone.
async fn put_one(client: &mut Client, resource: ResourceId, unit: Vec<u8>) -> u64 {
    client
        .request(Body::DataPut {
            resource_id: resource,
            units: vec![unit],
        })
        .await;
    code(&client.recv().await)
}
