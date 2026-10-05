//! Durability steps shared by the process and container restart checks
//! (LFCP-054, LFCP-055): populate a server over the protocol, then verify
//! after a restart that it kept every acknowledged object.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use lfcp::base::{ControlRecordId, Hash32};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::{CapabilityClaimBody, CapabilityGrantBody, ControlBody};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use lfcp::wire::key_package::{KeyPackage, ReceivedKeyPackage};
use lfcp::wire::keys::Dek;
use lfcp::wire::message::{Body, DataRange};

use super::lfcp::Client;
use super::vectors::{Vectors, CHAIN};

const AUTHORIZATION_FAILED: u64 = 4;
const CONTROL_HEAD_MISMATCH: u64 = 10;
const ACTOR_EQUIVOCATION: u64 = 16;

pub async fn session(addr: SocketAddr, keys: &PrincipalKeys) -> (Client, [u8; 32]) {
    let mut client = Client::connect(addr).await;
    let (challenge, _) = client.handshake(keys).await;
    let Body::Challenge(challenge) = challenge.body else {
        unreachable!()
    };
    (client, challenge.server_id)
}

async fn request(client: &mut Client, body: Body) -> Body {
    let id = client.request(body).await;
    let reply = client.recv().await;
    assert_eq!(reply.correlation_id, Some(id));
    reply.body
}

fn nack_code(body: &Body) -> u64 {
    match body {
        Body::Nack(e) => e.code,
        other => panic!("expected NACK, got {other:?}"),
    }
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

pub const UNITS: [&str; 3] = [
    "D1_bob_epoch0_seq1",
    "D2_bob_epoch0_seq2",
    "D4_carol_epoch1_seq1",
];
pub const SNAPSHOTS: [&str; 2] = ["SNAPSHOT-01", "SNAPSHOT-02"];

/// A second valid package for (epoch 0, BOB), from OWNER at C1. Sealing
/// is randomized (HPKE), so each test seals it once.
pub fn second_package(v: &Vectors) -> Vec<u8> {
    KeyPackage::seal(
        v.resource(),
        0,
        Hash32::from_bytes(*v.record_id("C1_grant_bob").as_bytes()),
        &Dek::from_bytes([4; 32]),
        v.principal("bob").descriptor(),
        &v.principal("owner"),
    )
    .unwrap()
    .signed_object()
    .bytes()
    .to_vec()
}

/// Host C0, commit C1–C10 through CONTROL_PUT, put D1, D2, D4, four Key
/// Packages and both Snapshots. Every put must be ACKed.
pub async fn populate(v: &Vectors, addr: SocketAddr, second: &[u8]) -> [u8; 32] {
    let (mut bob, server_id) = session(addr, &v.principal("bob")).await;
    let hosted = request(
        &mut bob,
        Body::ResourceHost {
            genesis: v.cose("C0_genesis"),
            hosting_credential: None,
        },
    )
    .await;
    assert!(matches!(hosted, Body::ResourceHosted { durability: 2, .. }));
    for i in 1..CHAIN.len() {
        let reply = request(
            &mut bob,
            Body::ControlPut {
                resource_id: v.resource(),
                expected_head: v.record_id(CHAIN[i - 1]),
                record: v.cose(CHAIN[i]),
            },
        )
        .await;
        assert!(matches!(reply, Body::Ack(_)), "{}: {reply:?}", CHAIN[i]);
    }
    let reply = request(
        &mut bob,
        Body::DataPut {
            resource_id: v.resource(),
            units: UNITS.iter().map(|u| v.cose(u)).collect(),
        },
    )
    .await;
    assert!(matches!(reply, Body::Ack(_)), "{reply:?}");
    let mut packages: Vec<Vec<u8>> = ["KP0_bob_epoch0", "KPI_invite_epoch0", "KPC_carol_epoch1"]
        .iter()
        .map(|p| v.cose(p))
        .collect();
    packages.push(second.to_vec());
    let reply = request(
        &mut bob,
        Body::KeyPackagePut {
            resource_id: v.resource(),
            packages,
        },
    )
    .await;
    assert!(matches!(reply, Body::Ack(_)), "{reply:?}");
    for snapshot in SNAPSHOTS {
        let reply = request(
            &mut bob,
            Body::SnapshotPut {
                resource_id: v.resource(),
                snapshot: v.cose(snapshot),
            },
        )
        .await;
        assert!(matches!(reply, Body::Ack(_)), "{reply:?}");
    }
    server_id
}

/// Everything the restarted server must show, over the protocol.
pub async fn verify_after_restart(
    v: &Vectors,
    addr: SocketAddr,
    server_id: [u8; 32],
    second: &[u8],
) {
    let bob_keys = v.principal("bob");
    let (mut bob, id) = session(addr, &bob_keys).await;
    assert_eq!(id, server_id, "the server ID survives");

    // The Resource and its Control Head.
    let opened = request(
        &mut bob,
        Body::ResourceOpen {
            resource_id: v.resource(),
            control_heads: vec![],
            have: vec![],
            grant_ids: None,
            flags: Some(0),
        },
    )
    .await;
    let Body::ResourceOpened { control_heads, .. } = opened else {
        panic!("expected RESOURCE_OPENED, got {opened:?}")
    };
    assert_eq!(control_heads.len(), 1);
    assert_eq!(control_heads[0].id, v.record_id("C10_revoke_grandchild"));
    assert_eq!(control_heads[0].sequence, 10);

    // Every committed Control Record, exact bytes.
    let batch = request(
        &mut bob,
        Body::ControlGet {
            resource_id: v.resource(),
            start: 0,
            end: 10,
        },
    )
    .await;
    let Body::ControlBatch { records, .. } = batch else {
        panic!("expected CONTROL_BATCH")
    };
    let published: Vec<Vec<u8>> = CHAIN.iter().map(|c| v.cose(c)).collect();
    assert_eq!(records, published);

    // A stale expected head is still stale.
    let stranger = PrincipalKeys::from_secrets(&[71; 32], [72; 32]);
    let late = sign(
        v,
        &bob_keys,
        10,
        v.record_id("C9_grant_invite_grandchild"),
        ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: stranger.descriptor().clone(),
            abilities: vec![1],
            delegable: vec![],
            parent: None,
            claim_limit: None,
        }),
    );
    let reply = request(
        &mut bob,
        Body::ControlPut {
            resource_id: v.resource(),
            expected_head: v.record_id("C9_grant_invite_grandchild"),
            record: late,
        },
    )
    .await;
    assert_eq!(nack_code(&reply), CONTROL_HEAD_MISMATCH);

    // The one-time invitation (C2) stays consumed by C3.
    let abilities = match ReceivedControlRecord::parse(&v.cose("C3_invite_claim_carol"))
        .unwrap()
        .body()
    {
        ControlBody::CapabilityClaim(c) => c.abilities.clone(),
        other => panic!("{other:?}"),
    };
    let second_claim = sign(
        v,
        &v.principal("invite"),
        11,
        v.record_id("C10_revoke_grandchild"),
        ControlBody::CapabilityClaim(CapabilityClaimBody {
            invitation_grant: v.record_id("C2_invite_grant"),
            claimant: stranger.descriptor().clone(),
            abilities,
        }),
    );
    let reply = request(
        &mut bob,
        Body::ControlPut {
            resource_id: v.resource(),
            expected_head: v.record_id("C10_revoke_grandchild"),
            record: second_claim,
        },
    )
    .await;
    assert_eq!(
        nack_code(&reply),
        AUTHORIZATION_FAILED,
        "claim still used up"
    );

    // Data catch-up from nothing delivers every committed unit, once.
    let have = request(
        &mut bob,
        Body::DataHave {
            resource_id: v.resource(),
            have: vec![],
        },
    )
    .await;
    let Body::DataHave { have, .. } = have else {
        panic!("expected DATA_HAVE")
    };
    let ranges: Vec<DataRange> = have
        .iter()
        .map(|h| DataRange {
            principal: h.principal,
            start: 1,
            end: h.contiguous,
        })
        .collect();
    let batch = request(
        &mut bob,
        Body::DataGet {
            resource_id: v.resource(),
            ranges,
        },
    )
    .await;
    let Body::DataBatch { units, .. } = batch else {
        panic!("expected DATA_BATCH")
    };
    let got: BTreeSet<Vec<u8>> = units.into_iter().collect();
    let want: BTreeSet<Vec<u8>> = UNITS.iter().map(|u| v.cose(u)).collect();
    assert_eq!(got, want);

    // Key Packages: both of (0, BOB) for BOB; KPC for CAROL.
    let batch = request(
        &mut bob,
        Body::KeyPackageGet {
            resource_id: v.resource(),
            recipient: *bob_keys.descriptor().id(),
            epochs: vec![0],
        },
    )
    .await;
    let Body::KeyPackageBatch { packages, .. } = batch else {
        panic!("expected KEY_PACKAGE_BATCH")
    };
    let ids: BTreeSet<[u8; 32]> = packages
        .iter()
        .map(|p| *ReceivedKeyPackage::parse(p).unwrap().id().as_bytes())
        .collect();
    let want: BTreeSet<[u8; 32]> = [v.cose("KP0_bob_epoch0"), second.to_vec()]
        .iter()
        .map(|p| *ReceivedKeyPackage::parse(p).unwrap().id().as_bytes())
        .collect();
    assert_eq!(ids, want);
    let (mut carol, _) = session(addr, &v.principal("carol")).await;
    let batch = request(
        &mut carol,
        Body::KeyPackageGet {
            resource_id: v.resource(),
            recipient: *v.principal("carol").descriptor().id(),
            epochs: vec![1],
        },
    )
    .await;
    assert_eq!(
        batch,
        Body::KeyPackageBatch {
            resource_id: v.resource(),
            packages: vec![v.cose("KPC_carol_epoch1")],
        }
    );

    // Snapshots by exact ID.
    for snapshot in SNAPSHOTS {
        let wanted = Hash32::from_bytes(
            v.hex(snapshot, "expected", "snapshot_id")
                .try_into()
                .unwrap(),
        );
        let reply = request(
            &mut bob,
            Body::SnapshotGet {
                resource_id: v.resource(),
                snapshot_id: Some(wanted),
            },
        )
        .await;
        assert_eq!(
            reply,
            Body::Snapshot {
                resource_id: v.resource(),
                snapshot: v.cose(snapshot),
            }
        );
    }

    // Dedup and equivocation indexes.
    let replay = request(
        &mut bob,
        Body::DataPut {
            resource_id: v.resource(),
            units: UNITS.iter().map(|u| v.cose(u)).collect(),
        },
    )
    .await;
    assert!(matches!(replay, Body::Ack(_)), "{replay:?}");
    let conflicting = v.hex("actor_equivocation", "inputs", "conflicting_D2_cose");
    let reply = request(
        &mut bob,
        Body::DataPut {
            resource_id: v.resource(),
            units: vec![conflicting],
        },
    )
    .await;
    assert_eq!(nack_code(&reply), ACTOR_EQUIVOCATION);
}
