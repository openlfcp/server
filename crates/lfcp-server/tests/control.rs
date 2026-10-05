//! The Control Coordinator over real TCP WebSocket connections (LFCP-049):
//! CONTROL_PUT compare-and-swap with LFCP-TEST-VECTORS-01, its failure
//! codes, races, one-time claims, restart, CONTROL_HAVE / GET / BATCH and
//! live pushes.

mod support;

use std::sync::Arc;

use lfcp::base::{ControlRecordId, Hash32, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::{
    CapabilityClaimBody, CapabilityGrantBody, ControlBody, ResourceTombstoneBody,
};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use lfcp::wire::message::{AckBody, Body, ControlHead, Message};
use support::lfcp::{code, start, state_dir, Client, Options, Script};
use support::vectors::Vectors;

const MALFORMED_MESSAGE: u64 = 2;
const AUTHORIZATION_FAILED: u64 = 4;
const RESOURCE_NOT_HOSTED: u64 = 6;
const INVALID_SIGNATURE: u64 = 7;
const INVALID_CONTROL_CHAIN: u64 = 8;
const CONTROL_HEAD_MISMATCH: u64 = 10;
const NOT_CONTROL_COORDINATOR: u64 = 11;
const PROTOCOL_UNSUPPORTED: u64 = 1;
const MISSING_DEPENDENCY: u64 = 15;

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

/// The coordinator C5 moves the Resource to.
fn sync_b(v: &Vectors) -> String {
    match ReceivedControlRecord::parse(&v.cose("C5_route_update"))
        .unwrap()
        .body()
    {
        ControlBody::RouteUpdate(route) => route.coordinator.clone(),
        other => panic!("C5 is a Route Update, got {other:?}"),
    }
}

fn options(urls: Vec<String>, random: Arc<Script>) -> Options {
    Options {
        random,
        public_urls: urls,
        ..Options::default()
    }
}

fn both(v: &Vectors) -> Vec<String> {
    vec![SYNC_A.into(), sync_b(v)]
}

fn put(v: &Vectors, expected: ControlRecordId, record: Vec<u8>) -> Body {
    Body::ControlPut {
        resource_id: v.resource(),
        expected_head: expected,
        record,
    }
}

fn open(v: &Vectors, flags: u64) -> Body {
    Body::ResourceOpen {
        resource_id: v.resource(),
        control_heads: vec![],
        have: vec![],
        grant_ids: None,
        flags: Some(flags),
    }
}

fn ack_of(id: ControlRecordId) -> Body {
    Body::Ack(AckBody {
        request_type: 23,
        object_ids: Some(vec![Hash32::from_bytes(*id.as_bytes())]),
        durable: Some(true),
    })
}

/// A client authenticated as `keys` that hosted C0.
async fn owner_client(v: &Vectors, addr: std::net::SocketAddr) -> Client {
    let mut client = Client::connect(addr).await;
    client.handshake(&v.principal("owner")).await;
    client
        .request(Body::ResourceHost {
            genesis: v.cose("C0_genesis"),
            hosting_credential: None,
        })
        .await;
    assert!(matches!(
        client.recv().await.body,
        Body::ResourceHosted { .. }
    ));
    client
}

/// Commit `CHAIN[1..=last]` through CONTROL_PUT, checking every ACK.
async fn commit_through(v: &Vectors, client: &mut Client, last: usize) {
    for i in 1..=last {
        let id = client
            .request(put(v, v.record_id(CHAIN[i - 1]), v.cose(CHAIN[i])))
            .await;
        let ack = client.recv().await;
        assert_eq!(ack.correlation_id, Some(id), "{}", CHAIN[i]);
        assert_eq!(ack.body, ack_of(v.record_id(CHAIN[i])), "{}", CHAIN[i]);
    }
}

/// The current head through CONTROL_HAVE.
async fn heads(v: &Vectors, client: &mut Client) -> Vec<ControlHead> {
    client
        .request(Body::ControlHave {
            resource_id: v.resource(),
            control_heads: vec![],
        })
        .await;
    match client.recv().await.body {
        Body::ControlHave { control_heads, .. } => control_heads,
        other => panic!("expected CONTROL_HAVE, got {other:?}"),
    }
}

fn head(v: &Vectors, name: &str, sequence: u64) -> ControlHead {
    ControlHead {
        sequence,
        id: v.record_id(name),
    }
}

/// Sign a record for the published Resource.
fn sign(
    v: &Vectors,
    signer: &PrincipalKeys,
    sequence: u64,
    previous: ControlRecordId,
    body: ControlBody,
) -> Vec<u8> {
    let header = ControlRecordHeader {
        resource_id: v.resource(),
        sequence,
        previous: Some(previous),
        issuer: *signer.descriptor().id(),
    };
    ControlRecord::sign(header, body, signer)
        .unwrap()
        .signed_object()
        .bytes()
        .to_vec()
}

fn grant_to(subject: &PrincipalKeys) -> ControlBody {
    ControlBody::CapabilityGrant(CapabilityGrantBody {
        subject: subject.descriptor().clone(),
        abilities: vec![1],
        delegable: vec![],
        parent: None,
        claim_limit: None,
    })
}

fn record_id(bytes: &[u8]) -> ControlRecordId {
    ReceivedControlRecord::parse(bytes).unwrap().id()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_published_chain_commits_through_control_put() {
    let v = Vectors::load();
    let dir = state_dir("control-chain");
    let script = Arc::new(Script::default());
    let server = start(&dir, options(both(&v), script.clone())).await;
    let mut client = owner_client(&v, server.addr).await;

    commit_through(&v, &mut client, 10).await;
    assert_eq!(
        heads(&v, &mut client).await,
        vec![head(&v, "C10_revoke_grandchild", 10)]
    );

    // Exact bytes are retained.
    let stored = server
        .store
        .control_records(v.resource(), 0, 10)
        .await
        .unwrap();
    let stored: Vec<Vec<u8>> = stored.into_iter().map(|r| r.bytes).collect();
    let published: Vec<Vec<u8>> = CHAIN.iter().map(|c| v.cose(c)).collect();
    assert_eq!(stored, published);

    // At-least-once delivery: a repeated put of a committed record, the
    // head or an older one, gets the same ACK and changes nothing.
    for (name, expected) in [
        ("C10_revoke_grandchild", "C9_grant_invite_grandchild"),
        ("C5_route_update", "C4_owner_transfer_commit"),
    ] {
        client
            .request(put(&v, v.record_id(expected), v.cose(name)))
            .await;
        assert_eq!(client.recv().await.body, ack_of(v.record_id(name)));
    }

    // CONTROL_GET 0..=6 answered with the published CONTROL_BATCH, byte
    // for byte (its message ID injected).
    let batch = v.message("CONTROL_BATCH");
    script.push(
        Message::decode(&batch, &Default::default())
            .unwrap()
            .message_id,
    );
    client.send_bytes(v.message("CONTROL_GET")).await;
    assert_eq!(client.recv_bytes().await, batch);

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_expected_head_gets_the_published_nack() {
    let v = Vectors::load();
    let dir = state_dir("control-stale");
    let script = Arc::new(Script::default());
    let server = start(&dir, options(both(&v), script.clone())).await;
    let mut client = owner_client(&v, server.addr).await;
    commit_through(&v, &mut client, 5).await;

    // C6 with expected head C4 while the head is C5: NACK carrying C5.
    let nack = v.message("NACK_CONTROL_HEAD_MISMATCH");
    script.push(
        Message::decode(&nack, &Default::default())
            .unwrap()
            .message_id,
    );
    client
        .send_bytes(v.hex("stale_control_head_put", "inputs", "message_cbor"))
        .await;
    assert_eq!(client.recv_bytes().await, nack);
    assert_eq!(
        v.expected_code("stale_control_head_put"),
        Some(CONTROL_HEAD_MISMATCH)
    );

    // The published CONTROL_PUT (C6 on C5) then commits.
    client.send_bytes(v.message("CONTROL_PUT")).await;
    assert_eq!(
        client.recv().await.body,
        ack_of(v.record_id("C6_key_epoch_1"))
    );

    // A null expected head does not decode (G-MSG5); the session goes on.
    client
        .send_bytes(v.hex("control_put_null_expected_head", "inputs", "message_cbor"))
        .await;
    let error = client.recv().await;
    assert!(matches!(error.body, Body::Error(_)));
    assert_eq!(code(&error), MALFORMED_MESSAGE);
    // OWNER lost its authority at C4 (§23.3); BOB, the owner now, reads.
    let mut bob = Client::connect(server.addr).await;
    bob.handshake(&v.principal("bob")).await;
    assert_eq!(
        heads(&v, &mut bob).await,
        vec![head(&v, "C6_key_epoch_1", 6)]
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_records_are_refused_with_their_codes() {
    let v = Vectors::load();
    let dir = state_dir("control-invalid");
    let server = start(&dir, options(both(&v), Arc::default())).await;
    let mut client = owner_client(&v, server.addr).await;
    let owner = v.principal("owner");
    let c0 = v.record_id("C0_genesis");

    let mut refuse = Vec::new();
    // W1: an unknown core type.
    refuse.push((
        "unknown core type",
        c0,
        v.negative("unknown_core_type_C1"),
        v.expected_code("unknown_core_type_C1").unwrap(),
    ));
    // Genesis uses RESOURCE_HOST.
    refuse.push(("Genesis", c0, v.cose("C0_genesis"), MALFORMED_MESSAGE));
    // Sequence: 2 on head 0.
    refuse.push((
        "sequence gap",
        c0,
        sign(&v, &owner, 2, c0, grant_to(&v.principal("bob"))),
        INVALID_CONTROL_CHAIN,
    ));
    // A signature that does not verify.
    let mut tampered = v.cose("C1_grant_bob");
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    refuse.push(("bad signature", c0, tampered, INVALID_SIGNATURE));
    // DV1: a Resource Tombstone is not applied in MVP.
    refuse.push((
        "tombstone",
        c0,
        sign(
            &v,
            &owner,
            1,
            c0,
            ControlBody::ResourceTombstone(ResourceTombstoneBody {
                reason: 0,
                note: None,
            }),
        ),
        PROTOCOL_UNSUPPORTED,
    ));
    // An issuer the chain does not know yet (BOB at C0, §13.1).
    let bob = v.principal("bob");
    refuse.push((
        "unknown issuer",
        c0,
        sign(&v, &bob, 1, c0, grant_to(&v.principal("carol"))),
        MISSING_DEPENDENCY,
    ));
    for (why, expected, record, wanted) in refuse {
        let id = client.request(put(&v, expected, record)).await;
        let nack = client.recv().await;
        assert!(matches!(nack.body, Body::Nack(_)), "{why}");
        assert_eq!(code(&nack), wanted, "{why}");
        assert_eq!(nack.correlation_id, Some(id), "{why}");
    }
    assert_eq!(
        heads(&v, &mut client).await,
        vec![head(&v, "C0_genesis", 0)]
    );

    // A grant by a known Principal without capability/grant (BOB holds
    // only data/read after C1).
    commit_through(&v, &mut client, 1).await;
    let c1 = v.record_id("C1_grant_bob");
    client
        .request(put(
            &v,
            c1,
            sign(&v, &bob, 2, c1, grant_to(&v.principal("carol"))),
        ))
        .await;
    assert_eq!(code(&client.recv().await), AUTHORIZATION_FAILED);

    // Previous: the right sequence on another record.
    let wrong_previous = sign(&v, &owner, 2, c0, grant_to(&v.principal("carol")));
    client
        .request(put(&v, v.record_id("C1_grant_bob"), wrong_previous))
        .await;
    assert_eq!(code(&client.recv().await), INVALID_CONTROL_CHAIN);

    // §17.2 escalation (C9 granting what C8 cannot delegate) and §17.3
    // revoking a revoked grant.
    commit_through(&v, &mut client, 8).await;
    client
        .request(put(
            &v,
            v.record_id("C8_grant_owner_delegated"),
            v.negative("grant_escalation_C9"),
        ))
        .await;
    assert_eq!(code(&client.recv().await), AUTHORIZATION_FAILED);
    commit_through(&v, &mut client, 10).await;
    client
        .request(put(
            &v,
            v.record_id("C10_revoke_grandchild"),
            v.negative("revoke_already_revoked"),
        ))
        .await;
    assert_eq!(
        Some(code(&client.recv().await)),
        v.expected_code("revoke_already_revoked")
    );
    assert_eq!(
        heads(&v, &mut client).await,
        vec![head(&v, "C10_revoke_grandchild", 10)]
    );

    // A Resource that is not hosted.
    client
        .request(Body::ControlPut {
            resource_id: ResourceId::from_bytes([0xcd; 32]),
            expected_head: c0,
            record: v.cose("C1_grant_bob"),
        })
        .await;
    assert_eq!(code(&client.recv().await), RESOURCE_NOT_HOSTED);

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_current_coordinator_accepts_control_put() {
    let v = Vectors::load();
    let dir = state_dir("control-coordinator");

    // Not configured as any coordinator: C1 is refused, naming sync-a.
    let server = start(&dir, options(vec![], Arc::default())).await;
    let mut client = owner_client(&v, server.addr).await;
    client
        .request(put(&v, v.record_id("C0_genesis"), v.cose("C1_grant_bob")))
        .await;
    let nack = client.recv().await;
    assert_eq!(code(&nack), NOT_CONTROL_COORDINATOR);
    let Body::Nack(body) = &nack.body else {
        unreachable!()
    };
    assert_eq!(body.details, Some(lfcp::cbor::Value::text(SYNC_A)));
    server.stop().await;

    // As sync-a (spelled differently: case and default port): C1–C5
    // commit; C5 moves the coordinator to sync-b, so C6 is refused.
    let urls = vec!["WSS://Sync-A.example.test:443/v1/ws".to_owned()];
    let server = start(&dir, options(urls, Arc::default())).await;
    let mut client = Client::connect(server.addr).await;
    client.handshake(&v.principal("owner")).await;
    commit_through(&v, &mut client, 5).await;
    client
        .request(put(
            &v,
            v.record_id("C5_route_update"),
            v.cose("C6_key_epoch_1"),
        ))
        .await;
    let nack = client.recv().await;
    assert_eq!(code(&nack), NOT_CONTROL_COORDINATOR);
    let Body::Nack(body) = &nack.body else {
        unreachable!()
    };
    assert_eq!(body.details, Some(lfcp::cbor::Value::text(sync_b(&v))));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn racing_puts_from_one_head_commit_exactly_once() {
    let v = Vectors::load();
    let dir = state_dir("control-race");
    let server = start(&dir, options(both(&v), Arc::default())).await;
    let mut owner = owner_client(&v, server.addr).await;
    owner.request(open(&v, 0)).await;
    owner.recv().await;

    // Eight connections, eight different grants, all on C0.
    let c0 = v.record_id("C0_genesis");
    let owner_keys = v.principal("owner");
    let mut clients = Vec::new();
    let mut records = Vec::new();
    for n in 0..8u8 {
        let mut client = Client::connect(server.addr).await;
        client.handshake(&owner_keys).await;
        let subject = PrincipalKeys::from_secrets(&[n + 40; 32], [n + 80; 32]);
        records.push(sign(&v, &owner_keys, 1, c0, grant_to(&subject)));
        clients.push(client);
    }
    let replies = futures_util::future::join_all(clients.iter_mut().zip(records.iter()).map(
        |(client, record)| async {
            client.request(put(&v, c0, record.clone())).await;
            client.recv().await
        },
    ))
    .await;
    let winners: Vec<usize> = (0..8)
        .filter(|&i| matches!(replies[i].body, Body::Ack(_)))
        .collect();
    assert_eq!(winners.len(), 1, "exactly one commit");
    let winner = record_id(&records[winners[0]]);
    for (i, reply) in replies.iter().enumerate() {
        if i == winners[0] {
            assert_eq!(reply.body, ack_of(winner));
            continue;
        }
        // Deterministic failure: the head moved, and the NACK names it.
        assert_eq!(code(reply), CONTROL_HEAD_MISMATCH);
        let Body::Nack(body) = &reply.body else {
            unreachable!()
        };
        assert_eq!(
            body.details,
            Some(lfcp::cbor::Value::bytes(winner.as_bytes().to_vec()))
        );
    }
    assert_eq!(
        heads(&v, &mut owner).await,
        vec![ControlHead {
            sequence: 1,
            id: winner
        }]
    );
    // The losing proposals were not stored as fork evidence.
    let at1 = server
        .store
        .control_records(v.resource(), 1, 1)
        .await
        .unwrap();
    assert_eq!(at1.len(), 1);

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_one_time_invitation_is_claimed_once() {
    let v = Vectors::load();
    let dir = state_dir("control-claim");
    let server = start(&dir, options(both(&v), Arc::default())).await;
    let mut owner = owner_client(&v, server.addr).await;
    commit_through(&v, &mut owner, 2).await;

    // Two claims of the C2 invitation (claim_limit 1), both on C2: CAROL's
    // published C3 and one for BOB, signed by the Invitation Principal.
    let invite = v.principal("invite");
    let c2 = v.record_id("C2_invite_grant");
    let abilities = match ReceivedControlRecord::parse(&v.cose("C3_invite_claim_carol"))
        .unwrap()
        .body()
    {
        ControlBody::CapabilityClaim(claim) => claim.abilities.clone(),
        other => panic!("C3 is a claim, got {other:?}"),
    };
    let claim_for = |claimant: &PrincipalKeys, sequence: u64, previous: ControlRecordId| {
        sign(
            &v,
            &invite,
            sequence,
            previous,
            ControlBody::CapabilityClaim(CapabilityClaimBody {
                invitation_grant: c2,
                claimant: claimant.descriptor().clone(),
                abilities: abilities.clone(),
            }),
        )
    };
    let carol_claim = v.cose("C3_invite_claim_carol");
    let bob_claim = claim_for(&v.principal("bob"), 3, c2);

    let mut a = Client::connect(server.addr).await;
    a.handshake(&invite).await;
    let mut b = Client::connect(server.addr).await;
    b.handshake(&invite).await;
    let (ra, rb) = tokio::join!(
        async {
            a.request(put(&v, c2, carol_claim.clone())).await;
            a.recv().await
        },
        async {
            b.request(put(&v, c2, bob_claim.clone())).await;
            b.recv().await
        }
    );
    let (winner, loser, loser_client, loser_keys) = match (&ra.body, &rb.body) {
        (Body::Ack(_), Body::Nack(_)) => (&carol_claim, rb, &mut b, v.principal("bob")),
        (Body::Nack(_), Body::Ack(_)) => (&bob_claim, ra, &mut a, v.principal("carol")),
        other => panic!("exactly one claim must commit: {other:?}"),
    };
    // The loser lost the compare-and-swap…
    assert_eq!(code(&loser), CONTROL_HEAD_MISMATCH);
    // …and after refreshing, the invitation is used up.
    let retry = claim_for(&loser_keys, 4, record_id(winner));
    loser_client
        .request(put(&v, record_id(winner), retry))
        .await;
    assert_eq!(code(&loser_client.recv().await), AUTHORIZATION_FAILED);
    assert_eq!(
        heads(&v, &mut owner).await,
        vec![ControlHead {
            sequence: 3,
            id: record_id(winner)
        }]
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_head_survives_a_restart() {
    let v = Vectors::load();
    let dir = state_dir("control-restart");
    let server = start(&dir, options(both(&v), Arc::default())).await;
    let mut client = owner_client(&v, server.addr).await;
    commit_through(&v, &mut client, 3).await;
    server.stop().await;

    let server = start(&dir, options(both(&v), Arc::default())).await;
    let mut client = Client::connect(server.addr).await;
    client.handshake(&v.principal("owner")).await;
    assert_eq!(
        heads(&v, &mut client).await,
        vec![head(&v, "C3_invite_claim_carol", 3)]
    );
    // The next put compares against the restored head.
    client
        .request(put(
            &v,
            v.record_id("C2_invite_grant"),
            v.cose("C4_owner_transfer_commit"),
        ))
        .await;
    let nack = client.recv().await;
    assert_eq!(code(&nack), CONTROL_HEAD_MISMATCH);
    client
        .request(put(
            &v,
            v.record_id("C3_invite_claim_carol"),
            v.cose("C4_owner_transfer_commit"),
        ))
        .await;
    assert_eq!(
        client.recv().await.body,
        ack_of(v.record_id("C4_owner_transfer_commit"))
    );
    // BOB is the owner after C4.
    let mut bob = Client::connect(server.addr).await;
    bob.handshake(&v.principal("bob")).await;
    bob.request(open(&v, 0)).await;
    let Body::ResourceOpened { control_heads, .. } = bob.recv().await.body else {
        panic!("expected RESOURCE_OPENED")
    };
    assert_eq!(control_heads, vec![head(&v, "C4_owner_transfer_commit", 4)]);

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn commits_are_pushed_to_live_control_subscribers() {
    let v = Vectors::load();
    let dir = state_dir("control-push");
    let server = start(&dir, options(both(&v), Arc::default())).await;
    let mut writer = owner_client(&v, server.addr).await;
    writer.request(open(&v, 0b010)).await;
    writer.recv().await;

    let mut live = Client::connect(server.addr).await;
    live.handshake(&v.principal("owner")).await;
    live.request(open(&v, 0b010)).await;
    live.recv().await;
    let mut data_only = Client::connect(server.addr).await;
    data_only.handshake(&v.principal("owner")).await;
    data_only.request(open(&v, 0b001)).await;
    data_only.recv().await;

    commit_through(&v, &mut writer, 1).await;
    // The live subscriber receives the exact record.
    let push = live.recv().await;
    assert_eq!(push.correlation_id, None);
    assert_eq!(
        push.body,
        Body::ControlBatch {
            resource_id: v.resource(),
            records: vec![v.cose("C1_grant_bob")],
        }
    );
    // The writer got only its ACK, and the data-only subscriber nothing:
    // their next message is the PONG to a PING.
    for client in [&mut writer, &mut data_only] {
        client.request(Body::Ping([3; 8])).await;
        assert_eq!(client.recv().await.body, Body::Pong([3; 8]));
    }

    // After RESOURCE_CLOSE, no more pushes.
    live.request(Body::ResourceClose {
        resource_id: v.resource(),
    })
    .await;
    assert!(matches!(live.recv().await.body, Body::Ack(_)));
    commit_through(&v, &mut writer, 2).await;
    live.request(Body::Ping([4; 8])).await;
    assert_eq!(live.recv().await.body, Body::Pong([4; 8]));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn control_reads_need_read_authority_and_return_every_record() {
    let v = Vectors::load();
    let dir = state_dir("control-read");
    let server = start(&dir, options(both(&v), Arc::default())).await;
    let mut owner = owner_client(&v, server.addr).await;
    commit_through(&v, &mut owner, 10).await;
    // A competing C6 stored as evidence (from a peer, not a put).
    let fork = v.negative("control_fork_C6");
    server.store.put_control_record(fork.clone()).await.unwrap();

    // CAROL holds data/read after her claim (C3): she sees both heads and
    // every record at sequence 6.
    let mut carol = Client::connect(server.addr).await;
    carol.handshake(&v.principal("carol")).await;
    let fork_id = record_id(&fork);
    assert_eq!(
        heads(&v, &mut carol).await,
        vec![
            ControlHead {
                sequence: 6,
                id: fork_id
            },
            head(&v, "C10_revoke_grandchild", 10)
        ]
    );
    let id = carol
        .request(Body::ControlGet {
            resource_id: v.resource(),
            start: 5,
            end: 7,
        })
        .await;
    let batch = carol.recv().await;
    assert_eq!(batch.correlation_id, Some(id));
    let Body::ControlBatch { records, .. } = batch.body else {
        panic!("expected CONTROL_BATCH")
    };
    let mut at6 = vec![v.cose("C6_key_epoch_1"), fork];
    at6.sort_by_key(|r| *record_id(r).as_bytes());
    assert_eq!(
        records,
        [
            vec![v.cose("C5_route_update")],
            at6,
            vec![v.cose("C7_grant_carol_delegator")]
        ]
        .concat()
    );
    // A reversed range is malformed.
    carol
        .request(Body::ControlGet {
            resource_id: v.resource(),
            start: 7,
            end: 5,
        })
        .await;
    assert_eq!(code(&carol.recv().await), MALFORMED_MESSAGE);

    // A Principal with no ability reads nothing.
    let stranger = PrincipalKeys::from_secrets(&[99; 32], [98; 32]);
    let mut outsider = Client::connect(server.addr).await;
    outsider.handshake(&stranger).await;
    outsider
        .request(Body::ControlGet {
            resource_id: v.resource(),
            start: 0,
            end: 10,
        })
        .await;
    assert_eq!(code(&outsider.recv().await), AUTHORIZATION_FAILED);

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
