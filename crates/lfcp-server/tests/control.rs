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

    // §20: a Route Update that does not advance the route version
    // (baseline.4: AUTHORIZATION_FAILED).
    commit_through(&v, &mut client, 4).await;
    client
        .request(put(
            &v,
            v.record_id("C4_owner_transfer_commit"),
            v.negative("route_version_not_increasing_C5"),
        ))
        .await;
    assert_eq!(
        Some(code(&client.recv().await)),
        v.expected_code("route_version_not_increasing_C5")
    );

    // §17.2 escalation (C9 granting what C8 cannot delegate) and §17.3
    // revoking a revoked grant or one that does not exist.
    commit_through(&v, &mut client, 8).await;
    client
        .request(put(
            &v,
            v.record_id("C8_grant_owner_delegated"),
            v.negative("grant_escalation_C9"),
        ))
        .await;
    assert_eq!(code(&client.recv().await), AUTHORIZATION_FAILED);
    commit_through(&v, &mut client, 9).await;
    client
        .request(put(
            &v,
            v.record_id("C9_grant_invite_grandchild"),
            v.negative("revoke_unknown_grant"),
        ))
        .await;
    assert_eq!(
        Some(code(&client.recv().await)),
        v.expected_code("revoke_unknown_grant")
    );
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
async fn an_active_invitation_subject_may_open_the_resource() {
    // §41, §84: read authority is data/read, or being the subject of an
    // active invitation grant, at the accepted Control Head.
    let v = Vectors::load();
    let dir = state_dir("control-invite-open");
    let server = start(&dir, options(both(&v), Arc::default())).await;
    let mut owner = owner_client(&v, server.addr).await;
    commit_through(&v, &mut owner, 2).await;
    let opened = |reply: &Message| matches!(reply.body, Body::ResourceOpened { .. });

    // At C2 the Invitation Principal opens; CAROL, not yet a member, not.
    let mut invite = Client::connect(server.addr).await;
    invite.handshake(&v.principal("invite")).await;
    invite.request(open(&v, 0)).await;
    assert!(opened(&invite.recv().await), "the invitation subject opens");
    let mut carol = Client::connect(server.addr).await;
    carol.handshake(&v.principal("carol")).await;
    carol.request(open(&v, 0)).await;
    assert_eq!(code(&carol.recv().await), AUTHORIZATION_FAILED);

    // C3 claims the one-time invitation (re-putting C1 and C2 is answered
    // with the same ACKs, §47): CAROL now holds data/read. The used-up C2
    // no longer confers invite/claim, but its data/read stays (§18.1).
    commit_through(&v, &mut owner, 3).await;
    carol.request(open(&v, 0)).await;
    assert!(opened(&carol.recv().await), "the claimant opens");
    invite.request(open(&v, 0)).await;
    assert!(opened(&invite.recv().await), "C2's data/read stays");

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
    // §43: the ACK names RESOURCE_CLOSE (type 14).
    assert_eq!(
        live.recv().await.body,
        Body::Ack(AckBody {
            request_type: 14,
            object_ids: None,
            durable: None,
        })
    );
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

// ---- identity-01 (LFCP-04-408 V2) -----------------------------------------

mod identity {
    use super::*;
    use support::identity::{
        ask, control_ack, nack_code, put, scratch, session, signer, store_chain, Identity,
    };

    fn server_options() -> Options {
        options(vec![SYNC_A.into()], Arc::default())
    }

    /// One session per fixture Principal (new connections per address are
    /// rate limited).
    struct Sessions<'a> {
        v: &'a Identity,
        server: &'a support::lfcp::Running,
        open: std::collections::HashMap<String, Client>,
    }

    impl<'a> Sessions<'a> {
        fn new(v: &'a Identity, server: &'a support::lfcp::Running) -> Self {
            Sessions {
                v,
                server,
                open: Default::default(),
            }
        }

        async fn of(&mut self, label: &str) -> &mut Client {
            if !self.open.contains_key(label) {
                let client = session(self.v, self.server, label).await;
                self.open.insert(label.to_owned(), client);
            }
            self.open.get_mut(label).unwrap()
        }

        /// The reply to case `id`'s record put at `head` by its signer.
        async fn put(&mut self, id: &str, head: ControlRecordId) -> Body {
            let v = self.v;
            let client = self.of(&signer(v, id)).await;
            ask(client, put(v, id, head)).await
        }

        /// Commit the published records `ids` in order, each by its
        /// signer, each on the previous one; returns the last head.
        async fn commit(&mut self, ids: &[&str], mut head: ControlRecordId) -> ControlRecordId {
            for id in ids {
                let reply = self.put(id, head).await;
                assert_eq!(reply, control_ack(self.v.record_id(id)), "{id}");
                head = self.v.record_id(id);
            }
            head
        }
    }

    async fn host(v: &Identity, server: &support::lfcp::Running, genesis: &str) {
        let mut client = session(v, server, &signer(v, genesis)).await;
        let reply = ask(
            &mut client,
            Body::ResourceHost {
                genesis: v.cose(genesis),
                hosting_credential: None,
            },
        )
        .await;
        assert!(matches!(reply, Body::ResourceHosted { .. }), "{reply:?}");
    }

    async fn stored(server: &support::lfcp::Running, resource: ResourceId) -> usize {
        server
            .store
            .control_records(resource, 0, u64::MAX)
            .await
            .unwrap()
            .len()
    }

    /// DEVICE_GRANT and DEVICE_REVOKE records (types 9, 10) of the
    /// published chain commit through CONTROL_PUT by the sessions of their
    /// signers (a device included), each by compare-and-swap on the
    /// previous head; a repeated put is acknowledged again; a put on a
    /// stale head names the current one; refused proposals are not stored.
    #[tokio::test(flavor = "multi_thread")]
    async fn device_records_commit_through_control_put() {
        let v = Identity::load();
        let dir = scratch("control-devices");
        let server = start(&dir, server_options()).await;
        let x = v.resource("X");
        host(&v, &server, "J0_genesis").await;
        let mut sessions = Sessions::new(&v, &server);
        let j2 = sessions
            .commit(
                &["J1_grant_bob", "J2_grant_carol"],
                v.record_id("J0_genesis"),
            )
            .await;

        // Refused at J2, whoever proposes them, and nothing is stored.
        for (id, code) in [
            ("device_grant_body_extra_key", MALFORMED_MESSAGE),
            ("device_grant_root_unknown", MISSING_DEPENDENCY),
            ("device_grant_issuer_unrelated", AUTHORIZATION_FAILED),
        ] {
            assert_eq!(v.case(id)["context"]["head"]["case"], "J2_grant_carol");
            assert_eq!(nack_code(&sessions.put(id, j2).await), code, "{id}");
        }
        assert_eq!(stored(&server, x).await, 3);

        let i1 = sessions.commit(&["I1_device_grant_dev_a"], j2).await;
        for (id, code) in [
            ("device_revoke_with_field_3", MALFORMED_MESSAGE),
            ("device_grant_issuer_unknown", MISSING_DEPENDENCY),
            ("device_revoke_wrong_root", AUTHORIZATION_FAILED),
            ("device_grant_repeat_same_leaf_fresh", AUTHORIZATION_FAILED),
            (
                "device_grant_self_recertify_active_managing",
                AUTHORIZATION_FAILED,
            ),
        ] {
            assert_eq!(
                v.case(id)["context"]["head"]["case"],
                "I1_device_grant_dev_a",
                "{id}"
            );
            assert_eq!(v.expected_code(id), Some(code), "{id}");
            assert_eq!(nack_code(&sessions.put(id, i1).await), code, "{id}");
        }
        assert_eq!(stored(&server, x).await, 4);

        let i10 = sessions
            .commit(
                &[
                    "I2_device_grant_self_dev_b",
                    "I3_owner_action_by_dev_a",
                    "I4_device_grant_dev_c_bob",
                    "I5_device_grant_dev_e_by_dev_c",
                    "I6_grant_by_member_device",
                    "I7_revoke_covered_by_sibling",
                    "I8_bridge_grant",
                    "I9_device_revoke_dev_a",
                    "I10_recertify_dev_b",
                ],
                i1,
            )
            .await;
        assert_eq!(stored(&server, x).await, 13);

        // A repeated put of an accepted record is the same ACK, at any
        // expected head (at-least-once delivery).
        let owner = sessions.of("OWNER").await;
        for expected in [j2, i10] {
            assert_eq!(
                ask(owner, put(&v, "I1_device_grant_dev_a", expected)).await,
                control_ack(i1)
            );
        }
        // A record proposed on I9 after I10 committed: the head moved.
        let reply = ask(
            owner,
            put(
                &v,
                "flow.revoke_suspended_dev_b",
                v.record_id("I9_device_revoke_dev_a"),
            ),
        )
        .await;
        assert_eq!(nack_code(&reply), CONTROL_HEAD_MISMATCH);
        let Body::Nack(body) = reply else {
            unreachable!()
        };
        assert_eq!(
            body.details,
            Some(lfcp::cbor::Value::bytes(i10.as_bytes().to_vec()))
        );
        assert_eq!(stored(&server, x).await, 13);
        assert_eq!(server.store.head(x).await.unwrap().unwrap().id, i10);

        server.stop().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two valid revocations of DEV_B on one head (the owner's and DEV_A's,
    /// identity flow F06): exactly one commits; the other is
    /// CONTROL_HEAD_MISMATCH naming the winner and is not stored; DEV_A's
    /// fresh proposal on the new head is then refused (DEV_B is revoked).
    #[tokio::test(flavor = "multi_thread")]
    async fn competing_device_revocations_commit_exactly_once() {
        let v = Identity::load();
        let dir = scratch("control-device-race");
        let server = start(&dir, server_options()).await;
        let x = v.resource("X");
        store_chain(&server.store, &v.chain("flow.f06_owner_revokes_dev_b")).await;
        let i2 = v.record_id("I2_device_grant_self_dev_b");
        assert_eq!(server.store.head(x).await.unwrap().unwrap().id, i2);

        let ids = [
            "flow.f06_owner_revokes_dev_b",
            "flow.f06_dev_a_stale_proposal",
        ];
        let mut owner = session(&v, &server, "OWNER").await;
        let mut dev_a = session(&v, &server, "DEV_A").await;
        let (a, b) = tokio::join!(
            ask(&mut owner, put(&v, ids[0], i2)),
            ask(&mut dev_a, put(&v, ids[1], i2)),
        );
        let replies = [a, b];
        let winners: Vec<usize> = (0..2)
            .filter(|&i| matches!(replies[i], Body::Ack(_)))
            .collect();
        assert_eq!(winners.len(), 1, "{replies:?}");
        let (w, l) = (winners[0], 1 - winners[0]);
        let winner = v.record_id(ids[w]);
        assert_eq!(replies[w], control_ack(winner));
        assert_eq!(nack_code(&replies[l]), CONTROL_HEAD_MISMATCH);
        assert_eq!(
            server.store.control_records(x, 5, 5).await.unwrap().len(),
            1
        );
        assert_eq!(server.store.head(x).await.unwrap().unwrap().id, winner);
        // The loser's revocation is redundant now.
        if w == 0 {
            let reply = ask(&mut dev_a, put(&v, "flow.f06_dev_a_fresh_revoke", winner)).await;
            assert_eq!(nack_code(&reply), AUTHORIZATION_FAILED);
        }

        server.stop().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Pairing (identity flow F01, resource I): the coordinator checks the
    /// approval of a DEVICE_GRANT against the consuming DEVICE_REVOKE
    /// (reason 3, the approved payload digest) at the expected head.
    #[tokio::test(flavor = "multi_thread")]
    async fn pairing_approval_is_checked_by_compare_and_swap() {
        let v = Identity::load();
        let dir = scratch("control-pairing");
        let server = start(&dir, server_options()).await;
        let i = v.resource("I");
        host(&v, &server, "P0_genesis_i").await;
        let mut sessions = Sessions::new(&v, &server);
        let p2 = sessions
            .commit(
                &["P1_device_grant_dev_a_i", "P2_pairing_device"],
                v.record_id("P0_genesis_i"),
            )
            .await;
        for (id, code) in [
            (
                "device_grant_approval_without_consume",
                AUTHORIZATION_FAILED,
            ),
            ("device_revoke_reason3_without_field4", MALFORMED_MESSAGE),
            ("device_revoke_field4_with_reason_0", MALFORMED_MESSAGE),
        ] {
            assert_eq!(nack_code(&sessions.put(id, p2).await), code, "{id}");
        }
        let p3 = sessions.commit(&["P3_consume_for_dev_b"], p2).await;
        for (id, code) in [
            ("device_grant_approval_mismatch", AUTHORIZATION_FAILED),
            ("device_grant_field2_personal", AUTHORIZATION_FAILED),
            ("device_revoke_consume_twice", AUTHORIZATION_FAILED),
        ] {
            assert_eq!(nack_code(&sessions.put(id, p3).await), code, "{id}");
        }
        assert_eq!(stored(&server, i).await, 4);
        let p4 = sessions.commit(&["P4_register_dev_b_approved"], p3).await;
        assert_eq!(server.store.head(i).await.unwrap().unwrap().id, p4);
        assert_eq!(stored(&server, i).await, 5);

        server.stop().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// After each commit the subscribers are revalidated (§69): a
    /// DEVICE_REVOKE ends the live pushes of the revoked device and of the
    /// devices it suspends (DEV_B, certified by DEV_A) before it is pushed;
    /// a full reader still receives it. A recertified device reads again
    /// after a new RESOURCE_OPEN.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_revoke_ends_the_live_pushes_of_the_devices_it_disables() {
        let v = Identity::load();
        let dir = scratch("control-revalidate");
        let server = start(&dir, server_options()).await;
        let x = v.resource("X");
        let chain = v.chain("I9_device_revoke_dev_a");
        let i8 = store_chain(&server.store, &chain).await;
        assert_eq!(i8, v.record_id("I8_bridge_grant"));
        let live = |resource| Body::ResourceOpen {
            resource_id: resource,
            control_heads: vec![],
            have: vec![],
            grant_ids: None,
            flags: Some(0b011),
        };
        let mut subscribers = Vec::new();
        for label in ["BOB", "DEV_A", "DEV_B", "DEV_C"] {
            let mut client = session(&v, &server, label).await;
            let reply = ask(&mut client, live(x)).await;
            assert!(
                matches!(reply, Body::ResourceOpened { .. }),
                "{label}: {reply:?}"
            );
            subscribers.push((label, client));
        }
        let mut owner = session(&v, &server, "OWNER").await;
        let reply = ask(&mut owner, put(&v, "I9_device_revoke_dev_a", i8)).await;
        assert_eq!(reply, control_ack(v.record_id("I9_device_revoke_dev_a")));
        let pushed = |record: &str| Body::ControlBatch {
            resource_id: x,
            records: vec![v.cose(record)],
        };
        for (label, client) in &mut subscribers {
            match *label {
                "BOB" | "DEV_C" => {
                    assert_eq!(
                        client.recv().await.body,
                        pushed("I9_device_revoke_dev_a"),
                        "{label}"
                    )
                }
                _ => {
                    client.request(Body::Ping([9; 8])).await;
                    assert_eq!(client.recv().await.body, Body::Pong([9; 8]), "{label}");
                }
            }
        }
        // I10 recertifies DEV_B by OWNER: pushed to the readers that kept
        // their subscription, not to DEV_B, whose subscription ended.
        let reply = ask(
            &mut owner,
            put(
                &v,
                "I10_recertify_dev_b",
                v.record_id("I9_device_revoke_dev_a"),
            ),
        )
        .await;
        assert_eq!(reply, control_ack(v.record_id("I10_recertify_dev_b")));
        for (label, client) in &mut subscribers {
            match *label {
                "BOB" | "DEV_C" => {
                    assert_eq!(
                        client.recv().await.body,
                        pushed("I10_recertify_dev_b"),
                        "{label}"
                    )
                }
                _ => {
                    client.request(Body::Ping([10; 8])).await;
                    assert_eq!(client.recv().await.body, Body::Pong([10; 8]), "{label}");
                }
            }
        }
        // DEV_B reads in full again; DEV_A only its prefix.
        let (_, dev_b) = &mut subscribers[2];
        let Body::ResourceOpened { control_heads, .. } = ask(dev_b, live(x)).await else {
            panic!("DEV_B reopens");
        };
        assert_eq!(control_heads[0].id, v.record_id("I10_recertify_dev_b"));
        let (_, dev_a) = &mut subscribers[1];
        let Body::ResourceOpened { control_heads, .. } = ask(dev_a, live(x)).await else {
            panic!("DEV_A reopens its prefix");
        };
        assert_eq!(control_heads[0].id, v.record_id("I9_device_revoke_dev_a"));

        server.stop().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
