//! The LFCP session over real TCP WebSocket connections (LFCP-048): the
//! handshake byte for byte against LFCP-TEST-VECTORS-01, its failure codes,
//! the pre-READY gate, and RESOURCE_HOST / OPEN / CLOSE.

mod support;

use std::sync::Arc;

use lfcp::base::{ControlRecordId, ResourceId};
use lfcp::wire::control::body::ControlBody;
use lfcp::wire::control::ReceivedControlRecord;
use lfcp::wire::message::{Body, ControlHead, HelloBody, HostingCredential, Message};
use lfcp::wire::session::WIRE_PROFILE;
use lfcp::wire::snapshot::ReceivedSnapshot;
use lfcp_server::store::{CasOutcome, Put};
use support::lfcp::{code, start, state_dir, Client, FixedIdentity, Options, Script};
use support::vectors::Vectors;

const PROTOCOL_UNSUPPORTED: u64 = 1;
const MALFORMED_MESSAGE: u64 = 2;
const AUTH_FAILED: u64 = 3;
const AUTHORIZATION_FAILED: u64 = 4;
const RESOURCE_NOT_HOSTED: u64 = 6;
const INVALID_SIGNATURE: u64 = 7;
const INVALID_CONTROL_CHAIN: u64 = 8;
const CONTROL_CONFLICT: u64 = 9;
const HOSTING_DENIED: u64 = 20;

fn id16(bytes: &[u8]) -> [u8; 16] {
    bytes.try_into().unwrap()
}

/// The message ID (envelope key 1) of a published message.
fn message_id(bytes: &[u8]) -> [u8; 16] {
    Message::decode(bytes, &Default::default())
        .unwrap()
        .message_id
}

/// Script the server's random values so CHALLENGE and READY are the
/// published ones: server nonce, session ID, then the two message IDs.
fn script_vector_handshake(v: &Vectors, script: &Script) {
    script.push(id16(&v.session("server_nonce")));
    script.push(id16(&v.session("session_id")));
    script.push(message_id(&v.message("CHALLENGE")));
    script.push(message_id(&v.message("READY")));
}

fn vector_options(v: &Vectors) -> (Options, Arc<Script>) {
    let script = Arc::new(Script::default());
    script_vector_handshake(v, &script);
    let options = Options {
        identity: Some(Arc::new(FixedIdentity(
            v.session("server_id").try_into().unwrap(),
        ))),
        random: script.clone(),
        hosting: None,
        public_urls: Vec::new(),
        ingest: None,
    };
    (options, script)
}

fn host(genesis: Vec<u8>) -> Body {
    Body::ResourceHost {
        genesis,
        hosting_credential: None,
    }
}

fn open(resource_id: ResourceId) -> Body {
    Body::ResourceOpen {
        resource_id,
        control_heads: vec![],
        have: vec![],
        grant_ids: None,
        flags: Some(3),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_published_handshake_and_hosting_are_reproduced_byte_for_byte() {
    let v = Vectors::load();
    let dir = state_dir("vectors");
    let (options, script) = vector_options(&v);
    let server = start(&dir, options).await;
    let mut client = Client::connect(server.addr).await;

    // HELLO (BOB) → CHALLENGE with the stable server ID (§35).
    client.send_bytes(v.message("HELLO")).await;
    assert_eq!(client.recv_bytes().await, v.message("CHALLENGE"));
    // AUTH, BOB's proof over this exact transcript → READY (§36, §37):
    // 8 MiB, durability 2, heartbeat 30000 ms, no extensions.
    client.send_bytes(v.message("AUTH")).await;
    assert_eq!(client.recv_bytes().await, v.message("READY"));

    // RESOURCE_HOST(C0), no hosting credential (self-hosted MVP mode) →
    // RESOURCE_HOSTED at durability 2.
    script.push(message_id(&v.message("RESOURCE_HOSTED")));
    client.send_bytes(v.message("RESOURCE_HOST")).await;
    assert_eq!(client.recv_bytes().await, v.message("RESOURCE_HOSTED"));
    // Persisted before the reply.
    let info = server.store.resource(v.resource()).await.unwrap().unwrap();
    assert_eq!(info.genesis, v.record_id("C0_genesis"));
    assert_eq!(info.hosting.host, *v.principal("bob").descriptor().id());

    // BOB hosted it, but hosting grants nothing: at C0 only OWNER holds
    // data/read (§36, §84).
    let open_request = v.message("RESOURCE_OPEN");
    client.send_bytes(open_request.clone()).await;
    let denied = client.recv().await;
    assert_eq!(code(&denied), AUTHORIZATION_FAILED);
    assert_eq!(denied.correlation_id, Some(message_id(&open_request)));

    // C1 grants BOB data/read: the same request now opens.
    let outcome = server
        .store
        .commit_control_record(v.cose("C1_grant_bob"), v.record_id("C0_genesis"))
        .await
        .unwrap();
    assert_eq!(outcome, CasOutcome::Committed(Put::Inserted));
    client.send_bytes(open_request.clone()).await;
    let opened = client.recv().await;
    assert_eq!(opened.correlation_id, Some(message_id(&open_request)));
    let Body::ResourceOpened {
        resource_id,
        control_heads,
        have,
        snapshot,
        route_version,
        coordinator,
    } = opened.body
    else {
        panic!("expected RESOURCE_OPENED, got {:?}", opened.body);
    };
    assert_eq!(resource_id, v.resource());
    assert_eq!(
        control_heads,
        vec![ControlHead {
            sequence: 1,
            id: v.record_id("C1_grant_bob")
        }]
    );
    assert!(have.is_empty());
    assert_eq!(snapshot, None);
    assert_eq!(route_version, Some(0));
    assert_eq!(
        coordinator.as_deref(),
        Some("wss://sync-a.example.test/v1/ws")
    );

    // RESOURCE_CLOSE → ACK; the Resource stays stored.
    let close_request = v.message("RESOURCE_CLOSE");
    client.send_bytes(close_request.clone()).await;
    let ack = client.recv().await;
    assert_eq!(ack.correlation_id, Some(message_id(&close_request)));
    assert!(matches!(&ack.body, Body::Ack(a) if a.request_type == 14));
    assert!(server.store.resource(v.resource()).await.unwrap().is_some());

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_id_and_hosted_resources_survive_a_restart() {
    let v = Vectors::load();
    let owner = v.principal("owner");
    let dir = state_dir("restart");

    let server = start(&dir, Options::default()).await;
    let mut client = Client::connect(server.addr).await;
    let (challenge, ready) = client.handshake(&owner).await;
    let Body::Challenge(challenge) = challenge.body else {
        unreachable!()
    };
    let Body::Ready(ready) = ready.body else {
        unreachable!()
    };
    assert_eq!(&challenge.server_id, server.server_id.as_bytes());
    assert_eq!(ready.server_id, challenge.server_id);
    client.request(host(v.cose("C0_genesis"))).await;
    assert!(matches!(
        client.recv().await.body,
        Body::ResourceHosted { durability: 2, .. }
    ));
    let first_id = server.server_id;
    server.stop().await;

    let server = start(&dir, Options::default()).await;
    assert_eq!(server.server_id, first_id, "the server ID is persisted");
    let mut client = Client::connect(server.addr).await;
    let (challenge, _) = client.handshake(&owner).await;
    let Body::Challenge(challenge) = challenge.body else {
        unreachable!()
    };
    assert_eq!(&challenge.server_id, first_id.as_bytes());
    client.request(open(v.resource())).await;
    let Body::ResourceOpened { control_heads, .. } = client.recv().await.body else {
        panic!("expected RESOURCE_OPENED");
    };
    assert_eq!(control_heads[0].id, v.record_id("C0_genesis"));
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The published HELLO with BOB's descriptor bytes replaced.
fn hello_with_descriptor(v: &Vectors, descriptor: &[u8]) -> Vec<u8> {
    let hello = v.message("HELLO");
    let bob = v.hex("principal_bob", "expected", "descriptor_cbor");
    let at = hello
        .windows(bob.len())
        .position(|w| w == bob.as_slice())
        .unwrap();
    [&hello[..at], descriptor, &hello[at + bob.len()..]].concat()
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_failures_close_with_the_session_codes() {
    let v = Vectors::load();
    let dir = state_dir("hello");
    let server = start(&dir, Options::default()).await;

    // P3: an invalid descriptor in HELLO is AUTH_FAILED, not MALFORMED.
    let extra = v.hex("descriptor_extra_field", "inputs", "descriptor_cbor");
    let mut client = Client::connect(server.addr).await;
    client.send_bytes(hello_with_descriptor(&v, &extra)).await;
    assert_eq!(code(&client.recv().await), AUTH_FAILED);
    client.expect_close().await;

    // P2: a descriptor whose ID is not its keys' hash.
    let mut mismatched = v.hex("principal_bob", "expected", "descriptor_cbor");
    mismatched[4] ^= 1; // inside field 0, the Principal ID
    let mut client = Client::connect(server.addr).await;
    client
        .send_bytes(hello_with_descriptor(&v, &mismatched))
        .await;
    assert_eq!(code(&client.recv().await), AUTH_FAILED);
    client.expect_close().await;

    // §34: no common wire profile.
    let mut client = Client::connect(server.addr).await;
    client
        .request(Body::Hello(HelloBody {
            wire_profiles: vec!["LFCP-WIRE-02".into()],
            principal: v.principal("bob").descriptor().clone(),
            client_nonce: [7; 16],
            data_profiles: None,
        }))
        .await;
    assert_eq!(code(&client.recv().await), PROTOCOL_UNSUPPORTED);
    client.expect_close().await;

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_auth_is_auth_failed() {
    let v = Vectors::load();
    let dir = state_dir("auth");

    // A tampered signature in this exact session.
    let (options, _) = vector_options(&v);
    let server = start(&dir, options).await;
    let mut client = Client::connect(server.addr).await;
    client.send_bytes(v.message("HELLO")).await;
    assert_eq!(client.recv_bytes().await, v.message("CHALLENGE"));
    let mut auth = v.message("AUTH");
    *auth.last_mut().unwrap() ^= 1;
    client.send_bytes(auth).await;
    assert_eq!(code(&client.recv().await), AUTH_FAILED);
    client.expect_close().await;
    server.stop().await;

    // The published proof replayed into another session (new nonce and
    // session ID): the transcript differs.
    let server = start(&dir, Options::default()).await;
    let mut client = Client::connect(server.addr).await;
    client.send_bytes(v.message("HELLO")).await;
    assert!(matches!(client.recv().await.body, Body::Challenge(_)));
    client.send_bytes(v.message("AUTH")).await;
    assert_eq!(code(&client.recv().await), AUTH_FAILED);
    client.expect_close().await;
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_messages_before_ready_are_refused_and_the_session_continues() {
    let v = Vectors::load();
    let dir = state_dir("gate");
    let (options, script) = vector_options(&v);
    // The NACK and PONG below draw their message IDs first.
    script.clear();
    let server = start(&dir, options).await;
    let mut client = Client::connect(server.addr).await;

    // §64: before HELLO.
    let open_request = v.message("RESOURCE_OPEN");
    client.send_bytes(open_request.clone()).await;
    let nack = client.recv().await;
    assert!(matches!(nack.body, Body::Nack(_)));
    assert_eq!(code(&nack), AUTHORIZATION_FAILED);
    assert_eq!(nack.correlation_id, Some(message_id(&open_request)));
    // G-SM4: PING is answered before READY.
    let ping = client.request(Body::Ping([9; 8])).await;
    let pong = client.recv().await;
    assert_eq!(pong.body, Body::Pong([9; 8]));
    assert_eq!(pong.correlation_id, Some(ping));

    // Between CHALLENGE and AUTH. The NACK takes a message ID between
    // CHALLENGE's and READY's.
    script.push(id16(&v.session("server_nonce")));
    script.push(id16(&v.session("session_id")));
    script.push(message_id(&v.message("CHALLENGE")));
    script.push([0xee; 16]);
    script.push(message_id(&v.message("READY")));
    client.send_bytes(v.message("HELLO")).await;
    assert_eq!(client.recv_bytes().await, v.message("CHALLENGE"));
    client.request(host(v.cose("C0_genesis"))).await;
    assert_eq!(code(&client.recv().await), AUTHORIZATION_FAILED);
    assert!(server.store.resource(v.resource()).await.unwrap().is_none());

    // The handshake still completes.
    client.send_bytes(v.message("AUTH")).await;
    assert_eq!(client.recv_bytes().await, v.message("READY"));
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_ordering_violations_are_malformed_and_close() {
    let v = Vectors::load();
    let dir = state_dir("order");
    let server = start(&dir, Options::default()).await;
    let bob = v.principal("bob");

    // AUTH before HELLO.
    let mut client = Client::connect(server.addr).await;
    client.send_bytes(v.message("AUTH")).await;
    assert_eq!(code(&client.recv().await), MALFORMED_MESSAGE);
    client.expect_close().await;

    // HELLO twice.
    let mut client = Client::connect(server.addr).await;
    client.send_bytes(v.message("HELLO")).await;
    assert!(matches!(client.recv().await.body, Body::Challenge(_)));
    client.send_bytes(v.message("HELLO")).await;
    assert_eq!(code(&client.recv().await), MALFORMED_MESSAGE);
    client.expect_close().await;

    // HELLO after READY.
    let mut client = Client::connect(server.addr).await;
    client.handshake(&bob).await;
    client.send_bytes(v.message("HELLO")).await;
    assert_eq!(code(&client.recv().await), MALFORMED_MESSAGE);
    client.expect_close().await;

    // A server message (CHALLENGE) from the client.
    let mut client = Client::connect(server.addr).await;
    client.send_bytes(v.message("CHALLENGE")).await;
    assert_eq!(code(&client.recv().await), MALFORMED_MESSAGE);
    client.expect_close().await;

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_host_validates_genesis() {
    let v = Vectors::load();
    let dir = state_dir("genesis");
    let server = start(&dir, Options::default()).await;
    let mut client = Client::connect(server.addr).await;
    client.handshake(&v.principal("owner")).await;

    let refused = [
        // S2: signed by BOB while the body names OWNER.
        (v.negative("genesis_signer_not_owner"), INVALID_SIGNATURE),
        // G-CP4: an http:// endpoint.
        (v.negative("genesis_http_endpoint"), MALFORMED_MESSAGE),
        // Not a Genesis.
        (v.cose("C1_grant_bob"), INVALID_CONTROL_CHAIN),
        // Not even a signed object.
        (vec![0x84, 0x40], MALFORMED_MESSAGE),
    ];
    for (i, (genesis, expected)) in refused.into_iter().enumerate() {
        let id = client.request(host(genesis)).await;
        let nack = client.recv().await;
        assert_eq!(code(&nack), expected, "case {i}");
        assert_eq!(nack.correlation_id, Some(id));
    }
    assert!(server.store.resource(v.resource()).await.unwrap().is_none());

    // C0, twice: hosting is idempotent.
    for _ in 0..2 {
        client.request(host(v.cose("C0_genesis"))).await;
        let hosted = client.recv().await;
        assert_eq!(
            hosted.body,
            Body::ResourceHosted {
                resource_id: v.resource(),
                durability: 2
            }
        );
    }
    // G-CP5: another valid Genesis for the hosted Resource ID.
    let id = client
        .request(host(v.negative("genesis_competing_root")))
        .await;
    let nack = client.recv().await;
    assert_eq!(code(&nack), CONTROL_CONFLICT);
    assert_eq!(nack.correlation_id, Some(id));
    let info = server.store.resource(v.resource()).await.unwrap().unwrap();
    assert_eq!(info.genesis, v.record_id("C0_genesis"));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A policy that requires one credential to host.
struct NeedsCredential;

impl lfcp_server::session::HostingPolicy for NeedsCredential {
    fn allows(&self, _: &lfcp::base::PrincipalId, credential: Option<&HostingCredential>) -> bool {
        credential.is_some_and(|c| c.expose_secret() == b"let-me-host")
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hosting_credential_is_policy_not_authority() {
    let v = Vectors::load();
    let dir = state_dir("credential");
    let options = Options {
        hosting: Some(Arc::new(NeedsCredential)),
        ..Options::default()
    };
    let server = start(&dir, options).await;
    let mut bob = Client::connect(server.addr).await;
    bob.handshake(&v.principal("bob")).await;

    bob.request(host(v.cose("C0_genesis"))).await;
    assert_eq!(code(&bob.recv().await), HOSTING_DENIED);
    bob.request(Body::ResourceHost {
        genesis: v.cose("C0_genesis"),
        hosting_credential: Some(HostingCredential::new(b"wrong".to_vec())),
    })
    .await;
    assert_eq!(code(&bob.recv().await), HOSTING_DENIED);
    bob.request(Body::ResourceHost {
        genesis: v.cose("C0_genesis"),
        hosting_credential: Some(HostingCredential::new(b"let-me-host".to_vec())),
    })
    .await;
    assert!(matches!(bob.recv().await.body, Body::ResourceHosted { .. }));

    // The credential let BOB host; it gives BOB no Resource ability.
    bob.request(open(v.resource())).await;
    assert_eq!(code(&bob.recv().await), AUTHORIZATION_FAILED);
    // The owner, who has no credential, opens: authority is the chain.
    let mut owner = Client::connect(server.addr).await;
    owner.handshake(&v.principal("owner")).await;
    owner.request(open(v.resource())).await;
    assert!(matches!(
        owner.recv().await.body,
        Body::ResourceOpened { .. }
    ));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn opening_reports_forks_have_and_snapshot() {
    let v = Vectors::load();
    let dir = state_dir("fork");
    let server = start(&dir, Options::default()).await;
    let store = server.store.clone();

    // The published chain C0–C10, a competing C6, data and a snapshot.
    let chain = [
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
    let owner = v.principal("owner");
    store
        .host_resource(
            v.cose(chain[0]),
            lfcp_server::store::Hosting {
                host: *owner.descriptor().id(),
                durability: 2,
            },
        )
        .await
        .unwrap();
    for pair in chain.windows(2) {
        store
            .commit_control_record(v.cose(pair[1]), v.record_id(pair[0]))
            .await
            .unwrap();
    }
    let fork = v.negative("control_fork_C6");
    store.put_control_record(fork.clone()).await.unwrap();
    for unit in ["D1_bob_epoch0_seq1", "D2_bob_epoch0_seq2"] {
        store.put_data_unit(v.cose(unit)).await.unwrap();
    }
    let snapshot = v.cose("SNAPSHOT-01");
    store.put_snapshot(snapshot.clone()).await.unwrap();

    // BOB owns the Resource since C4.
    let mut client = Client::connect(server.addr).await;
    client.handshake(&v.principal("bob")).await;
    client.request(open(v.resource())).await;
    let Body::ResourceOpened {
        control_heads,
        have,
        snapshot: summary,
        route_version,
        coordinator,
        ..
    } = client.recv().await.body
    else {
        panic!("expected RESOURCE_OPENED");
    };
    // §42: the fork is not hidden.
    let fork_id =
        ControlRecordId::from_slice(&v.hex("control_fork_C6", "inputs", "record_id")).unwrap();
    assert_eq!(
        control_heads,
        vec![
            ControlHead {
                sequence: 6,
                id: fork_id
            },
            ControlHead {
                sequence: 10,
                id: v.record_id("C10_revoke_grandchild")
            },
        ]
    );
    // The Have: BOB's units 1 and 2.
    assert_eq!(have.len(), 1);
    assert_eq!(have[0].principal, *v.principal("bob").descriptor().id());
    assert_eq!(have[0].contiguous, 2);
    // The stored Snapshot's summary.
    let parsed = ReceivedSnapshot::parse(&snapshot).unwrap();
    let summary = summary.expect("a snapshot summary");
    assert_eq!(summary.snapshot_id, parsed.id());
    assert_eq!(summary.data_epoch, parsed.header().data_epoch);
    // Route version and coordinator from C5.
    let ControlBody::RouteUpdate(route) = ReceivedControlRecord::parse(&v.cose("C5_route_update"))
        .unwrap()
        .body()
        .clone()
    else {
        panic!("C5 is a Route Update")
    };
    assert_eq!(route_version, Some(route.version));
    assert_eq!(coordinator, Some(route.coordinator));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_resource_is_not_hosted() {
    let v = Vectors::load();
    let dir = state_dir("unknown");
    let server = start(&dir, Options::default()).await;
    let mut client = Client::connect(server.addr).await;
    client.handshake(&v.principal("owner")).await;
    let id = client
        .request(open(ResourceId::from_bytes([0xab; 32])))
        .await;
    let nack = client.recv().await;
    assert_eq!(code(&nack), RESOURCE_NOT_HOSTED);
    assert_eq!(nack.correlation_id, Some(id));
    // Presence is not offered; the session goes on.
    client
        .request(Body::PresenceLeave {
            resource_id: v.resource(),
            principal: *v.principal("owner").descriptor().id(),
        })
        .await;
    assert_eq!(code(&client.recv().await), PROTOCOL_UNSUPPORTED);
    client.request(Body::Ping([1; 8])).await;
    assert_eq!(client.recv().await.body, Body::Pong([1; 8]));
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn wire_profile_is_the_published_one() {
    let v = Vectors::load();
    let hello = Message::decode(&v.message("HELLO"), &Default::default()).unwrap();
    let Body::Hello(hello) = hello.body else {
        panic!()
    };
    assert_eq!(hello.wire_profiles, vec![WIRE_PROFILE.to_owned()]);
}
