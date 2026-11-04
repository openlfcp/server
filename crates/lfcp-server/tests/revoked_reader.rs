//! The Control read for a revoked reader (WIRE-01 §41, identity-01; task
//! LFCP-04-408 V3) and the other session cases of
//! LFCP-IDENTITY-TEST-VECTORS-01, over real WebSocket sessions.
//!
//! A registered device that held `data/read` immediately before the first
//! `DEVICE_REVOKE` naming it reads the accepted Control Chain through that
//! record: `RESOURCE_OPENED` names it as the only head, with an empty Have,
//! no Snapshot summary and no live subscription; `CONTROL_HAVE` answers it;
//! `CONTROL_GET` returns the accepted records up to it. Every other read is
//! `NACK(AUTHORIZATION_FAILED)`. Presence is refused to every session: the
//! server does not offer the `presence` extension (§58). Uploads are
//! checked by object, whoever sends them (§84).

mod support;

use lfcp::base::{PrincipalId, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::{CapabilityGrantBody, ControlBody};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use lfcp::wire::message::{Body, ControlHead, DataRange};
use support::identity::{scratch, store_chain, Identity};
use support::lfcp::{start, Client, Options, Running};

const PROTOCOL_UNSUPPORTED: u64 = 1;
const AUTHORIZATION_FAILED: u64 = 4;

/// A server whose store holds case `id`'s context chain.
async fn server_for(v: &Identity, id: &str) -> (Running, std::path::PathBuf) {
    let dir = scratch(&format!("rr-{}", id.replace(['.', '/'], "-")));
    let server = start(&dir, Options::default()).await;
    store_chain(&server.store, &v.chain(id)).await;
    (server, dir)
}

async fn session(server: &Running, keys: &PrincipalKeys) -> Client {
    let mut client = Client::connect(server.addr).await;
    client.handshake(keys).await;
    client
}

fn head_of(v: &Identity, case: &str) -> ControlHead {
    ControlHead {
        sequence: v.case(case)["inputs"]["control_seq"].as_u64().unwrap(),
        id: v.record_id(case),
    }
}

fn open(resource: ResourceId) -> Body {
    Body::ResourceOpen {
        resource_id: resource,
        control_heads: vec![],
        have: vec![],
        grant_ids: None,
        // Live Data, live Control and presence.
        flags: Some(0b111),
    }
}

fn control_get(resource: ResourceId, start: u64, end: u64) -> Body {
    Body::ControlGet {
        resource_id: resource,
        start,
        end,
    }
}

/// Send `body`; the reply.
async fn ask(client: &mut Client, body: Body) -> Body {
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

/// The records of a one-batch CONTROL_GET reply.
async fn records(client: &mut Client, resource: ResourceId, start: u64, end: u64) -> Vec<Vec<u8>> {
    match ask(client, control_get(resource, start, end)).await {
        Body::ControlBatch { records, .. } => records,
        other => panic!("expected CONTROL_BATCH, got {other:?}"),
    }
}

async fn control_have(client: &mut Client, resource: ResourceId) -> Body {
    ask(
        client,
        Body::ControlHave {
            resource_id: resource,
            control_heads: vec![],
        },
    )
    .await
}

/// Every read other than the Control prefix, each refused.
async fn refused_reads(client: &mut Client, resource: ResourceId, me: PrincipalId, after: u64) {
    let reads = [
        (
            "later Control Records",
            control_get(resource, after + 1, u64::MAX),
        ),
        (
            "DATA_HAVE",
            Body::DataHave {
                resource_id: resource,
                have: vec![],
            },
        ),
        (
            "DATA_GET",
            Body::DataGet {
                resource_id: resource,
                ranges: vec![DataRange {
                    principal: me,
                    start: 1,
                    end: 100,
                }],
            },
        ),
        (
            "KEY_PACKAGE_GET",
            Body::KeyPackageGet {
                resource_id: resource,
                recipient: me,
                epochs: vec![0, 1],
            },
        ),
        (
            "SNAPSHOT_GET",
            Body::SnapshotGet {
                resource_id: resource,
                snapshot_id: None,
            },
        ),
    ];
    for (what, body) in reads {
        assert_eq!(
            nack_code(&ask(client, body).await),
            AUTHORIZATION_FAILED,
            "{what}"
        );
    }
    // No presence for anyone here (§58: the extension is not offered).
    let presence = Body::Presence {
        resource_id: resource,
        principal: me,
        ttl_ms: 1000,
        payload: vec![],
    };
    assert_eq!(
        nack_code(&ask(client, presence).await),
        PROTOCOL_UNSUPPORTED,
        "presence"
    );
}

/// A `session_read` case: RESOURCE_OPEN, CONTROL_GET or DATA_GET by its
/// session on its context chain, as the case expects.
async fn session_read(v: &Identity, id: &str) {
    let case = v.case(id);
    let inputs = &case["inputs"];
    assert_eq!(inputs["server_extensions"][0], "identity-01", "{id}");
    let (server, dir) = server_for(v, id).await;
    let resource = v.context_resource(id).unwrap();
    let label = inputs["session"].as_str().unwrap();
    let me = v.principal_id(label);
    let mut client = session(&server, &v.principal(label)).await;
    let latest = v.latest(id).unwrap();
    match v.expected_code(id) {
        Some(expected) if inputs["request"] == "DATA_GET" => {
            let reply = ask(
                &mut client,
                Body::DataGet {
                    resource_id: resource,
                    ranges: vec![DataRange {
                        principal: me,
                        start: 1,
                        end: 100,
                    }],
                },
            )
            .await;
            assert_eq!(nack_code(&reply), expected, "{id}: DATA_GET");
        }
        Some(expected) => {
            // No Control read either: refused whatever the session asks.
            let reply = ask(&mut client, open(resource)).await;
            assert_eq!(nack_code(&reply), expected, "{id}: RESOURCE_OPEN");
            let reply = control_have(&mut client, resource).await;
            assert_eq!(nack_code(&reply), expected, "{id}: CONTROL_HAVE");
            let reply = ask(&mut client, control_get(resource, 0, u64::MAX)).await;
            assert_eq!(nack_code(&reply), expected, "{id}: CONTROL_GET");
        }
        None => {
            let post = &case["expected"]["post_state"];
            let head = head_of(v, post["control_head"].as_str().unwrap());
            match post["read"].as_str().unwrap() {
                "full" => {
                    assert_eq!(head.id, latest, "{id}");
                    let Body::ResourceOpened { control_heads, .. } =
                        ask(&mut client, open(resource)).await
                    else {
                        panic!("{id}: not opened");
                    };
                    assert_eq!(control_heads, vec![head], "{id}");
                }
                "prefix" => {
                    assert_ne!(head.id, latest, "{id}: a later head exists");
                    let want: Vec<Vec<u8>> = post["records"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| v.cose(r.as_str().unwrap()))
                        .collect();
                    assert_eq!(
                        records(&mut client, resource, 0, u64::MAX).await,
                        want,
                        "{id}"
                    );
                    assert_eq!(
                        control_have(&mut client, resource).await,
                        Body::ControlHave {
                            resource_id: resource,
                            control_heads: vec![head],
                        },
                        "{id}"
                    );
                    assert_eq!(
                        ask(&mut client, open(resource)).await,
                        Body::ResourceOpened {
                            resource_id: resource,
                            control_heads: vec![head],
                            have: vec![],
                            snapshot: None,
                            route_version: None,
                            coordinator: None,
                        },
                        "{id}"
                    );
                    assert_eq!(
                        server.store.head(resource).await.unwrap().unwrap().id,
                        latest
                    );
                    refused_reads(&mut client, resource, me, head.sequence).await;
                    let listed = post["refused_reads"].as_array().unwrap().len();
                    assert_eq!(listed, 6, "{id}: the reads checked above");
                }
                other => panic!("{id}: read {other}"),
            }
        }
    }
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A `session_upload` case: a revoked session uploads an object; it is
/// checked by object (§84), the session's read authority aside.
async fn session_upload(v: &Identity, id: &str) {
    let case = v.case(id);
    let inputs = &case["inputs"];
    let (server, dir) = server_for(v, id).await;
    let resource = v.context_resource(id).unwrap();
    let label = inputs["session"].as_str().unwrap();
    let mut client = session(&server, &v.principal(label)).await;
    // The session reads nothing but the prefix ...
    assert_eq!(
        nack_code(
            &ask(
                &mut client,
                Body::DataHave {
                    resource_id: resource,
                    have: vec![]
                }
            )
            .await
        ),
        AUTHORIZATION_FAILED,
        "{id}"
    );
    // ... and uploads like any session.
    let put = |bytes: Vec<u8>| match case["kind"].as_str() {
        _ if inputs["recipient"].is_string() => Body::KeyPackagePut {
            resource_id: resource,
            packages: vec![bytes],
        },
        _ => Body::DataPut {
            resource_id: resource,
            units: vec![bytes],
        },
    };
    if let Some(previous) = inputs["previous"].as_str() {
        let reply = ask(&mut client, put(v.cose(previous))).await;
        assert!(matches!(reply, Body::Ack(_)), "{id}: {previous}: {reply:?}");
    }
    let reply = ask(&mut client, put(v.cose(id))).await;
    let got = match reply {
        Body::Ack(_) => None,
        ref other => Some(nack_code(other)),
    };
    assert_eq!(got, v.expected_code(id), "{id}");
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_session_vectors_hold_on_the_server() {
    let v = Identity::load();
    let reads: Vec<String> = v
        .cases()
        .filter(|c| c["kind"] == "session_read")
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect();
    let uploads: Vec<String> = v
        .cases()
        .filter(|c| c["kind"] == "session_upload")
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect();
    for required in [
        "CONTROL_GET_by_revoked_reader",
        "CONTROL_GET_by_consumed_pairing",
        "CONTROL_GET_by_intermediate_only",
        "CONTROL_GET_by_unbound_tombstoned",
        "CONTROL_GET_by_never_reader",
        "CONTROL_GET_by_root_without_standing",
        "DATA_GET_by_revoked_session",
    ] {
        assert!(reads.iter().any(|id| id == required), "{required}");
    }
    assert_eq!((reads.len(), uploads.len()), (11, 4));
    for id in &reads {
        session_read(&v, id).await;
    }
    for id in &uploads {
        session_upload(&v, id).await;
    }
}

/// The three negative cases the task names, each refused for every Control
/// read: an intermediate-only device, a pre-emptively revoked device that
/// was never bound, and a device whose mask never held `data/read`.
#[tokio::test(flavor = "multi_thread")]
async fn no_prefix_without_a_revoked_registered_reader() {
    let v = Identity::load();
    for id in [
        "CONTROL_GET_by_intermediate_only",
        "CONTROL_GET_by_unbound_tombstoned",
        "CONTROL_GET_by_never_reader",
    ] {
        assert_eq!(v.expected_code(id), Some(AUTHORIZATION_FAILED), "{id}");
        let (server, dir) = server_for(&v, id).await;
        let resource = v.context_resource(id).unwrap();
        let label = v.case(id)["inputs"]["session"].as_str().unwrap().to_owned();
        let mut client = session(&server, &v.principal(&label)).await;
        for (start, end) in [(0, 0), (0, u64::MAX), (1, 3)] {
            let reply = ask(&mut client, control_get(resource, start, end)).await;
            assert_eq!(
                nack_code(&reply),
                AUTHORIZATION_FAILED,
                "{id} {start}..{end}"
            );
        }
        assert_eq!(
            nack_code(&control_have(&mut client, resource).await),
            AUTHORIZATION_FAILED,
            "{id}"
        );
        assert_eq!(
            nack_code(&ask(&mut client, open(resource)).await),
            AUTHORIZATION_FAILED,
            "{id}"
        );
        server.stop().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The prefix is the accepted chain only: fork evidence stored at a
/// sequence the prefix covers is served to a full reader, never to the
/// revoked one; a range is cut at the revocation, and a range after it is
/// refused.
#[tokio::test(flavor = "multi_thread")]
async fn the_prefix_is_the_accepted_chain_through_the_revocation() {
    let v = Identity::load();
    let id = "CONTROL_GET_by_revoked_reader";
    let (server, dir) = server_for(&v, id).await;
    let resource = v.context_resource(id).unwrap();
    let chain = v.chain(id);
    let revocation = head_of(&v, "I9_device_revoke_dev_a");
    assert_eq!(revocation.sequence, 11);

    // A competing record at sequence 5, stored as evidence, and a Data
    // Unit of DEV_A from before its revocation.
    let owner = v.principal("OWNER");
    let at4 = ReceivedControlRecord::parse(&chain[4].bytes).unwrap();
    let competing = ControlRecord::sign(
        ControlRecordHeader {
            resource_id: resource,
            sequence: 5,
            previous: Some(at4.id()),
            issuer: *owner.descriptor().id(),
        },
        ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: v.principal("DAVE").descriptor().clone(),
            abilities: vec![1],
            delegable: vec![],
            parent: None,
            claim_limit: None,
        }),
        &owner,
    )
    .unwrap();
    let competing = competing.signed_object().bytes().to_vec();
    server
        .store
        .put_control_record(competing.clone())
        .await
        .unwrap();
    let mut full = session(&server, &owner).await;
    let reply = ask(
        &mut full,
        Body::DataPut {
            resource_id: resource,
            units: vec![v.cose("D_dev_a_seq1")],
        },
    )
    .await;
    assert!(matches!(reply, Body::Ack(_)), "{reply:?}");

    let all = records(&mut full, resource, 0, u64::MAX).await;
    assert_eq!(all.len(), chain.len() + 1);
    assert!(all.contains(&competing));
    let Body::ResourceOpened {
        control_heads,
        have,
        ..
    } = ask(&mut full, open(resource)).await
    else {
        panic!("OWNER opens X");
    };
    assert_eq!(control_heads.len(), 2, "the fork is visible to a reader");
    assert!(!have.is_empty());

    let mut revoked = session(&server, &v.principal("DEV_A")).await;
    let prefix: Vec<Vec<u8>> = chain[..=11].iter().map(|r| r.bytes.clone()).collect();
    assert_eq!(records(&mut revoked, resource, 0, u64::MAX).await, prefix);
    assert_eq!(records(&mut revoked, resource, 5, 100).await, prefix[5..]);
    assert_eq!(records(&mut revoked, resource, 11, 11).await, prefix[11..]);
    assert_eq!(
        nack_code(&ask(&mut revoked, control_get(resource, 12, 12)).await),
        AUTHORIZATION_FAILED
    );
    let Body::ResourceOpened {
        control_heads,
        have,
        snapshot,
        ..
    } = ask(&mut revoked, open(resource)).await
    else {
        panic!("DEV_A opens its prefix");
    };
    assert_eq!(control_heads, vec![revocation]);
    assert!(have.is_empty() && snapshot.is_none());
    refused_reads(&mut revoked, resource, v.principal_id("DEV_A"), 11).await;
    // A reversed range stays malformed.
    assert_eq!(
        nack_code(&ask(&mut revoked, control_get(resource, 3, 2)).await),
        2
    );
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A revoked reader's prefix ends at the first record that revoked it,
/// and it gets no live pushes: records committed after its RESOURCE_OPEN
/// reach a full reader, not it.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_reader_gets_no_live_pushes() {
    let v = Identity::load();
    let id = "CONTROL_GET_by_revoked_reader";
    let dir = scratch("rr-live");
    let server = start(
        &dir,
        Options {
            public_urls: vec!["wss://sync-a.example.test/v1/ws".into()],
            ..Options::default()
        },
    )
    .await;
    let chain = v.chain(id);
    // Through I9: DEV_A is revoked; I10 is committed live.
    store_chain(&server.store, &chain[..12]).await;
    let resource = v.context_resource(id).unwrap();
    let mut revoked = session(&server, &v.principal("DEV_A")).await;
    let Body::ResourceOpened { control_heads, .. } = ask(&mut revoked, open(resource)).await else {
        panic!("prefix open");
    };
    assert_eq!(control_heads, vec![head_of(&v, "I9_device_revoke_dev_a")]);
    let mut reader = session(&server, &v.principal("OWNER")).await;
    assert!(matches!(
        ask(&mut reader, open(resource)).await,
        Body::ResourceOpened { .. }
    ));

    let mut writer = session(&server, &v.principal("DEV_B")).await;
    let reply = ask(
        &mut writer,
        Body::ControlPut {
            resource_id: resource,
            expected_head: v.record_id("I9_device_revoke_dev_a"),
            record: v.cose("I10_recertify_dev_b"),
        },
    )
    .await;
    assert!(matches!(reply, Body::Ack(_)), "{reply:?}");
    let pushed = reader.recv().await;
    assert!(
        matches!(&pushed.body, Body::ControlBatch { records, .. } if records == &vec![v.cose("I10_recertify_dev_b")]),
        "{pushed:?}"
    );
    // Nothing reached the revoked reader: its next message is the reply
    // to its next request.
    assert_eq!(
        control_have(&mut revoked, resource).await,
        Body::ControlHave {
            resource_id: resource,
            control_heads: vec![head_of(&v, "I9_device_revoke_dev_a")],
        }
    );
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
