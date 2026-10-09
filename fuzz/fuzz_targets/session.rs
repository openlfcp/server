//! The server's request handlers through its own WebSocket session, over an
//! in-memory pipe (no network I/O), on a fresh store.
//!
//! Input: `[flags][records]`, each record `[kind][len u16 LE][bytes]`, at
//! most 32. Flag bit 0: the harness first completes HELLO / AUTH as the
//! owner; bit 1: it then hosts the owner's Resource (`lfcp_server_fuzz::
//! resource`). Each record is sent as a binary frame (kind bit 0: text).
//!
//! Checks, beyond no panic (any panic aborts, the server's tasks included)
//! and the allocation limit:
//! - every server message decodes;
//! - a request answered with NACK or ERROR leaves every table of the store
//!   as it was (ACTOR_EQUIVOCATION excepted: its units are kept as
//!   evidence, WIRE §26.2);
//! - after the connection, the store still opens and reads.
//!
//! `LFCP_FUZZ_WRITE_SEEDS=<dir>` writes the seed corpus (a full owner
//! session: open, have, get, grant, Data Units, an invitation and its
//! claim, a revoke, key package and Snapshot reads) and exits.

#![no_main]

use std::sync::Arc;
use std::time::Duration;

use lfcp::base::{Hash32, PrincipalId};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::authority::ability;
use lfcp::wire::control::body::{
    CapabilityClaimBody, CapabilityGrantBody, CapabilityRevokeBody, ControlBody,
};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use lfcp::wire::data_unit::{DataUnit, DataUnitHeader};
use lfcp::wire::keys::Dek;
use lfcp::wire::message::{Body, DataRange, DecodeOptions, FrameKind, Message};
use lfcp_server::store::Store;
use lfcp_server_fuzz::*;
use libfuzzer_sys::fuzz_target;

/// ACTOR_EQUIVOCATION: the NACK whose units are kept as evidence.
const ACTOR_EQUIVOCATION: &str = "ACTOR_EQUIVOCATION";

fn records(mut data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while data.len() >= 3 && out.len() < 32 {
        let kind = data[0];
        let len = usize::from(u16::from_le_bytes([data[1], data[2]]));
        let Some(bytes) = data.get(3..3 + len) else {
            break;
        };
        out.push((kind, bytes));
        data = &data[3 + len..];
    }
    out
}

/// Whether `body` is a request the server answers (a client message type).
fn answered(body: &Body) -> bool {
    !matches!(
        body,
        Body::Error(_)
            | Body::Pong(_)
            | Body::Ack(_)
            | Body::Nack(_)
            | Body::Ready(_)
            | Body::Challenge(_)
    )
}

fn code_name(code: u64) -> &'static str {
    lfcp::base::WireCode::from_number(code).map_or("?", |c| c.name())
}

fuzz_target!(|data: &[u8]| {
    if let Some(dir) = std::env::var_os("LFCP_FUZZ_WRITE_SEEDS") {
        write_seeds(std::path::Path::new(&dir));
        std::process::exit(0);
    }
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let dir = fresh_dir();
    let config = config(&dir);
    let store = Arc::new(Store::open(&dir).expect("a fresh store opens"));
    let db = store.path().to_owned();
    runtime().block_on(async {
        let mut conn = connect(store.clone(), &config).await;
        let mut open = true;
        if flags & 1 != 0 {
            open = conn.handshake(&owner()).await;
            if open && flags & 2 != 0 {
                let id = [0xa3; 16];
                let host = Body::ResourceHost {
                    genesis: genesis(&owner(), resource()),
                    hosting_credential: None,
                };
                conn.send_binary(Message::new(id, host).encode()).await;
                let r = conn.reply(Some(id), Duration::from_secs(5)).await;
                assert!(
                    matches!(&r, Reply::Answered(m) if matches!(m.last().map(|m| &m.body), Some(Body::ResourceHosted { .. }))),
                    "the harness's RESOURCE_HOST: {r:?}"
                );
            }
        }
        let options = DecodeOptions {
            max_message_bytes: config.max_message_bytes,
            ..DecodeOptions::default()
        };
        for (kind, bytes) in records(rest) {
            if !open {
                break;
            }
            let before = fingerprint(&db);
            let text = kind & 1 != 0;
            let frame_kind = if text {
                FrameKind::Text
            } else {
                FrameKind::Binary
            };
            let decoded = Message::decode_frame(frame_kind, bytes, &options).ok();
            let sent = if text {
                conn.send_text(String::from_utf8_lossy(bytes).into_owned()).await
            } else {
                conn.send_binary(bytes.to_vec()).await
            };
            if !sent {
                break;
            }
            let (id, wait) = match &decoded {
                Some(m) if answered(&m.body) => (Some(m.message_id), Duration::from_millis(1500)),
                _ => (None, Duration::from_millis(60)),
            };
            let reply = conn.reply(id, wait).await;
            let messages = match &reply {
                Reply::Answered(m) | Reply::Silent(m) => m,
                Reply::Closed(m) => {
                    open = false;
                    m
                }
            };
            // The answer to this request, when it is a refusal.
            let refusal = match &reply {
                Reply::Answered(m) => match m.last().map(|m| &m.body) {
                    Some(Body::Nack(e) | Body::Error(e)) => Some(code_name(e.code)),
                    _ => None,
                },
                Reply::Closed(m) | Reply::Silent(m) => m.iter().rev().find_map(|m| match &m.body {
                    Body::Error(e) if m.correlation_id.is_none() || m.correlation_id == id => {
                        Some(code_name(e.code))
                    }
                    _ => None,
                }),
            };
            if std::env::var_os("LFCP_FUZZ_TRACE").is_some() {
                let sent = decoded.as_ref().map(|m| format!("{:?}", m.body).chars().take(40).collect::<String>());
                let got: Vec<String> = messages.iter().map(|m| format!("{:?}", m.body).chars().take(70).collect()).collect();
                eprintln!("TRACE sent {sent:?} -> {} {got:?}", match &reply { Reply::Answered(_) => "answered", Reply::Closed(_) => "closed", Reply::Silent(_) => "silent" });
            }
            if let Some(code) = refusal {
                if code != ACTOR_EQUIVOCATION {
                    // Give a write the server should not make a moment to land.
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    assert_eq!(
                        fingerprint(&db),
                        before,
                        "a request refused with {code} changed the store"
                    );
                }
            }
        }
        conn.close().await;
    });
    drop(store);
    if let Some(keep) = std::env::var_os("LFCP_FUZZ_KEEP_STORE") {
        // For the store_open seeds: the database a session left.
        let keep = std::path::PathBuf::from(keep);
        let _ = std::fs::create_dir_all(&keep);
        for suffix in ["", "-wal"] {
            let mut from = db.clone().into_os_string();
            from.push(suffix);
            let _ = std::fs::copy(&from, keep.join(format!("server.sqlite3{suffix}")));
        }
    }
    // The store reopens after the session.
    let reopened = Store::open(&dir).expect("the store reopens after a session");
    drop(reopened);
    let _ = std::fs::remove_dir_all(&dir);
});

// ---- seeds ----------------------------------------------------------------

fn record(kind: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn sign(keys: &PrincipalKeys, sequence: u64, previous: &[u8], body: ControlBody) -> Vec<u8> {
    ControlRecord::sign(
        ControlRecordHeader {
            resource_id: resource(),
            sequence,
            previous: Some(ReceivedControlRecord::parse(previous).unwrap().id()),
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

fn write_seeds(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    let r = resource();
    let alice = owner();
    let b = bob();
    let invitee = PrincipalKeys::from_secrets(&[5; 32], [6; 32]);
    let g = genesis(&alice, r);
    let head0 = ReceivedControlRecord::parse(&g).unwrap().id();
    let grant = sign(
        &alice,
        1,
        &g,
        ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: b.descriptor().clone(),
            abilities: vec![ability::DATA_READ, ability::DATA_WRITE],
            delegable: vec![],
            parent: None,
            claim_limit: None,
        }),
    );
    let invite = sign(
        &alice,
        2,
        &grant,
        ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: invitee.descriptor().clone(),
            abilities: vec![ability::DATA_READ, ability::INVITE_CLAIM],
            delegable: vec![],
            parent: None,
            claim_limit: Some(1),
        }),
    );
    let claim = sign(
        &invitee,
        3,
        &invite,
        ControlBody::CapabilityClaim(CapabilityClaimBody {
            invitation_grant: ReceivedControlRecord::parse(&invite).unwrap().id(),
            claimant: b.descriptor().clone(),
            abilities: vec![ability::DATA_READ],
        }),
    );
    let revoke = sign(
        &alice,
        4,
        &claim,
        ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: ReceivedControlRecord::parse(&grant).unwrap().id(),
        }),
    );
    let dek = Dek::from_bytes([9; 32]);
    let mut previous = None;
    let units: Vec<Vec<u8>> = (1..=3u64)
        .map(|seq| {
            let unit = DataUnit::seal(
                DataUnitHeader {
                    resource_id: r,
                    data_epoch: 0,
                    actor: *alice.descriptor().id(),
                    sequence: seq,
                    previous,
                    control_head: Hash32::from_bytes(*head0.as_bytes()),
                },
                format!("plaintext {seq}").as_bytes(),
                &dek,
                &alice,
            )
            .unwrap();
            previous = Some(unit.id());
            unit.signed_object().bytes().to_vec()
        })
        .collect();
    let me: PrincipalId = *alice.descriptor().id();
    let id_of = |rec: &[u8]| ReceivedControlRecord::parse(rec).unwrap().id();
    let mut n = 0u8;
    let mut msg = |body: Body| {
        n += 1;
        Message::new([n; 16], body).encode()
    };
    let steps: Vec<Vec<u8>> = vec![
        msg(Body::ResourceOpen {
            resource_id: r,
            control_heads: vec![],
            have: vec![],
            grant_ids: None,
            flags: None,
        }),
        msg(Body::ControlHave {
            resource_id: r,
            control_heads: vec![],
        }),
        msg(Body::ControlGet {
            resource_id: r,
            start: 0,
            end: 8,
        }),
        msg(Body::ControlPut {
            resource_id: r,
            expected_head: head0,
            record: grant.clone(),
        }),
        msg(Body::DataPut {
            resource_id: r,
            units: units[..2].to_vec(),
        }),
        msg(Body::DataPut {
            resource_id: r,
            units: units[2..].to_vec(),
        }),
        msg(Body::DataHave {
            resource_id: r,
            have: vec![],
        }),
        msg(Body::DataGet {
            resource_id: r,
            ranges: vec![DataRange {
                principal: me,
                start: 1,
                end: 3,
            }],
        }),
        msg(Body::ControlPut {
            resource_id: r,
            expected_head: id_of(&grant),
            record: invite.clone(),
        }),
        msg(Body::ControlPut {
            resource_id: r,
            expected_head: id_of(&invite),
            record: claim.clone(),
        }),
        msg(Body::ControlPut {
            resource_id: r,
            expected_head: id_of(&claim),
            record: revoke.clone(),
        }),
        msg(Body::KeyPackageGet {
            resource_id: r,
            recipient: me,
            epochs: vec![0],
        }),
        msg(Body::SnapshotGet {
            resource_id: r,
            snapshot_id: None,
        }),
        msg(Body::Ping([7; 8])),
        msg(Body::ResourceClose { resource_id: r }),
    ];
    let write = |name: &str, flags: u8, recs: &[Vec<u8>]| {
        let mut data = vec![flags];
        for r in recs {
            data.extend(r);
        }
        std::fs::write(dir.join(name), data).unwrap();
    };
    let all: Vec<Vec<u8>> = steps.iter().map(|s| record(0, s)).collect();
    write("full-session", 3, &all);
    for (i, s) in steps.iter().enumerate() {
        write(&format!("one-{i:02}"), 3, &[record(0, s)]);
        write(&format!("one-{i:02}-before-host"), 1, &[record(0, s)]);
        write(&format!("one-{i:02}-before-ready"), 0, &[record(0, s)]);
    }
    write("text-frame", 3, &[record(1, b"{\"type\":0}")]);
    // Pre-handshake: a HELLO of the owner, as raw bytes.
    let hello = Message::new(
        [0xa1; 16],
        Body::Hello(lfcp::wire::message::HelloBody {
            wire_profiles: vec![lfcp::wire::session::WIRE_PROFILE.into()],
            principal: alice.descriptor().clone(),
            client_nonce: [0xc1; 16],
            data_profiles: None,
        }),
    )
    .encode();
    write("raw-hello", 0, &[record(0, &hello)]);
    write(
        "raw-genesis-host",
        1,
        &[record(
            0,
            &msg(Body::ResourceHost {
                genesis: g.clone(),
                hosting_credential: None,
            }),
        )],
    );
}
