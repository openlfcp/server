//! LFCP-IDENTITY-TEST-VECTORS-01 (mvp-0.4-baseline.2) through the
//! server's own code paths, for every case a server decides (WIRE-01 §37
//! `identity-01`, §41, §84; the corpus list is IDENTITY-PROFILE-01 §12):
//!
//! | Kind | Server path |
//! | --- | --- |
//! | `control_record`, Genesis | `RESOURCE_HOST` validation ([`validate_genesis`]) |
//! | `control_record`, others | `CONTROL_PUT` through [`Coordinator::put`]: the context chain stored, the case's record proposed at the context head (compare-and-swap, sdk-rs `propose_transition`) |
//! | `data_unit`, `key_package`, `snapshot` | the ingest validators ([`ingest`]) on the context chain at its latest head; a unit that equivocates with the context's accepted unit, both through `DATA_PUT` |
//!
//! The session cases (`session_read`, `session_upload`) run over WebSocket
//! in `tests/revoked_reader.rs`. The expected outcome is the case's
//! `expected.valid` / `expected.error.code`; every case of these kinds is
//! run, none is skipped as client-only.

mod support;

use std::sync::Arc;

use lfcp::base::{Error, WireCode};
use lfcp::wire::message::Body;
use lfcp::wire::message::ErrorBody;
use lfcp_server::coordinator::{Coordinator, Failure};
use lfcp_server::ingest;
use lfcp_server::rng::OsRandom;
use lfcp_server::session::validate_genesis;
use lfcp_server::store::Store;
use support::identity::{scratch, store_chain, Identity};
use support::lfcp::{code, start, Client, Options};

const SYNC_A: &str = "wss://sync-a.example.test/v1/ws";

fn error_code(error: &Error) -> u64 {
    ErrorBody::for_error(error).map_or(WireCode::InternalError.number(), |b| b.code)
}

fn failure_code(failure: &Failure) -> u64 {
    match failure {
        Failure::NotHosted => WireCode::ResourceNotHosted.number(),
        Failure::NotCoordinator(_) => WireCode::NotControlCoordinator.number(),
        Failure::Genesis => WireCode::MalformedMessage.number(),
        Failure::Lfcp(error) => error_code(error),
        Failure::Store(_) => WireCode::InternalError.number(),
    }
}

fn name(code: Option<u64>) -> String {
    match code {
        None => "accept".into(),
        Some(n) => WireCode::from_number(n).map_or_else(|| n.to_string(), |c| c.name().to_owned()),
    }
}

/// One case's outcome on the server: `None` accepted, else the code.
async fn control_outcome(v: &Identity, id: &str) -> Option<u64> {
    let record = v.cose(id);
    if v.case(id)["inputs"]["control_type"] == 0 {
        return validate_genesis(&record).err().map(|e| error_code(&e));
    }
    let dir = scratch(&format!("cr-{}", id.replace(['.', '/'], "-")));
    let store = Arc::new(Store::open(&dir).unwrap());
    let chain = v.chain(id);
    store_chain(&store, &chain).await;
    let expected = v.head(id).unwrap_or_else(|| panic!("{id}: no head"));
    let coordinator = Coordinator::new(store.clone(), &[SYNC_A.to_owned()]);
    let resource = v.context_resource(id).unwrap();
    let outcome = coordinator
        .put(resource, expected, record, 0, &OsRandom)
        .await
        .err()
        .map(|f| failure_code(&f));
    drop((coordinator, store));
    std::fs::remove_dir_all(&dir).unwrap();
    outcome
}

/// A Data Unit case whose context holds an accepted unit at the same
/// actor and sequence (`context.accepted_unit`): equivocation is a
/// `DATA_PUT` decision (§26.2, §51), so both units go through a server.
async fn equivocation_outcome(v: &Identity, id: &str) -> Option<u64> {
    let accepted = v.case(id)["context"]["accepted_unit"]["case"]
        .as_str()
        .unwrap()
        .to_owned();
    let dir = scratch(&format!("eq-{}", id.replace(['.', '/'], "-")));
    let server = start(&dir, Options::default()).await;
    store_chain(&server.store, &v.chain(id)).await;
    let resource = v.context_resource(id).unwrap();
    let mut client = Client::connect(server.addr).await;
    let signer = v.case(id)["inputs"]["signer"].as_str().unwrap().to_owned();
    client.handshake(&v.principal(&signer)).await;
    let put = |unit: Vec<u8>| Body::DataPut {
        resource_id: resource,
        units: vec![unit],
    };
    client.request(put(v.cose(&accepted))).await;
    let ack = client.recv().await;
    assert!(
        matches!(ack.body, Body::Ack(_)),
        "{accepted}: {:?}",
        ack.body
    );
    client.request(put(v.cose(id))).await;
    let reply = client.recv().await;
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
    match reply.body {
        Body::Ack(_) => None,
        _ => Some(code(&reply)),
    }
}

async fn object_outcome(v: &Identity, id: &str) -> Option<u64> {
    let case = v.case(id);
    if case["context"]["accepted_unit"].is_object() {
        return equivocation_outcome(v, id).await;
    }
    let dir = scratch(&format!("obj-{}", id.replace(['.', '/'], "-")));
    let store = Arc::new(Store::open(&dir).unwrap());
    store_chain(&store, &v.chain(id)).await;
    let coordinator = Coordinator::new(store.clone(), &[SYNC_A.to_owned()]);
    let resource = v.context_resource(id).unwrap();
    let chain = match coordinator.chain(resource).await {
        Ok(Some(chain)) => chain,
        Ok(None) => panic!("{id}: not hosted"),
        Err(failure) => return Some(failure_code(&failure)),
    };
    let bytes = v.cose(id);
    let result = match case["kind"].as_str().unwrap() {
        "data_unit" => ingest::data_unit(&chain, resource, &bytes).map(|_| ()),
        "key_package" => ingest::key_package(&chain, resource, &bytes).map(|_| ()),
        "snapshot" => ingest::snapshot(&chain, resource, &bytes).map(|_| ()),
        other => unreachable!("{other}"),
    };
    drop((chain, coordinator, store));
    std::fs::remove_dir_all(&dir).unwrap();
    result.err().map(|e| error_code(&e))
}

fn check(v: &Identity, results: Vec<(String, Option<u64>)>) {
    let mut wrong = Vec::new();
    for (id, got) in &results {
        let want = v.expected_code(id);
        if *got != want {
            wrong.push(format!("{id}: expected {}, got {}", name(want), name(*got)));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} cases differ:\n{}",
        wrong.len(),
        results.len(),
        wrong.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn control_records_through_control_put() {
    let v = Identity::load();
    let ids: Vec<String> = v
        .cases()
        .filter(|c| c["kind"] == "control_record")
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 196, "baseline.2 Control Record cases");
    // I9: epoch placement precedes dependencies, signatures and authority,
    // but follows structural validation (§19, §62).
    for required in [
        "key_epoch_wrong_number",
        "key_epoch_repeats_current_number",
        "key_epoch_wrong_number_and_bad_sig",
        "key_epoch_wrong_number_unknown_issuer",
        "key_epoch_wrong_number_without_key_rotate",
        "key_epoch_wrong_number_noncanonical_frontier",
    ] {
        assert!(ids.iter().any(|id| id == required), "{required}");
    }
    let mut results = Vec::new();
    for id in ids {
        let outcome = control_outcome(&v, &id).await;
        results.push((id, outcome));
    }
    check(&v, results);
}

#[tokio::test(flavor = "multi_thread")]
async fn data_units_key_packages_and_snapshots_through_ingest() {
    let v = Identity::load();
    let ids: Vec<String> = v
        .cases()
        .filter(|c| {
            matches!(
                c["kind"].as_str(),
                Some("data_unit" | "key_package" | "snapshot")
            )
        })
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        ids.len(),
        72,
        "baseline.2 Data Units, Key Packages and Snapshots"
    );
    let mut results = Vec::new();
    for id in ids {
        let outcome = object_outcome(&v, &id).await;
        results.push((id, outcome));
    }
    check(&v, results);
}
