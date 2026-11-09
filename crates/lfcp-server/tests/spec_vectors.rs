//! The server ID against LFCP-TEST-VECTORS-01 at the spec.lock pin: the
//! CHALLENGE and READY messages carry a 32-byte server ID (WIRE-01 §35,
//! §37), the same one in both, decoded with sdk-rs.

mod support;

use lfcp::wire::message::{Body, DecodeOptions, Message};
use lfcp_server::identity::ServerId;
use support::spec::Spec;

#[test]
fn challenge_and_ready_carry_one_server_id() {
    let spec = Spec::open();
    assert_eq!(spec.lock().tag, "mvp-0.4-baseline.5");
    let suite = spec.read_json("test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json");
    let message = |id: &str| {
        let case = suite["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap();
        let bytes = lfcp::base::from_hex(case["expected"]["message_cbor"]["hex"].as_str().unwrap())
            .unwrap();
        Message::decode(&bytes, &DecodeOptions::default()).unwrap()
    };
    let Body::Challenge(challenge) = message("CHALLENGE").body else {
        panic!("CHALLENGE")
    };
    let Body::Ready(ready) = message("READY").body else {
        panic!("READY")
    };
    let fixture = lfcp::base::from_hex(
        suite["fixtures"]["session"]["server_id"]["hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let id = ServerId::from_bytes(challenge.server_id);
    assert_eq!(id.as_bytes().as_slice(), fixture.as_slice());
    assert_eq!(ServerId::from_bytes(ready.server_id), id);
    assert_eq!(id.to_hex(), lfcp::base::to_hex(&fixture));
}

/// The complete published READY (WIRE-01 §37), corrected in baseline.2:
/// type 3, LFCP-WIRE-01, and the server's advertised extensions. Fixture
/// inputs supply the envelope IDs and deployment-specific READY values
/// (the corpus uses durability 1; this server promises durability 2).
#[test]
fn ready_lists_identity_01_as_published() {
    use lfcp::wire::message::ReadyBody;
    let spec = Spec::open();
    let suite = spec.read_json(support::identity::SUITE);
    let case = suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "READY_identity_01")
        .unwrap();
    let inputs = &case["inputs"];
    assert_eq!(lfcp_server::session::IDENTITY_01, inputs["extension"]);
    assert_eq!(lfcp::wire::session::WIRE_PROFILE, inputs["wire_profile"]);
    let bytes = |field: &str| lfcp::base::from_hex(inputs[field]["hex"].as_str().unwrap()).unwrap();
    let published =
        lfcp::base::from_hex(case["expected"]["message_cbor"]["hex"].as_str().unwrap()).unwrap();
    let decoded = Message::decode(&published, &DecodeOptions::default()).unwrap();
    let mut ours = Message::new(
        bytes("message_id").try_into().unwrap(),
        Body::Ready(ReadyBody {
            wire_profile: lfcp::wire::session::WIRE_PROFILE.into(),
            server_id: bytes("server_id").try_into().unwrap(),
            max_message_bytes: inputs["max_message_bytes"].as_u64().unwrap(),
            durability: inputs["durability"].as_u64().unwrap(),
            heartbeat_ms: inputs["heartbeat_ms"].as_u64().unwrap(),
            extensions: Some(
                lfcp_server::session::EXTENSIONS
                    .iter()
                    .map(|e| e.to_string())
                    .collect(),
            ),
        }),
    );
    ours.correlation_id = Some(bytes("correlation").try_into().unwrap());
    assert_eq!(decoded, ours);
    assert_eq!(ours.encode(), published);
}
