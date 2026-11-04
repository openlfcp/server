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
    assert_eq!(spec.lock().tag, "mvp-0.4-baseline.1");
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

/// READY of an identity-01 server (LFCP-IDENTITY-TEST-VECTORS-01
/// `READY_identity_01`, WIRE-01 §37): field 5 of the READY this server
/// sends is the published `["identity-01"]`, value for value.
///
/// The published message is not a whole READY at mvp-0.4-baseline.1: its
/// envelope type is 1 (HELLO), not 3, and its wire profile "lfcp-1", not
/// "LFCP-WIRE-01" (the generator calls `wire_msg(1, ...)`), so sdk-rs
/// refuses it as a message. The test compares the body's field 5 only and
/// pins that defect, so a corrected corpus is noticed (status-408.md).
#[test]
fn ready_lists_identity_01_as_published() {
    use lfcp::cbor::{decode_strict, Value};
    use lfcp::wire::message::ReadyBody;
    let spec = Spec::open();
    let suite = spec.read_json(support::identity::SUITE);
    let case = suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "READY_identity_01")
        .unwrap();
    assert_eq!(
        lfcp_server::session::IDENTITY_01,
        case["inputs"]["extension"]
    );
    let published =
        lfcp::base::from_hex(case["expected"]["message_cbor"]["hex"].as_str().unwrap()).unwrap();
    assert!(Message::decode(&published, &DecodeOptions::default()).is_err());
    let published = decode_strict(&published).unwrap();
    assert_eq!(
        published.get_uint(0),
        Some(&Value::Unsigned(1)),
        "the known defect"
    );
    let field5 = |message: &Value| message.get_uint(4).unwrap().get_uint(5).cloned();
    assert_eq!(
        field5(&published),
        Some(Value::Array(vec![Value::text("identity-01")]))
    );

    let ours = Message::new(
        [0; 16],
        Body::Ready(ReadyBody {
            wire_profile: lfcp::wire::session::WIRE_PROFILE.into(),
            server_id: [0; 32],
            max_message_bytes: 1 << 20,
            durability: 2,
            heartbeat_ms: 30000,
            extensions: Some(
                lfcp_server::session::EXTENSIONS
                    .iter()
                    .map(|e| e.to_string())
                    .collect(),
            ),
        }),
    );
    let ours = decode_strict(&ours.encode()).unwrap();
    assert_eq!(ours.get_uint(0), Some(&Value::Unsigned(3)));
    assert_eq!(field5(&ours), field5(&published));
}
