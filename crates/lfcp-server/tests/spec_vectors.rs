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
    assert_eq!(spec.lock().tag, "mvp-0.1-baseline.5");
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
