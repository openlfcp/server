//! Inbound frame decoding as the server does it (`ws.rs`: binary and text
//! frames through `Message::decode_frame` with the configured message size
//! limit): no panic and no unbounded allocation on any bytes; a decoded
//! message encodes back to exactly the bytes (deterministic CBOR, WIRE §5.2)
//! and decodes again to the same message.

#![no_main]

use lfcp::wire::message::{DecodeOptions, FrameKind, Message, DEFAULT_MAX_MESSAGE_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&flags, bytes)) = data.split_first() else {
        return;
    };
    let options = DecodeOptions {
        max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        ..DecodeOptions::default()
    };
    let kind = if flags & 1 == 0 {
        FrameKind::Binary
    } else {
        FrameKind::Text
    };
    let decoded = Message::decode_frame(kind, bytes, &options);
    let again = Message::decode_frame(kind, bytes, &options);
    assert_eq!(decoded.is_ok(), again.is_ok(), "not deterministic");
    if let (FrameKind::Binary, Ok(message)) = (kind, decoded) {
        let encoded = message.encode();
        assert_eq!(encoded, bytes, "a decoded message encodes to other bytes");
        let back = Message::decode(&encoded, &options).expect("an encoded message decodes");
        assert_eq!(back, message, "decode(encode(m)) != m");
    }
});
