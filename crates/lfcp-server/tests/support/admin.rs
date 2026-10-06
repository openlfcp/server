//! A minimal admin API client: pairing and sessions with the signed
//! challenge proof (LFCP-046), for tests outside tests/admin.rs.

use std::net::SocketAddr;

use lfcp::base::to_hex;
use lfcp::cbor::{self, Value};
use lfcp::cose;
use lfcp::principal::PrincipalKeys;
use serde_json::{json, Value as Json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::lfcp::Running;

/// One HTTP/1.1 request; the status and the JSON body.
pub async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Json>,
) -> (u16, Json) {
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    let reply = String::from_utf8(reply).unwrap();
    let status: u16 = reply[9..12].parse().unwrap();
    let body = reply.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, serde_json::from_str(body).unwrap_or(Json::Null))
}

fn proof(keys: &PrincipalKeys, purpose: &str, server_id: &[u8; 32], challenge: &str) -> Json {
    let transcript = cbor::encode(&Value::Array(vec![
        Value::text("LFCP-ADMIN-v1"),
        Value::text(purpose),
        Value::bytes(server_id.to_vec()),
        Value::bytes(lfcp::base::from_hex(challenge).unwrap()),
    ]))
    .unwrap();
    json!({
        "principal": to_hex(&keys.descriptor().encode()),
        "challenge": challenge,
        "proof": to_hex(cose::sign(&transcript, keys).unwrap().bytes()),
    })
}

async fn challenge(addr: SocketAddr) -> String {
    let (status, body) = http(addr, "POST", "/admin/challenge", None, None).await;
    assert_eq!(status, 200);
    body["challenge"].as_str().unwrap().to_owned()
}

/// Pair `keys` as the administrator with the server's setup code, and
/// return an admin session token.
pub async fn admin_token(server: &Running, keys: &PrincipalKeys) -> String {
    let code = server.setup_code.clone().expect("an unpaired server");
    let c = challenge(server.addr).await;
    let mut body = proof(keys, "pair", server.server_id.as_bytes(), &c);
    body["code"] = json!(code);
    let (status, reply) = http(server.addr, "POST", "/setup/pair", None, Some(body)).await;
    assert_eq!(status, 200, "{reply}");
    let c = challenge(server.addr).await;
    let body = proof(keys, "session", server.server_id.as_bytes(), &c);
    let (status, reply) = http(server.addr, "POST", "/admin/session", None, Some(body)).await;
    assert_eq!(status, 200, "{reply}");
    reply["token"].as_str().unwrap().to_owned()
}

/// A new admin session token for the paired administrator `keys`.
pub async fn session_token(server: &Running, keys: &PrincipalKeys) -> String {
    let c = challenge(server.addr).await;
    let body = proof(keys, "session", server.server_id.as_bytes(), &c);
    let (status, reply) = http(server.addr, "POST", "/admin/session", None, Some(body)).await;
    assert_eq!(status, 200, "{reply}");
    reply["token"].as_str().unwrap().to_owned()
}
