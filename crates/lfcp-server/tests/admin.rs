//! The setup/admin HTTP surface over real HTTP (LFCP-046): first-run
//! pairing with the one-time code and a signed challenge, its refusals,
//! admin sessions, the hosting policy taking effect on RESOURCE_HOST and
//! surviving a restart, and the separation of server administration from
//! LFCP Resource authority.

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use lfcp::base::to_hex;
use lfcp::cbor::{self, Value};
use lfcp::cose;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::message::{Body, HostingCredential};
use serde_json::{json, Value as Json};
use support::lfcp::{start, state_dir, Client, Options, Running};
use support::vectors::Vectors;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const AUTHORIZATION_FAILED: u64 = 4;
const HOSTING_DENIED: u64 = 20;

/// One HTTP/1.1 request; the status and the JSON body.
async fn http(
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

async fn challenge(addr: SocketAddr) -> String {
    let (status, body) = http(addr, "POST", "/admin/challenge", None, None).await;
    assert_eq!(status, 200);
    body["challenge"].as_str().unwrap().to_owned()
}

/// The admin proof: COSE_Sign1 by `keys` over
/// ["LFCP-ADMIN-v1", purpose, server_id, challenge].
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

fn with_code(mut proof: Json, code: &str) -> Json {
    proof["code"] = json!(code);
    proof
}

async fn pair(server: &Running, keys: &PrincipalKeys, code: &str) -> (u16, Json) {
    let c = challenge(server.addr).await;
    let body = with_code(proof(keys, "pair", server.server_id.as_bytes(), &c), code);
    http(server.addr, "POST", "/setup/pair", None, Some(body)).await
}

async fn session(server: &Running, keys: &PrincipalKeys) -> (u16, Json) {
    let c = challenge(server.addr).await;
    let body = proof(keys, "session", server.server_id.as_bytes(), &c);
    http(server.addr, "POST", "/admin/session", None, Some(body)).await
}

async fn token(server: &Running, keys: &PrincipalKeys) -> String {
    let (status, body) = session(server, keys).await;
    assert_eq!(status, 200, "{body}");
    body["token"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_works_once_and_health_stays_minimal() {
    let v = Vectors::load();
    let dir = state_dir("admin-pair");
    let server = start(&dir, Options::default()).await;
    let code = server.setup_code.clone().expect("a first-run code");
    assert_eq!(code.len(), 9);
    assert_eq!(&code[4..5], "-");
    // The code is in its file only (security review M6); an unpaired
    // restart replaces it.
    let setup_file = dir.join(lfcp_server::admin::SETUP_CODE_FILE);
    assert_eq!(
        std::fs::read_to_string(&setup_file).unwrap(),
        format!("{code}\n")
    );
    server.stop().await;
    let server = start(&dir, Options::default()).await;
    let code = server.setup_code.clone().expect("a new code");
    assert_eq!(
        std::fs::read_to_string(&setup_file).unwrap(),
        format!("{code}\n")
    );

    let (status, body) = http(server.addr, "GET", "/setup", None, None).await;
    assert_eq!((status, &body["paired"]), (200, &json!(false)));
    assert_eq!(body["server_id"], json!(server.server_id.to_hex()));

    // The code is case- and separator-insensitive.
    let carol = v.principal("carol");
    let (status, body) = pair(&server, &carol, &code.to_lowercase().replace('-', "")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["admin"], json!(carol.descriptor().id().to_hex()));
    assert!(!setup_file.exists(), "pairing removes the code file");
    let (_, body) = http(server.addr, "GET", "/setup", None, None).await;
    assert_eq!(body["paired"], json!(true));

    // Once: the code is destroyed.
    let (status, _) = pair(&server, &v.principal("bob"), &code).await;
    assert_eq!(status, 410);

    // Health: nothing but the status.
    let (status, body) = http(server.addr, "GET", "/health", None, None).await;
    assert_eq!((status, body), (200, json!({ "status": "ok" })));
    server.stop().await;

    // A paired server creates no new code on restart.
    let server = start(&dir, Options::default()).await;
    assert!(server.setup_code.is_none());
    assert_eq!(pair(&server, &carol, &code).await.0, 410);
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_codes_proofs_and_expired_codes_are_refused() {
    let v = Vectors::load();
    let bob = v.principal("bob");

    // An expired code.
    let dir = state_dir("admin-expired");
    let server = start(
        &dir,
        Options {
            setup_ttl: Some(Duration::from_secs(1)),
            ..Options::default()
        },
    )
    .await;
    let code = server.setup_code.clone().unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(pair(&server, &bob, &code).await.0, 410);
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();

    let dir = state_dir("admin-refusals");
    let server = start(&dir, Options::default()).await;
    let code = server.setup_code.clone().unwrap();
    let id = *server.server_id.as_bytes();

    // A wrong signature: signed by CAROL, claiming BOB.
    let c = challenge(server.addr).await;
    let mut forged = proof(&v.principal("carol"), "pair", &id, &c);
    forged["principal"] = json!(to_hex(&bob.descriptor().encode()));
    let (status, _) = http(
        server.addr,
        "POST",
        "/setup/pair",
        None,
        Some(with_code(forged, &code)),
    )
    .await;
    assert_eq!(status, 401);
    // A proof for another purpose, or another server.
    let c = challenge(server.addr).await;
    let body = with_code(proof(&bob, "session", &id, &c), &code);
    assert_eq!(
        http(server.addr, "POST", "/setup/pair", None, Some(body))
            .await
            .0,
        401
    );
    let c = challenge(server.addr).await;
    let body = with_code(proof(&bob, "pair", &[0; 32], &c), &code);
    assert_eq!(
        http(server.addr, "POST", "/setup/pair", None, Some(body))
            .await
            .0,
        401
    );
    // A challenge is single use, and one the server never issued fails.
    let c = challenge(server.addr).await;
    let body = with_code(proof(&bob, "pair", &id, &c), "AAAA-AAAA");
    assert_eq!(
        http(server.addr, "POST", "/setup/pair", None, Some(body.clone()))
            .await
            .0,
        403
    );
    assert_eq!(
        http(server.addr, "POST", "/setup/pair", None, Some(body))
            .await
            .0,
        401
    );
    let body = with_code(proof(&bob, "pair", &id, &"00".repeat(32)), &code);
    assert_eq!(
        http(server.addr, "POST", "/setup/pair", None, Some(body))
            .await
            .0,
        401
    );
    // Malformed requests.
    let (status, _) = http(
        server.addr,
        "POST",
        "/setup/pair",
        None,
        Some(json!({ "code": code })),
    )
    .await;
    assert_eq!(status, 400);

    // Five wrong codes destroy it (one was spent above): then even the
    // right one is gone.
    for attempt in 0..4 {
        let (status, _) = pair(&server, &bob, "ZZZZ-ZZZZ").await;
        assert_eq!(status, 403, "attempt {attempt}");
    }
    assert_eq!(pair(&server, &bob, &code).await.0, 410);
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_endpoints_need_an_admin_session() {
    let v = Vectors::load();
    let dir = state_dir("admin-auth");
    let server = start(&dir, Options::default()).await;
    let code = server.setup_code.clone().unwrap();
    let carol = v.principal("carol");
    assert_eq!(pair(&server, &carol, &code).await.0, 200);

    for path in ["/admin/status", "/admin/hosting", "/admin/resources"] {
        assert_eq!(
            http(server.addr, "GET", path, None, None).await.0,
            401,
            "{path}"
        );
        assert_eq!(
            http(server.addr, "GET", path, Some(&"ab".repeat(32)), None)
                .await
                .0,
            401,
            "{path}"
        );
    }
    // A non-admin Principal gets no session.
    assert_eq!(session(&server, &v.principal("bob")).await.0, 403);

    let admin = token(&server, &carol).await;
    let (status, body) = http(server.addr, "GET", "/admin/status", Some(&admin), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["server_id"], json!(server.server_id.to_hex()));
    assert_eq!(body["admins"], json!([carol.descriptor().id().to_hex()]));
    assert_eq!(body["hosted_resources"], json!(0));
    assert_eq!(body["durability"], json!(2));

    // No REST Resource sync, and unknown methods are refused.
    for path in ["/resources", "/admin/data", "/v1/data"] {
        assert_eq!(
            http(server.addr, "GET", path, Some(&admin), None).await.0,
            404,
            "{path}"
        );
    }
    assert_eq!(
        http(server.addr, "DELETE", "/admin/status", Some(&admin), None)
            .await
            .0,
        405
    );
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

async fn host(
    server: &Running,
    keys: &PrincipalKeys,
    v: &Vectors,
    credential: Option<&[u8]>,
) -> Body {
    let mut client = Client::connect(server.addr).await;
    client.handshake(keys).await;
    client
        .request(Body::ResourceHost {
            genesis: v.cose("C0_genesis"),
            hosting_credential: credential.map(|c| HostingCredential::new(c.to_vec())),
        })
        .await;
    client.recv().await.body
}

fn nack(body: &Body) -> u64 {
    match body {
        Body::Nack(e) => e.code,
        other => panic!("expected NACK, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_hosting_policy_applies_to_resource_host_and_persists() {
    let v = Vectors::load();
    let dir = state_dir("admin-hosting");
    let server = start(&dir, Options::default()).await;
    let code = server.setup_code.clone().unwrap();
    let carol = v.principal("carol");
    assert_eq!(pair(&server, &carol, &code).await.0, 200);
    let admin = token(&server, &carol).await;

    let (status, body) = http(server.addr, "GET", "/admin/hosting", Some(&admin), None).await;
    assert_eq!((status, body), (200, json!({ "mode": "open" })));

    // Only OWNER, or whoever presents the credential "deploy-key".
    let owner = v.principal("owner");
    let rule = json!({
        "mode": "allow_list",
        "principals": [owner.descriptor().id().to_hex()],
        "credentials": [to_hex(b"deploy-key")],
    });
    let (status, body) = http(
        server.addr,
        "PUT",
        "/admin/hosting",
        Some(&admin),
        Some(rule),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["credentials"],
        json!(1),
        "credentials are counted, never shown"
    );
    assert!(!body.to_string().contains(&to_hex(b"deploy-key")));
    let (status, _) = http(
        server.addr,
        "PUT",
        "/admin/hosting",
        Some(&admin),
        Some(json!({ "mode": "allow_list", "principals": ["zz"] })),
    )
    .await;
    assert_eq!(status, 400);

    let bob = v.principal("bob");
    assert_eq!(nack(&host(&server, &bob, &v, None).await), HOSTING_DENIED);
    assert_eq!(
        nack(&host(&server, &bob, &v, Some(b"wrong")).await),
        HOSTING_DENIED
    );
    // The administrator itself is not allowed to host either.
    assert_eq!(nack(&host(&server, &carol, &v, None).await), HOSTING_DENIED);
    assert!(matches!(
        host(&server, &bob, &v, Some(b"deploy-key")).await,
        Body::ResourceHosted { .. }
    ));
    server.stop().await;

    // The policy survives a restart.
    let server = start(&dir, Options::default()).await;
    assert_eq!(
        nack(&host(&server, &v.principal("invite"), &v, None).await),
        HOSTING_DENIED
    );
    assert!(matches!(
        host(&server, &owner, &v, None).await,
        Body::ResourceHosted { .. }
    ));
    let admin = token(&server, &carol).await;
    let (_, body) = http(server.addr, "GET", "/admin/resources", Some(&admin), None).await;
    let list = body["resources"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["resource_id"], json!(v.resource().to_hex()));
    assert_eq!(list[0]["control_head_seq"], json!(0));
    assert_eq!(list[0]["control_records"], json!(1));
    // Sizes only: no object bytes or contents.
    let keys: std::collections::BTreeSet<&str> = list[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: std::collections::BTreeSet<&str> = [
        "resource_id",
        "control_head_seq",
        "control_records",
        "data_units",
        "key_packages",
        "snapshots",
        "bytes",
    ]
    .into();
    assert_eq!(keys, expected);
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn being_an_administrator_grants_no_resource_authority() {
    let v = Vectors::load();
    let dir = state_dir("admin-authority");
    let server = start(&dir, Options::default()).await;
    let code = server.setup_code.clone().unwrap();
    // INVITE becomes the server administrator; OWNER hosts the Resource.
    let invite_keys = PrincipalKeys::from_secrets(&[33; 32], [34; 32]);
    assert_eq!(pair(&server, &invite_keys, &code).await.0, 200);
    assert!(matches!(
        host(&server, &v.principal("owner"), &v, None).await,
        Body::ResourceHosted { .. }
    ));
    // The administrator cannot open it: authority is the Control Chain.
    let mut client = Client::connect(server.addr).await;
    client.handshake(&invite_keys).await;
    client
        .request(Body::ResourceOpen {
            resource_id: v.resource(),
            control_heads: vec![],
            have: vec![],
            grant_ids: None,
            flags: Some(0),
        })
        .await;
    assert_eq!(nack(&client.recv().await.body), AUTHORIZATION_FAILED);
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
